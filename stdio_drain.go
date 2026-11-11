package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Byte-stream drain for the stdio transport
// ([pattern:mcp-cli-immediate-eof-race]).
//
// mcp.StdioTransport's ioConn reads stdin with a json.Decoder on its own
// goroutine. When a CLI client writes its request(s) and closes stdin
// immediately, the decoder goroutine can observe io.EOF and deliver it to
// readIncoming BEFORE the in-flight handler goroutine writes its response.
// readIncoming then records readErr=io.EOF; every subsequent
// Connection.write hits inFlightState.shuttingDown and fails with
// ErrServerClosing ("server is closing: EOF"), the failed write sets
// writeErr, conn.Wait() surfaces it, srv.Run returns a non-nil error, and
// main exits rc=1 — frequently without the response ever reaching stdout.
//
// The fix stays at the byte-stream layer of a stock mcp.IOTransport (we must
// NOT wrap mcp.Connection: Server.bind type-asserts ss.mcpConn to the
// unexported serverConnection interface implemented by *ioConn, which sets
// protocolVersion and drives batch validation). Two wrappers share a
// stdioDrain bookkeeping value:
//
//   - stdinGate buffers os.Stdin line-wise; each line (or concatenated
//     JSON value / batch array on one line) is minimally parsed and every
//     inbound JSON-RPC request — an object with a non-empty "method" AND a
//     non-null "id"; notifications have no "id" and are not tracked — is
//     registered by its normalized id. When the underlying stdin reports
//     io.EOF while requests are still in flight, Read blocks until the
//     drain releases it, so ioConn only ever sees (0, io.EOF) after every
//     response has been written.
//   - stdoutTracker passes writes through to os.Stdout; every completed
//     outbound JSON line is scanned for JSON-RPC responses — an object
//     with an "id" and no "method" — which release the matching in-flight
//     request (an "id":null error response releases one outstanding
//     request as a fallback). Release happens after the bytes have been
//     written, so an unblocked EOF can never precede response bytes.
//
// The drain is bounded (stdioDrainMaxWait) so a wedged handler cannot block
// shutdown forever, and Close/cancel always unblocks a waiting Read.

// stdioDrainMaxWait bounds how long a post-EOF Read waits for in-flight
// responses before reporting EOF anyway — a safety cap against wedged
// handlers, not part of the protocol contract.
const stdioDrainMaxWait = 5 * time.Second

// stdioDrain tracks inbound requests whose responses have not yet been
// written, and wakes post-EOF readers once the count returns to zero.
// Invariant: inFlight == sum(ids[*]) — the map is a multiset so reused ids
// still count correctly.
type stdioDrain struct {
	mu       sync.Mutex
	inFlight int
	ids      map[string]int // normalized id -> outstanding count
	drained  chan struct{}  // non-nil, closed iff inFlight == 0
}

func newStdioDrain() *stdioDrain {
	d := &stdioDrain{ids: make(map[string]int)}
	d.drained = make(chan struct{})
	close(d.drained) // idle: zero in flight
	return d
}

// track registers an inbound request id. Empty/null ids are not trackable.
func (d *stdioDrain) track(id string) {
	if id == "" || id == "null" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inFlight == 0 {
		d.drained = make(chan struct{})
	}
	d.inFlight++
	d.ids[id]++
}

// release marks one response as written. An empty/null id releases an
// arbitrary outstanding request (an "id":null error response cannot name
// its request; the count is what matters for the drain).
func (d *stdioDrain) release(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inFlight == 0 {
		return
	}
	key := id
	if key == "" || key == "null" || d.ids[key] == 0 {
		for k := range d.ids {
			if d.ids[k] > 0 {
				key = k
				break
			}
		}
	}
	if d.ids[key] > 0 {
		d.ids[key]--
		if d.ids[key] == 0 {
			delete(d.ids, key)
		}
	}
	d.inFlight--
	if d.inFlight == 0 {
		select {
		case <-d.drained:
		default:
			close(d.drained)
		}
	}
}

// inFlightCount reports the number of requests awaiting a response.
func (d *stdioDrain) inFlightCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inFlight
}

// waitDrained blocks until in-flight requests reach zero, ctx or closedCh
// fires, or stdioDrainMaxWait elapses. It reports whether the drain actually
// completed.
func (d *stdioDrain) waitDrained(ctx context.Context, closedCh <-chan struct{}) bool {
	d.mu.Lock()
	drained := d.drained
	d.mu.Unlock()
	select {
	case <-drained:
		return true
	case <-closedCh:
		return false
	case <-ctx.Done():
		return false
	case <-time.After(stdioDrainMaxWait):
		return false
	}
}

// stdinGate is the Reader half of the stdio drain: a line-buffered
// io.ReadCloser over stdin that registers inbound request ids and withholds
// io.EOF until all in-flight responses have been written.
type stdinGate struct {
	d   *stdioDrain
	ctx context.Context // session ctx; cancellation must unblock EOF waits

	br       *bufio.Reader
	src      io.ReadCloser
	pending  [][]byte // buffered complete lines not yet handed to the decoder
	eof      bool     // source reached io.EOF
	readErr  error    // sticky non-EOF read error
	closedCh chan struct{}
	once     sync.Once
	mu       sync.Mutex
}

func newStdinGate(ctx context.Context, stdin io.ReadCloser, d *stdioDrain) *stdinGate {
	return &stdinGate{
		d:        d,
		ctx:      ctx,
		br:       bufio.NewReaderSize(stdin, 64*1024),
		src:      stdin,
		closedCh: make(chan struct{}),
	}
}

// Read serves pending buffered lines first; when they are exhausted it
// reads the next line from stdin. A non-empty tail line terminated by
// io.EOF (no trailing newline) is completed with '\n' and delivered first —
// the EOF is only reported on a later call, and even then only after the
// drain is empty (bounded by ctx/cancel/Close/stdioDrainMaxWait).
func (g *stdinGate) Read(p []byte) (int, error) {
	for {
		g.mu.Lock()
		if len(g.pending) > 0 {
			n := copy(p, g.pending[0])
			g.pending[0] = g.pending[0][n:]
			if len(g.pending[0]) == 0 {
				g.pending = g.pending[1:]
			}
			g.mu.Unlock()
			if n > 0 {
				return n, nil
			}
			continue
		}
		if g.readErr != nil {
			err := g.readErr
			g.mu.Unlock()
			return 0, err
		}
		select {
		case <-g.closedCh:
			g.mu.Unlock()
			return 0, io.ErrClosedPipe
		default:
		}
		// EOF already observed: no more bytes can arrive, so the only thing
		// left to gate on is the in-flight request set.
		if g.eof {
			drained := g.d.inFlightCount() == 0
			g.mu.Unlock()
			if !drained {
				// Responses may still be in flight; wait for the tracker to
				// drain them (or for close/cancel/the safety cap) before
				// surfacing EOF to ioConn.
				g.d.waitDrained(g.ctx, g.closedCh)
			}
			return 0, io.EOF
		}
		g.fillLocked()
		g.mu.Unlock()
	}
}

// fillLocked reads one more line from stdin into g.pending. g.mu must be
// held; the underlying blocking read keeps the lock, but Close does not
// need g.mu to close the source and closedCh.
func (g *stdinGate) fillLocked() {
	line, err := g.br.ReadBytes('\n')
	if err == nil {
		g.pending = append(g.pending, line)
		scanDrainLine(line, g.d.track, nil)
		return
	}
	if len(line) > 0 {
		// io.EOF (or a read error) with a partial tail: complete the line so
		// the decoder sees a well-formed value; the error is surfaced by the
		// next Read once this tail has been consumed.
		completed := line
		if completed[len(completed)-1] != '\n' {
			completed = append(completed, '\n')
		}
		g.pending = append(g.pending, completed)
		scanDrainLine(completed, g.d.track, nil)
	}
	if errors.Is(err, io.EOF) {
		g.eof = true
	} else {
		g.readErr = err
	}
}

// Close unblocks any pending EOF wait and closes the underlying stdin. It
// does not take g.mu so it can never deadlock against an in-progress
// fillLocked read; the source close unblocks that read instead.
func (g *stdinGate) Close() error {
	var err error
	g.once.Do(func() {
		close(g.closedCh)
		err = g.src.Close()
	})
	return err
}

// stdoutTracker is the Writer half of the drain: bytes pass through to
// stdout verbatim; each completed outbound line is scanned AFTER the write
// so a response releases its in-flight request only once it is on the wire.
type stdoutTracker struct {
	d   *stdioDrain
	wc  io.WriteCloser
	buf []byte // partial outbound line
}

func newStdoutTracker(stdout io.WriteCloser, d *stdioDrain) *stdoutTracker {
	return &stdoutTracker{d: d, wc: stdout}
}

func (t *stdoutTracker) Write(p []byte) (int, error) {
	// Line-buffer for scanning only; the bytes themselves pass through
	// unmodified and in order.
	t.buf = append(t.buf, p...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(t.buf, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, t.buf[:i+1])
		t.buf = t.buf[i+1:]
	}
	n, err := t.wc.Write(p)
	// Scan only after the write: the drain must observe the response on the
	// wire, not merely enqueued.
	for _, line := range lines {
		scanDrainLine(line, nil, t.d.release)
	}
	return n, err
}

// Close scans a trailing unterminated response line (defensive: ioConn
// always terminates messages with '\n') and closes the underlying writer.
func (t *stdoutTracker) Close() error {
	if len(t.buf) > 0 {
		scanDrainLine(t.buf, nil, t.d.release)
		t.buf = nil
	}
	return t.wc.Close()
}

// nopWriteCloser adds a no-op Close to an io.Writer, mirroring the SDK's
// internal nopCloserWriter used for os.Stdout.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// scanDrainLine minimally parses one complete JSON line for drain
// bookkeeping. A JSON array is treated as a batch and scanned per element;
// otherwise the line may hold one object, or several values concatenated
// (legal whitespace-separated JSON-RPC messages) — handled by a decoder
// fallback. Malformed lines are ignored; the SDK reports the real error.
func scanDrainLine(line []byte, track func(string), release func(string)) {
	trim := bytes.TrimSpace(line)
	if len(trim) == 0 {
		return
	}
	if trim[0] == '[' {
		var elems []map[string]json.RawMessage
		if err := json.Unmarshal(trim, &elems); err == nil {
			for _, e := range elems {
				applyDrainObject(e, track, release)
			}
			return
		}
		// Fall through: an unparsable array is scanned value-by-value below.
	}
	if track == nil && release == nil {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(trim))
	for {
		var e map[string]json.RawMessage
		if err := dec.Decode(&e); err != nil {
			return
		}
		applyDrainObject(e, track, release)
	}
}

// applyDrainObject classifies one decoded object: inbound requests are
// tracked (non-empty method AND present non-null id); outbound responses
// release (id present, no method; "id":null releases via the fallback).
func applyDrainObject(e map[string]json.RawMessage, track func(string), release func(string)) {
	method := e["method"]
	hasMethod := len(method) > 0 && string(method) != "null"
	id, hasID := e["id"]
	if hasMethod {
		if track != nil && hasID && len(id) > 0 && string(id) != "null" {
			track(normalizeDrainID(id))
		}
		return
	}
	if hasID && release != nil {
		release(normalizeDrainID(id))
	}
}

// normalizeDrainID compacts a raw JSON id so equivalent spellings compare
// equal; the wire id is echoed verbatim by the SDK, so exact compaction is
// sufficient.
func normalizeDrainID(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// newStdioDrainTransport builds the stdio transport used by main: a stock
// mcp.IOTransport whose byte streams are wrapped by the drain pair above.
// ctx is the session context (srv.Run's), used to unblock a post-EOF wait.
func newStdioDrainTransport(ctx context.Context, stdin io.ReadCloser, stdout io.WriteCloser) mcp.Transport {
	d := newStdioDrain()
	return &mcp.IOTransport{
		Reader: newStdinGate(ctx, stdin, d),
		Writer: newStdoutTracker(stdout, d),
	}
}

// stdioTransport constructs the production transport over os.Stdin/os.Stdout.
func stdioTransport(ctx context.Context) mcp.Transport {
	return newStdioDrainTransport(ctx, os.Stdin, nopWriteCloser{os.Stdout})
}
