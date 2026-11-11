package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Regression coverage for [pattern:mcp-cli-immediate-eof-race]: when the CLI
// client writes its request(s) and closes stdin's write end immediately, the
// SDK's ioConn read goroutine can deliver io.EOF to readIncoming BEFORE the
// in-flight handler goroutine writes its response. readIncoming then sets
// readErr, every subsequent Connection.write hits shuttingDown and fails with
// ErrServerClosing ("server is closing: EOF"), the write error becomes the
// session's Wait() result, and srv.Run exits rc=1 — often leaving the
// initialize/tools-call response never written to stdout at all.
//
// The fix (stdio_drain.go) delays io.EOF at the byte-stream layer until the
// response bytes have actually been written to stdout. These tests drive the
// full mcp.Server over real pipes through the same transport factory main()
// uses; TestStdioDrain_BaselineReproducesRace pins the failure mechanism on
// the raw (ungated) transport for comparison.

// drainTestTimeout bounds one regression session so a wedged server fails
// instead of hanging the suite.
const drainTestTimeout = 30 * time.Second

// drainSlowEchoDelay delays the echo tool's response long enough for the
// stdin EOF to be delivered to readIncoming first, making the race outcome
// deterministic rather than probabilistic.
const drainSlowEchoDelay = 50 * time.Millisecond

const drainInitializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"drain-test","version":"1"}}}`

// runMCPStdioSession runs srv over an os.Pipe pair using the given transport
// factory (mirroring main's construction), writes input to the server's
// stdin, closes the write end at once, and returns all bytes the server
// wrote to its stdout plus srv.Run's result. A nil runErr with a closed
// input reproduces the production rc=0 contract; a non-nil runErr is the
// "server exited: ..." fatal path.
func runMCPStdioSession(t *testing.T, srv *mcp.Server, mkTransport func(ctx context.Context, stdin io.ReadCloser, stdout io.WriteCloser) mcp.Transport, input []byte) (stdout string, runErr error) {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdoutR.Close()

	ctx, cancel := context.WithTimeout(context.Background(), drainTestTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- srv.Run(ctx, mkTransport(ctx, stdinR, stdoutW))
	}()

	if _, err := stdinW.Write(input); err != nil {
		t.Fatalf("write client input: %v", err)
	}
	if err := stdinW.Close(); err != nil {
		t.Fatalf("close client stdin write end: %v", err)
	}

	outCh := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, stdoutR)
		outCh <- buf.Bytes()
	}()

	var out []byte
	select {
	case runErr = <-done:
		// The transport's writer-side Close (rwc.Close inside ioConn) closes
		// stdoutW so the copy above terminates shortly after Run returns.
		select {
		case out = <-outCh:
		case <-time.After(5 * time.Second):
			return "", fmt.Errorf("stdout copy did not finish after session end")
		}
	case <-ctx.Done():
		return "", fmt.Errorf("session did not finish within %v", drainTestTimeout)
	}
	return string(out), runErr
}

// newDrainTestServer builds the smallest mcp.Server that exercises the race:
// initialize (handled by the SDK itself) plus a deliberately slow tools/call
// whose handler latency makes the EOF-before-response ordering deterministic.
func newDrainTestServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "ctxmode", Version: Version}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "slow_echo", Description: "echo after a fixed delay"},
		func(ctx context.Context, _ *mcp.CallToolRequest, args struct {
			Text string `json:"text"`
		}) (*mcp.CallToolResult, any, error) {
			timer := time.NewTimer(drainSlowEchoDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				// On the ungated baseline the read-side EOF cancels the
				// handler; the response write then fails with ErrServerClosing.
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "tool:" + args.Text}},
			}, nil, nil
		})
	return srv
}

func assertDrainSessionOK(t *testing.T, runErr error, stdout string, wantIDs ...string) {
	t.Helper()
	if runErr != nil {
		t.Fatalf("srv.Run must return nil after immediate stdin EOF, got %v\nstdout: %s", runErr, stdout)
	}
	for _, id := range wantIDs {
		if !strings.Contains(stdout, id) {
			t.Fatalf("stdout missing response %s, got: %s", id, stdout)
		}
	}
	if strings.Contains(stdout, "server is closing") {
		t.Fatalf("stdout contains a server-is-closing error response: %s", stdout)
	}
	if !strings.Contains(stdout, `"serverInfo"`) {
		t.Fatalf("stdout missing initialize response (serverInfo), got: %s", stdout)
	}
}

// Baseline control: with the UNGATED transport (plain IOTransport over the
// same pipes, no drain), the delayed tools/call deterministically trips the
// race — EOF reaches readIncoming during the handler sleep, the response
// write fails with ErrServerClosing, and Wait/Run surfaces "server is
// closing". Keeping this as an explicit subtest pins the failure mechanism
// the drain eliminates.
func TestStdioDrain_BaselineReproducesRace(t *testing.T) {
	input := drainInitializeRequest + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow_echo","arguments":{"text":"x"}}}` + "\n"

	raw := func(_ context.Context, stdin io.ReadCloser, stdout io.WriteCloser) mcp.Transport {
		return &mcp.IOTransport{Reader: stdin, Writer: stdout}
	}
	stdout, runErr := runMCPStdioSession(t, newDrainTestServer(), raw, []byte(input))
	if runErr == nil {
		t.Skipf("baseline did not reproduce the race this run (stdout: %s)", stdout)
	}
	if !strings.Contains(runErr.Error(), "server is closing") {
		t.Fatalf("baseline failure must be the EOF shutdown race, got: %v", runErr)
	}
}

// Case ①: a single initialize request with NO trailing newline, followed
// immediately by closing stdin. The gate must deliver the unterminated tail
// line and still let the response out before reporting EOF.
func TestStdioDrain_NoTrailingNewlineInitialize(t *testing.T) {
	stdout, runErr := runMCPStdioSession(t, newDrainTestServer(), newStdioDrainTransport,
		[]byte(drainInitializeRequest)) // no trailing '\n'
	assertDrainSessionOK(t, runErr, stdout, `"id":1`)
}

// Case ②: many concurrent sessions each doing write+immediate-close. Before
// the fix a fraction lost the race and exited rc=1; the drain must make the
// outcome deterministic.
func TestStdioDrain_ConcurrentInitializeImmediateEOF(t *testing.T) {
	const sessions = 50
	var wg sync.WaitGroup
	errs := make([]error, sessions)
	outs := make([]string, sessions)
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stdout, runErr := runMCPStdioSession(t, newDrainTestServer(), newStdioDrainTransport,
				[]byte(drainInitializeRequest+"\n"))
			errs[i], outs[i] = runErr, stdout
		}(i)
	}
	wg.Wait()
	for i := range sessions {
		if errs[i] != nil {
			t.Fatalf("session %d: srv.Run returned %v (stdout: %s)", i, errs[i], outs[i])
		}
		if !strings.Contains(outs[i], `"id":1`) || !strings.Contains(outs[i], `"serverInfo"`) {
			t.Fatalf("session %d: initialize response incomplete: %s", i, outs[i])
		}
	}
}

// Case ③: a pipelined burst — initialize + initialized notification + a slow
// tools/call — then the client hangs up. The tools/call response must still
// be fully written before EOF is reported.
func TestStdioDrain_PipelinedImmediateEOF(t *testing.T) {
	input := drainInitializeRequest + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow_echo","arguments":{"text":"x"}}}` + "\n"
	stdout, runErr := runMCPStdioSession(t, newDrainTestServer(), newStdioDrainTransport, []byte(input))
	assertDrainSessionOK(t, runErr, stdout, `"id":1`, `"id":2`)
	if !strings.Contains(stdout, `"tool:x"`) && !strings.Contains(stdout, `tool:x`) {
		t.Fatalf("stdout missing slow_echo result text, got: %s", stdout)
	}
}

// gatedWriteCloser blocks inside Write until a token arrives on gate;
// closing gate releases every subsequent Write. It holds Write calls in
// flight so stdoutTracker.Close overlaps them deterministically instead of
// relying on scheduler luck.
type gatedWriteCloser struct {
	gate chan struct{}
}

func (w *gatedWriteCloser) Write(p []byte) (int, error) {
	<-w.gate
	return len(p), nil
}

func (w *gatedWriteCloser) Close() error { return nil }

// Regression for the stdoutTracker Write/Close data race: the SDK serializes
// ioConn.Write with writeMu but ioConn.Close does NOT take writeMu
// (transport.go), so while a handler goroutine sits inside Write the
// shutdown path can call stdoutTracker.Close concurrently. Both paths
// touched t.buf unsynchronized — a torn buf can also drop the release() of a
// completed line and stall the drain for the full stdioDrainMaxWait.
// Under -race this test fails on the unguarded implementation; with the
// mutex it must pass and the writer goroutine must never deadlock.
func TestStdoutTracker_WriteCloseRace(t *testing.T) {
	const rounds = 4
	for r := 0; r < rounds; r++ {
		d := newStdioDrain()
		w := &gatedWriteCloser{gate: make(chan struct{})}
		tr := newStdoutTracker(w, d)

		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 1000; i++ {
				// Newline-free fragments stay in t.buf, so every Write mutates
				// the same state that Close scans.
				_, _ = tr.Write([]byte("x"))
			}
		}()

		// Let a few writes get in flight, then Close mid-stream — the exact
		// overlap ioConn permits.
		for i := 0; i < 8; i++ {
			w.gate <- struct{}{}
		}
		_ = tr.Close()
		close(w.gate) // release the remaining blocked writes

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: writer goroutine stuck — deadlock after Close", r)
		}
	}
}

// Probe for the "id":null release-fallback concern: an inbound request whose
// id is literally null is a notification per JSON-RPC (the SDK decodes it
// that way and — per conn.go processResult — never writes a response for
// it), so no outbound "id":null error response should appear and the
// in-flight tools/call must not be released early. If the SDK ever did emit
// an "id":null response here, the drain's release fallback would decrement
// id=2's count and this session would regress to "server is closing"/rc=1.
// The test is the arbiter: green pins the unreachable path, red proves the
// fallback bug reachable.
func TestStdioDrain_NullIDRequestDoesNotStealRelease(t *testing.T) {
	input := drainInitializeRequest + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow_echo","arguments":{"text":"x"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":null,"method":"bogus"}` + "\n"
	stdout, runErr := runMCPStdioSession(t, newDrainTestServer(), newStdioDrainTransport, []byte(input))
	assertDrainSessionOK(t, runErr, stdout, `"id":1`, `"id":2`)
	if !strings.Contains(stdout, `"id":null`) {
		t.Logf("no \"id\":null response on the wire (null-id inbound handled as notification): %s", stdout)
	}
}
