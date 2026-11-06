package main

import "testing"

// TestRAllow2_ForEnumSubst covers narrowed R-Allow-2 for-loop const
// substitution into -c payloads and top-level static abs-path heads.
func TestRAllow2_ForEnumSubst(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		reject bool
	}{
		{
			name:   "for_safe_python_c",
			code:   `for s in a b c; do python3 -c "print('$s')"; done`,
			reject: false,
		},
		{
			name:   "for_unsafe_enum_reject",
			code:   "for s in a '; pig; #'; do python3 -c \"print('$s')\"; done",
			reject: true,
		},
		{
			name:   "for_scene_worker_replay",
			code:   `for s in a b c d e; do python3 -c "import json;m=json.load(open('scene-$s/...'))"; done`,
			reject: false,
		},
		{
			name:   "for_enum_segments",
			code:   `for s in a b; do python3 -c "print('$s')"; done`,
			reject: false,
		},
		{
			name:   "export_abs_path_head",
			code:   `export BUN=/usr/bin/echo; "$BUN" hi`,
			reject: false,
		},
		{
			name:   "assign_abs_path_head",
			code:   `BUN=/usr/bin/echo; "$BUN" hi`,
			reject: false,
		},
		{
			name:   "rel_path_head_stays_dynamic",
			code:   `BUN=echo; "$BUN" hi`,
			reject: true,
		},
		{
			name:   "bind_inside_if_ignored",
			code:   `if true; then BUN=/usr/bin/echo; fi; "$BUN" hi`,
			reject: true,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			hit := guardShellSubagent(c.code)
			if c.reject {
				if hit == "" {
					t.Fatalf("expected REJECT, got ALLOW; code=%q", c.code)
				}
			} else if hit != "" {
				t.Fatalf("expected ALLOW, got REJECT %q; code=%q", hit, c.code)
			}
		})
	}

	// All enum values must produce screened segments.
	segs, ok := parseSubagentShellAST(`for s in a b c; do python3 -c "print('$s')"; done`, 0, false, false)
	if !ok {
		t.Fatal("parse failed")
	}
	if len(segs) < 3 {
		t.Fatalf("want >=3 enum segments, got %d: %#v", len(segs), segs)
	}
	want := []string{"print('a')", "print('b')", "print('c')"}
	for i, w := range want {
		if i >= len(segs) || len(segs[i].argv) < 3 || segs[i].argv[2] != w {
			t.Fatalf("seg[%d] want payload %q, segs=%#v", i, w, segs)
		}
	}
}
