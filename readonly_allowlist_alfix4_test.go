package main

import (
	"strings"
	"testing"
)

// Round-4: delete high-risk commands; tighten remaining parsers.
// Red samples cover AUDIT.md table (30) + prior agy samples.

func TestReadonlyAllowlist_Alfix4_AuditMustFixBlocked(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
	}{
		// 1 shell glued -c / extra args — whole shell deleted
		{name: "bash -ctrue", argv: []string{"bash", "-ctrue", "rm -rf /tmp/x"}},
		{name: "sh -ceu", argv: []string{"sh", "-ceu", "id"}},
		{name: "bash -c ls", argv: []string{"bash", "-c", "ls /tmp"}},
		{name: "sh -c ls", argv: []string{"sh", "-c", "ls /tmp"}},
		// 2 sed script escape — only sed -n Np|N,Mp kept
		{name: "sed e escape", argv: []string{"sed", "/[/s/]/e id;#/p"}},
		{name: "sed s", argv: []string{"sed", "s/a/b/", "f"}},
		{name: "sed d", argv: []string{"sed", "1d", "f"}},
		// 3-6 sqlite — whole command deleted
		{name: "sqlite comment escape", argv: []string{"sqlite3", "-readonly", "-safe", "a.db", `SELECT /*/ ' */ 1; VACUUM INTO "/tmp/pwn.db"; /* ' */`}},
		{name: "sqlite -safe create", argv: []string{"sqlite3", "-safe", "/tmp/new.db", "SELECT 1"}},
		{name: "sqlite PRAGMA paren", argv: []string{"sqlite3", "-safe", "a.db", "PRAGMA user_version(1)"}},
		{name: "sqlite WITH DELETE", argv: []string{"sqlite3", "-safe", "a.db", "WITH c AS (SELECT 1) DELETE FROM t"}},
		{name: "sqlite multi sqlParts", argv: []string{"sqlite3", "-readonly", "-safe", "a.db", "SELECT 1", ".output /tmp/x"}},
		{name: "sqlite ro+safe SELECT", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1"}},
		// 7-8 tar deleted
		{name: "tar -I glued", argv: []string{"tar", "-I/usr/bin/id", "-tf", "a.tar", "gzip"}},
		{name: "tar tfI", argv: []string{"tar", "tfI", "a.tar", "/usr/bin/id"}},
		{name: "tar --index-file", argv: []string{"tar", "-tvf", "a.tar", "--index-file=/tmp/overwrite"}},
		{name: "tar -tf", argv: []string{"tar", "-tf", "a.tar"}},
		// 9 git grep -O
		{name: "git grep -O glued", argv: []string{"git", "grep", "-O/usr/bin/id", "root"}},
		{name: "git grep --open-files-in-pager=", argv: []string{"git", "grep", "--open-files-in-pager=/usr/bin/id", "root"}},
		{name: "git grep -O", argv: []string{"git", "grep", "-O", "/usr/bin/id", "root"}},
		// 10 git config --show-scope write
		{name: "git config --show-scope write", argv: []string{"git", "config", "--show-scope", "core.fsmonitor", "/usr/bin/id"}},
		// 11 git symbolic-ref
		{name: "git symbolic-ref set", argv: []string{"git", "symbolic-ref", "refs/heads/pwn", "refs/heads/main"}},
		{name: "git symbolic-ref -d", argv: []string{"git", "symbolic-ref", "-d", "refs/heads/pwn"}},
		// 12 git branch/tag modifiers as query
		{name: "git branch --no-column create", argv: []string{"git", "branch", "--no-column", "new_br"}},
		{name: "git tag --no-color create", argv: []string{"git", "tag", "--no-color", "new_tag"}},
		// 13 git worktree/reflog skip flags
		{name: "git worktree -q add", argv: []string{"git", "worktree", "-q", "add", "/tmp/wt"}},
		{name: "git reflog -n expire", argv: []string{"git", "reflog", "-n", "1", "expire", "--all"}},
		{name: "git reflog -n 5 expire", argv: []string{"git", "reflog", "-n", "5", "expire"}},
		// 14 git fsck
		{name: "git fsck --lost-found", argv: []string{"git", "fsck", "--lost-found"}},
		{name: "git-fsck --lost-found", argv: []string{"git-fsck", "--lost-found"}},
		// 15 uniq --group swallow
		{name: "uniq --group out", argv: []string{"uniq", "--group", "in.txt", "out.txt"}},
		// 16 VAR=val prefix
		{name: "GIT_EXTERNAL_DIFF assign", code: "GIT_EXTERNAL_DIFF=/usr/bin/id git diff"},
		{name: "TAR_OPTIONS assign", code: `TAR_OPTIONS="--to-command=/bin/sh" tar -xOf a.tar`},
		{name: "LD_PRELOAD assign", code: "LD_PRELOAD=/tmp/x.so ls"},
		// 17 path argv0 / cd
		{name: "./ls", argv: []string{"./ls"}},
		{name: "/tmp/rg", argv: []string{"/tmp/rg"}},
		{name: "cd", argv: []string{"cd", "/tmp"}},
		// 18 unzip deleted
		{name: "unzip -l after archive", argv: []string{"unzip", "archive.zip", "-l"}},
		{name: "unzip -vu", argv: []string{"unzip", "-vu", "archive.zip"}},
		{name: "unzip -l", argv: []string{"unzip", "-l", "archive.zip"}},
		// 19 optional_argument swallow
		{name: "journalctl --boot vacuum", argv: []string{"journalctl", "--boot", "--vacuum-size=1M"}},
		{name: "date --iso-8601 -s glued", argv: []string{"date", "--iso-8601", "-s2026-01-01"}},
		// Should Fix samples
		{name: "curl gopher", argv: []string{"curl", "gopher://127.0.0.1:6379/_FLUSHALL"}},
		{name: "curl file", argv: []string{"curl", "file:///etc/shadow"}},
		{name: "curl --header= swallow", argv: []string{"curl", "--header=", "-o", "/tmp/x", "https://example.com"}},
		{name: "curl -sS", argv: []string{"curl", "-sS", "https://example.com"}},
		{name: "strace -o", argv: []string{"strace", "-o", "/tmp/overwrite", "ls"}},
		{name: "busybox sh", argv: []string{"busybox", "sh", "-c", "id"}},
		{name: "timeout ls", argv: []string{"timeout", "5", "ls"}},
		{name: "python3 json.tool", argv: []string{"python3", "-m", "json.tool", "input.json"}},
		{name: "go list -compiled", argv: []string{"go", "list", "-compiled", "./..."}},
		{name: "go list -export", argv: []string{"go", "list", "-export", "./..."}},
		{name: "go list -test", argv: []string{"go", "list", "-test", "./..."}},
		{name: "file -s", argv: []string{"file", "-s", "/dev/sda"}},
		{name: "file -z", argv: []string{"file", "-z", "a.gz"}},
		{name: "file --magic-file", argv: []string{"file", "--magic-file", "/tmp/m", "f"}},
		{name: "rg --search-zip", argv: []string{"rg", "--search-zip", "pat"}},
		{name: "rg -z", argv: []string{"rg", "-z", "pat"}},
		{name: "rg --pre", argv: []string{"rg", "--pre", "cmd", "pat"}},
		{name: "date set digits", argv: []string{"date", "110306292026"}},
		{name: "allDigits /tmp/123", argv: []string{"/tmp/123"}},
		{name: "allDigits base", argv: []string{"123"}},
		{name: "read PATH", argv: []string{"read", "PATH"}},
		{name: "arith ((", argv: []string{"((", "PATH=0", "))"}},
		{name: "ctxmode --config", argv: []string{"ctxmode", "--config", "/tmp/evil.toml", "search"}},
		{name: "ctxmode -config", argv: []string{"ctxmode", "-config", "/tmp/evil.toml", "search"}},
		{name: "tail -f", argv: []string{"tail", "-f", "a.log"}},
		{name: "tail -F", argv: []string{"tail", "-F", "a.log"}},
		{name: "tail --follow", argv: []string{"tail", "--follow", "a.log"}},
		{name: "journalctl -f", argv: []string{"journalctl", "-f"}},
		{name: "journalctl --follow", argv: []string{"journalctl", "--follow"}},
		{name: "journalctl --rotate", argv: []string{"journalctl", "--rotate"}},
		{name: "journalctl --flush", argv: []string{"journalctl", "--flush"}},
		{name: "herdr wait-output", argv: []string{"herdr", "pane", "wait-output"}},
		{name: "git ls-remote", argv: []string{"git", "ls-remote"}},
		{name: "git remote show", argv: []string{"git", "remote", "show", "origin"}},
		{name: "gcc -E", argv: []string{"gcc", "-E", "x.c"}},
		{name: "make bare", argv: []string{"make"}},
		{name: "gzip -l", argv: []string{"gzip", "-l", "a.gz"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if tc.code != "" {
				got = guardShellReadonly(tc.code)
			} else {
				got = guardArgvReadonly(tc.argv)
			}
			if got == "" {
				t.Fatalf("expected block for argv=%v code=%q", tc.argv, tc.code)
			}
		})
	}
}

func TestReadonlyAllowlist_AlFix4_CommonReadsStillPass(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
	}{
		{name: "cat", argv: []string{"cat", "/etc/hosts"}},
		{name: "head -n", argv: []string{"head", "-n", "20", "f"}},
		{name: "tail -n", argv: []string{"tail", "-n", "5", "f"}},
		{name: "wc", argv: []string{"wc", "-l", "f"}},
		{name: "rg", argv: []string{"rg", "-n", "foo", "."}},
		{name: "rg -A", argv: []string{"rg", "-A", "3", "foo", "."}},
		{name: "jq", argv: []string{"jq", ".", "f.json"}},
		{name: "git log", argv: []string{"git", "log", "-3"}},
		{name: "git show", argv: []string{"git", "show", "HEAD"}},
		{name: "git diff", argv: []string{"git", "diff"}},
		{name: "git status", argv: []string{"git", "status"}},
		{name: "git branch list", argv: []string{"git", "branch", "-a"}},
		{name: "ls", argv: []string{"ls", "-la"}},
		{name: "find", argv: []string{"find", ".", "-name", "*.go", "-print"}},
		{name: "sed -n range", argv: []string{"sed", "-n", "1,20p", "f"}},
		{name: "sed -n line", argv: []string{"sed", "-n", "5p", "f"}},
		{name: "ps", argv: []string{"ps", "aux"}},
		{name: "ss", argv: []string{"ss", "-lnt"}},
		{name: "git config --get", argv: []string{"git", "config", "--get", "user.name"}},
		{name: "git config -l", argv: []string{"git", "config", "-l"}},
		{name: "git worktree list", argv: []string{"git", "worktree", "list"}},
		{name: "git reflog", argv: []string{"git", "reflog"}},
		{name: "git reflog show", argv: []string{"git", "reflog", "show"}},
		{name: "git remote -v", argv: []string{"git", "remote", "-v"}},
		{name: "go list -json", argv: []string{"go", "list", "-json", "./..."}},
		{name: "go list -f", argv: []string{"go", "list", "-f", "{{.ImportPath}}", "./..."}},
		{name: "go list -m", argv: []string{"go", "list", "-m", "all"}},
		{name: "date -u", argv: []string{"date", "-u"}},
		{name: "date +fmt", argv: []string{"date", "+%Y-%m-%d"}},
		{name: "file plain", argv: []string{"file", "f"}},
		{name: "pipe", code: "ls /tmp | head -n 5"},
		{name: "herdr pane read", argv: []string{"herdr", "pane", "read", "w1:p1"}},
		{name: "uniq one file", argv: []string{"uniq", "f"}},
		{name: "journalctl -u -n", argv: []string{"journalctl", "-u", "x", "-n", "30", "--no-pager"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if tc.code != "" {
				got = guardShellReadonly(tc.code)
			} else {
				got = guardArgvReadonly(tc.argv)
			}
			if got != "" {
				t.Fatalf("expected allow, got %q (argv=%v code=%q)", got, tc.argv, tc.code)
			}
		})
	}
}

func TestReadonlyAllowlist_ShortOptsDisjoint(t *testing.T) {
	for name, entry := range readonlyAllowlist {
		if entry == nil {
			continue
		}
		for i := 0; i < len(entry.shortBool); i++ {
			ch := entry.shortBool[i]
			if strings.IndexByte(entry.shortValue, ch) >= 0 {
				t.Errorf("%s: shortBool and shortValue both contain %q", name, string(ch))
			}
		}
	}
}

func TestReadonlyAllowlist_AlFix4_HintAlternatives(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
		want []string
	}{
		{name: "bash hint", argv: []string{"bash", "-c", "ls"}, want: []string{"rg", "jq"}},
		{name: "curl hint", argv: []string{"curl", "-s", "https://x"}, want: []string{"cat", "rg"}},
		{name: "sqlite hint", argv: []string{"sqlite3", "-readonly", "-safe", "a.db", "SELECT 1"}, want: []string{"jq"}},
		{name: "python hint", argv: []string{"python3", "-m", "json.tool"}, want: []string{"jq"}},
		{name: "sed hint", argv: []string{"sed", "s/a/b/", "f"}, want: []string{"rg"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if tc.code != "" {
				got = guardShellReadonly(tc.code)
			} else {
				got = guardArgvReadonly(tc.argv)
			}
			if got == "" {
				t.Fatalf("expected block")
			}
			hinted := readonlyBlockWithHint(got)
			low := strings.ToLower(hinted)
			for _, w := range tc.want {
				if !strings.Contains(low, strings.ToLower(w)) {
					t.Fatalf("hint %q missing %q", hinted, w)
				}
			}
		})
	}
}
