package main

// R7 audit adversarial probe (not for commit).

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func r7load(t *testing.T, p string) [][2]string {
	b, err := os.ReadFile(p)
	if err != nil {
		// Local audit fixtures live under /root on the dev host only;
		// skip (do not fail) when they are not available, e.g. on CI.
		t.Skip(err)
	}
	var out [][2]string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.SplitN(l, "\t", 2)
		out = append(out, [2]string{f[0], strings.ReplaceAll(f[1], `\n`, "\n")})
	}
	return out
}

func TestR7Adv(t *testing.T) {
	for _, c := range r7load(t, "/root/r7in/adv/cases_py.tsv") {
		got := auGuard(t, auCase{id: c[0], role: "scout", lang: "python", cmd: c[1]})
		fmt.Printf("R7ADV\tpython\t%s\t%s\n", c[0], got)
	}
	for _, c := range r7load(t, "/root/r7in/adv/cases_js.tsv") {
		for _, lang := range []string{"javascript", "node", "js"} {
			got := auGuard(t, auCase{id: c[0], role: "scout", lang: lang, cmd: c[1]})
			fmt.Printf("R7ADV\t%s\t%s\t%s\n", lang, c[0], got)
		}
	}
}
