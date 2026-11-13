package main

// R10 audit adversarial probe (not for commit).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestR10Adv(t *testing.T) {
	for _, fn := range []string{"/root/r10in/adv/cases10.jsonl"} {
		f, err := os.Open(fn)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var c struct{ ID, Lang, Kind, Code string }
			if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
				t.Fatal(err)
			}
			got := auGuard(t, auCase{id: c.ID, role: "scout", lang: c.Lang, cmd: c.Code})
			d := "ALLOW"
			if r, dd := (guardCall{strictReadonly: true, readonly: true}).guardCtxRunCode(c.Lang, c.Code); r != "" {
				d = "BLOCK " + r + ": " + dd
			}
			fmt.Printf("R10ADV\t%s\t%s\t%s\t%s\t%s\n", c.Lang, c.Kind, c.ID, got, d)
		}
		f.Close()
	}
}
