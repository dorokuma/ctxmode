package main

// R8 audit adversarial probe (not for commit).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestR8Adv(t *testing.T) {
	f, err := os.Open("/root/r8in/adv/cases8.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
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
		fmt.Printf("R8ADV\t%s\t%s\t%s\t%s\t%s\n", c.Lang, c.Kind, c.ID, got, d)
	}
}
