package main

// R5 audit direct probe (not for commit).

import (
	"fmt"
	"testing"
)

func TestR5Direct(t *testing.T) {
	for _, c := range r5advCases {
		m := pythonMask(c.code)
		if len(m) != len(c.code) {
			fmt.Printf("MASKLEN\t%s\t%d!=%d\n", c.id, len(m), len(c.code))
		}
		hit := pythonWriteModeHit(c.code)
		v := "A"
		if hit != "" {
			v = "B"
		}
		mark := "ok"
		if v != c.want {
			mark = "MISMATCH"
		}
		fmt.Printf("DIRECT\t%s\twant=%s\tgot=%s\t%s\t%q\n", c.id, c.want, v, mark, hit)
	}
}
