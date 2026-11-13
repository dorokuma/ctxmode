package main

import (
	"fmt"
	"testing"
)

func TestR7Reg(t *testing.T) {
	for _, c := range r7load(t, "/root/r7in/adv/cases_reg.tsv") {
		got := auGuard(t, auCase{id: c[0], role: "scout", lang: "python", cmd: c[1]})
		fmt.Printf("R7REG\tpython\t%s\t%s\n", c[0], got)
	}
}
