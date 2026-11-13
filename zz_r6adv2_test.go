package main

import (
	"fmt"
	"testing"
)

func TestR6Adv2(t *testing.T) {
	py := []string{
		"import logging.config\nlogging.config._resolve('logging.FileHandler')('a.log')\n",
		"import logging.config\nlogging.config.BaseConfigurator({}).resolve('logging.FileHandler')('a.log')\n",
		"import pkgutil\npkgutil.resolve_name('logging:FileHandler')('a.log')\n",
		"import pydoc\npydoc.locate('logging.FileHandler')('a.log')\n",
		"from logging.handlers import BaseRotatingHandler as B\nB('a.log', 'a')\n",
		"import logging\n\uff4cogging.FileHandler('a.log')\n",
		"print('\u00e9t\u00e9')\n# caf\u00e9\n",
	}
	for _, c := range py {
		got := auGuard(t, auCase{role: "scout", lang: "python", cmd: c})
		fmt.Printf("ADV2PY\t%q\t%s\n", c, got)
	}
	js := []string{
		"require('fs').\\u0077riteFileSync('js.txt', 'x')\n",
		"require('fs').writeFileSync('js.txt', 'x')\n",
	}
	for _, lang := range []string{"javascript", "node", "js"} {
		for _, c := range js {
			got := auGuard(t, auCase{role: "scout", lang: lang, cmd: c})
			fmt.Printf("ADV2JS\t%s\t%q\t%s\n", lang, c, got)
		}
	}
}
