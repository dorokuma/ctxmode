.PHONY: check

check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "gofmt: files not formatted:" >&2; \
		printf '%s\n' "$$files" >&2; \
		exit 1; \
	fi
	"$$(go env GOPATH)/bin/staticcheck" ./...
	go vet ./...
	go test -race ./...
	go build -o /dev/null .
	@if command -v node >/dev/null 2>&1; then \
		node --experimental-strip-types --test integrations/pi/*.test.ts; \
	elif [ "$${CI:-}" = "true" ]; then \
		echo "check: node not found but CI=true; refusing to skip integrations/pi/*.test.ts" >&2; \
		exit 1; \
	else \
		echo "check: node not in PATH (zero-node host); skipping integrations/pi/*.test.ts"; \
	fi
