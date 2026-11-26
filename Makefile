BIN ?= bin/rsbx
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: build dev-bundle test check fmt lint vuln clean

build:
	go build -ldflags "-X github.com/gyrel/sandboxes-cli/internal/version.Commit=$(COMMIT)" -o $(BIN) ./cmd/rsbx

# Local workspace bundle; releases must use tagged module dependencies.
dev-bundle:
	go build -ldflags "-X github.com/gyrel/sandboxes-cli/internal/version.Commit=$(COMMIT)" -o dist/rsbx ./cmd/rsbx
	cd ../sandboxes-daemon && go build -o ../sandboxes-cli/dist/sandboxesd ./cmd/sandboxesd
	cd ../sandboxes-guest && CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -trimpath -o ../sandboxes-cli/dist/sandboxes-guest-linux-$$(go env GOARCH) ./cmd/sandboxes-guest

test:
	go test -race -count=1 ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint config verify
	golangci-lint run ./...

vuln:
	govulncheck ./...

clean:
	rm -rf bin
