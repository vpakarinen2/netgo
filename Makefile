GO ?= go
VERSION ?= dev
BINARY := bin/scan
ifeq ($(OS),Windows_NT)
BINARY := bin/scan.exe
endif

.PHONY: build plugins test vet fmt fmt-check check race fuzz clean

plugins:
	$(GO) run ./tools/build-plugins

build:
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/scan

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd configs internal pkg examples tools

fmt-check:
	@test -z "$$(gofmt -l cmd configs internal pkg examples tools)" || (gofmt -l cmd configs internal pkg examples tools; exit 1)

check: fmt-check test vet build

race:
	$(GO) test -race ./...

fuzz:
	$(GO) test ./pkg/network/targets -run='^$$' -fuzz=FuzzParsePorts -fuzztime=10s
	$(GO) test ./pkg/network/targets -run='^$$' -fuzz=FuzzSpanUnion -fuzztime=10s
	$(GO) test ./pkg/service -run='^$$' -fuzz=FuzzFingerprint -fuzztime=10s
	$(GO) test ./pkg/service -run='^$$' -fuzz=FuzzWebFingerprint -fuzztime=10s
	$(GO) test ./pkg/network/sockets -run='^$$' -fuzz=FuzzUDPReplyMatching -fuzztime=10s

clean:
	$(GO) clean ./...
