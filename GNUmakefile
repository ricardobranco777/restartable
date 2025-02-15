BIN	= restartable

.PHONY: all
all:	$(BIN)

GO	:= go

# https://github.com/golang/go/issues/64875
arch := $(shell uname -m)
ifeq ($(arch),s390x)
CGO_ENABLED = 0
else
CGO_ENABLED := 1
endif

$(BIN): *.go
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags="-s -w -buildid=" -buildmode=pie

.PHONY: test
test:
	$(GO) test ./... -v
	$(GO) vet
	staticcheck
	gofmt -s -l .

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: clean
clean:
	$(GO) clean

.PHONY: gen
gen:
	rm -f go.mod go.sum
	$(GO) mod init $(BIN)
	$(GO) mod tidy

.PHONY: install
install: $(BIN)
	install -s -m 0755 $(BIN) /usr/local/bin/ 2>/dev/null
