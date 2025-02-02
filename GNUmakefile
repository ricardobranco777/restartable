BIN	= restartable

.PHONY: all
all:	$(BIN)

GO	:= go

$(BIN): *.go
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -buildmode=pie

.PHONY: test
test:
	$(GO) vet
	staticcheck
	$(GO) test ./... -v

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
