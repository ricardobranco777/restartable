BIN	= restartable

.PHONY: all
all:	$(BIN)

GO	:= go
CGO_ENABLED := 0

$(BIN): *.go
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build

.PHONY: test
test:
	$(GO) vet
	staticcheck
	$(GO) test

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
