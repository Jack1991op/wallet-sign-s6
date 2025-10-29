GITCOMMIT := $(shell git rev-parse HEAD)
GITDATE := $(shell git show -s --format='%ct')

LDFLAGSSTRING +=-X main.GitCommit=$(GITCOMMIT)
LDFLAGSSTRING +=-X main.GitDate=$(GITDATE)
LDFLAGS := -ldflags "$(LDFLAGSSTRING)"

wallet-sign-server:
	go mod tidy
	env GO111MODULE=on go build -v $(LDFLAGS) ./cmd/wallet-sign-server

clean:
	rm wallet-sign-server

test:
	go test -v ./...

lint:
	golangci-lint run ./...

proto:
	sh ./bin/compile.sh

.PHONY: \
	wallet-sign-server \
	clean \
	test \
	lint \
	proto