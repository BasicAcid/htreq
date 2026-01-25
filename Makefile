.PHONY: build build-release clean install test test-unit test-integration test-all

BINARY=htreq
INSTALL_PATH=/usr/local/bin
LDFLAGS=-ldflags="-s -w"

build:
	go build -o $(BINARY) .

build-release:
	go build $(LDFLAGS) -o $(BINARY) .
	@echo "Binary size:" && ls -lh $(BINARY) | awk '{print $$5}'

install: build-release
	install -m 755 $(BINARY) $(INSTALL_PATH)/$(BINARY)

clean:
	rm -f $(BINARY)

test-unit:
	@echo "Running unit tests..."
	@go test -v -cover

test-integration: build
	@echo "Running integration tests..."
	@./test/integration_test.sh

test: test-unit
	@if [ -f ./compare_versions.sh ]; then \
		echo "Testing basic functionality..."; \
		./compare_versions.sh; \
	fi

test-all: test-unit test-integration

.DEFAULT_GOAL := build
