.PHONY: build build-release clean install test

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

test:
	@echo "Running unit tests..."
	@go test -v -cover
	@if [ -f ./compare_versions.sh ]; then \
		echo "Testing basic functionality..."; \
		./compare_versions.sh; \
	fi

.DEFAULT_GOAL := build
