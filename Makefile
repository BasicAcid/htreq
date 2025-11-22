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
	@echo "Testing basic functionality..."
	@./compare_versions.sh

.DEFAULT_GOAL := build
