export GOTOOLCHAIN := go$(shell awk '$$1 == "go" { print $$2; exit }' go.mod)

.PHONY: build desktop test test-provider test-tools check

build:
	sh scripts/build-macos-app.sh

desktop: build

test:
	CGO_LDFLAGS="-framework UniformTypeIdentifiers" go test -race ./...
	npm test
	$(MAKE) test-provider test-tools

test-provider:
	cd tests/provider && go test -race ./...

test-tools:
	python3 -m unittest discover -s tests -p 'test_*.py'
	@if [ -d .forgejo/tests ]; then python3 -m unittest discover -s .forgejo/tests -p 'test_*.py'; fi

check:
	go vet ./...
	cd tests/provider && go vet ./...
	node --check internal/portal/assets/app.js
