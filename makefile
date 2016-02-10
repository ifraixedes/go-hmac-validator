
.PHONY: dev-deps

dev-deps:
	go get github.com/alecthomas/gometalinter
	gometalinter --install --update

test:
	go test -v .
