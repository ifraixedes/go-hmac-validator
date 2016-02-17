
.PHONY: dev-deps

dev-deps:
	go get github.com/alecthomas/gometalinter
	gometalinter --install --update

lint:
	gometalinter -t .

test:
	go test -v .
