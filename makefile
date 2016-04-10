
.PHONY: dev-deps deps lint test doc

dev-deps:
	go get github.com/alecthomas/gometalinter
	gometalinter --install --update --force

lint:
	gometalinter .

test:
	go test -v .

doc:
	godoc github.com/ifraixedes/go-hmac-validator
