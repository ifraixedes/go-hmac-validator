
.PHONY: dev-deps deps lint test doc

dev-deps:
	go get github.com/alecthomas/gometalinter
	gometalinter --install --update --force

deps:
	go get -u github.com/stretchr/testify
	@mkdir -p  vendor/github.com/stretchr/testify
	cp -r $(GOPATH)/src/github.com/stretchr/testify/assert \
		$(GOPATH)/src/github.com/stretchr/testify/require \
		$(GOPATH)/src/github.com/stretchr/testify/vendor \
		vendor/github.com/stretchr/testify

lint:
	gometalinter .

test:
	go test -v .

doc:
	godoc github.com/ifraixedes/go-hmac-validator
