clean:
	@rm -rf bin go.mod go.sum

GO_SRC=./ffi_wrapper.go

compile:
	@env GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -o bin/lib-iotics-id-sdk-amd64.so ${GO_SRC}

so: clean compile
