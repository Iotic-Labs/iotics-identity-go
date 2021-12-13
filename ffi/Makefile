clean:
	@rm -rf bin go.mod go.sum

GO_SRC=./ffi_wrapper.go

compile_lin:
	@env GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -o lib/lib-iotics-id-sdk-linux-amd64.so ${GO_SRC}

compile: compile_lin

so: clean compile_lin
