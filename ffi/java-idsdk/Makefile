clean:
	@rm -rf bin

GO_SRC=../ffi_wrapper.go
#GO_SRC=main.go

so: clean
	@go build -buildmode=c-shared -o bin/lib-iotics-id-sdk.so ${GO_SRC}
