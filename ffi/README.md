# Build

`make compile`

The target should determine the platform and architecture of the current OS and build the binary library accordingly.

Alternatively you can build your version using:

`env GOOS=<os> GOARCH=<arch> go build -buildmode=c-shared -o lib/lib-iotics-id-sdk.so ./ffi_wrapper.go`
