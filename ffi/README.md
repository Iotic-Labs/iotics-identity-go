# iotics-identity-go/ffi

FFI wrapper for iotics-identity-go

## Build

`make compile`

The target should determine the platform and architecture of the current OS and build the binary library accordingly.

Alternatively you can build your version using:

`env GOOS=<os> GOARCH=<arch> go build -buildmode=c-shared -o lib/lib-iotics-id-sdk.so ./ffi_wrapper.go`

## Verifying goreleaser locally

```bash
# verify build (optional)
goreleaser build --snapshot --rm-dist --single-target
# verify packaging
goreleaser release --auto-snapshot --rm-dist
# verify content of the packages
tar -tvf dist/*.tar.gz
```
