# iotics-identity-go/ffi

FFI wrapper for iotics-identity-go

## Build

On a *nix base OS, or if you have `make` installed you can compile for the current platform with
`make compile`

if you want to override the value of GOOS, define `$OS_FLAG` to the desired value. For example 
`env OS_FLAG=ios make compile`


On Windows

`powershell -ExecutionPolicy Bypass -File build.ps1`

The target should determine the platform and architecture of the current OS and build the binary library accordingly.

Alternatively you can build your version using:

`env GOOS=<$OS_FLAG> GOARCH=<$OS_ARCH> go build -buildmode=c-shared -o lib/lib-iotics-id-sdk.so ./ffi_wrapper.go`

## Verifying goreleaser locally

```bash
# verify build (optional)
goreleaser build --snapshot --rm-dist --single-target
# verify packaging
goreleaser release --auto-snapshot --rm-dist
# verify content of the packages
tar -tvf dist/*.tar.gz
```
