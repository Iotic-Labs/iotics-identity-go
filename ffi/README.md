# iotics-identity-go/ffi

FFI wrapper for iotics-identity-go

## Build

With `make` installed you can compile for the current platform with
`make compile`. The script will detect the OS and ARCH and build for your system.

If you want to override the target os (the `GOOS` variable), define `$OS_FLAG` to the desired value.
For example if you want to compile for an iOS target run
`env OS_FLAG=ios make compile`


On Windows, if you don't have `make` you can run the powershell script `build.ps1` like:

`powershell -ExecutionPolicy Bypass -File build.ps1`

Alternatively you can build your version manually using:

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
