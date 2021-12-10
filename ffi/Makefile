UNAME_OS := $(shell uname -s)
ifeq ($(UNAME_OS),Darwin)
	OS_FLAG=darwin
endif
ifeq ($(UNAME_OS),Linux)
	OS_FLAG=linux
endif

UNAME_ARCH := $(shell uname -s)
ifeq ($(UNAME_ARCH),i386)
	ARCH_FLAG=i386
endif
ifeq ($(UNAME_ARCH),amd64)
	ARCH_FLAG=amd64
endif

clean:
	@rm -rf bin go.mod go.sum

GO_SRC=./ffi_wrapper.go

compile:
	@env GOOS=$(OS_FLAG) GOARCH=$(ARCH_FLAG) go build -buildmode=c-shared -o bin/lib-iotics-id-sdk-$(ARCH_FLAG).so ${GO_SRC}

so: clean compile
