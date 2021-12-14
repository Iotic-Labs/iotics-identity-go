ifeq ($(OS),Windows_NT)
    OS_FLAG=windows
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
        ARCH_FLAG=amd64
    else
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
            ARCH_FLAG=amd64
        endif
        ifeq ($(PROCESSOR_ARCHITECTURE),x86)
            ARCH_FLAG=386
        endif
    endif
	OS_EXT=dll
else
	UNAME_OS := $(shell uname -s)
	ifeq ($(UNAME_OS),Darwin)
		OS_FLAG=darwin
	endif
	ifeq ($(UNAME_OS),Linux)
		OS_FLAG=linux
	endif

	UNAME_ARCH := $(shell uname -s)
	ifeq ($(UNAME_ARCH),i386)
		ARCH_FLAG=386
	endif
	ifeq ($(UNAME_ARCH),amd64)
		ARCH_FLAG=amd64
	endif
	OS_EXT=so
endif

clean:
	@rm -rf lib bin go.mod go.sum

GO_SRC=./ffi_wrapper.go

compile_task:
	@env GOOS=${OS_FLAG} GOARCH=${ARCH_FLAG} go build -buildmode=c-shared -o lib/lib-iotics-id-sdk.${OS_EXT} ${GO_SRC}

compile: clean compile_task
