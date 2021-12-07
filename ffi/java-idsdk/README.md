# Java wrapper for the ID SDK

FFI wrapper using JNA

## Build

`$> mvn pakage`

## Test

A sample app is in the test/java directory: `com.iotics.sdk.identity.App`

## Use

```
SdkApi api = new JnaSdkApiInitialiser("<path_to>/lib-iotics-id-sdk-amd64.so").get();

```