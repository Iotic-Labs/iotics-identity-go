# iotics-identity-go

[![GitHub Workflow](https://img.shields.io/github/workflow/status/Iotic-Labs/iotics-identity-go/go)](https://github.com/Iotic-Labs/iotics-identity-go/actions/workflows/go.yml)
[![GitHub Issues](https://img.shields.io/github/issues/Iotic-Labs/iotics-identity-go)](https://github.com/Iotic-Labs/iotics-identity-go/issues)
[![GitHub Release](https://img.shields.io/github/v/release/Iotic-Labs/iotics-identity-go)](https://github.com/Iotic-Labs/iotics-identity-go/releases)
[![GitHub Go Mod version](https://img.shields.io/github/go-mod/go-version/Iotic-Labs/iotics-identity-go)](https://github.com/Iotic-Labs/iotics-identity-go/blob/main/go.mod)
[![GitHub License](https://img.shields.io/github/license/Iotic-Labs/iotics-identity-go)](https://github.com/Iotic-Labs/iotics-identity-go/blob/main/LICENSE)
[![GitHub Contributors](https://img.shields.io/github/contributors/Iotic-Labs/iotics-identity-go)](https://github.com/Iotic-Labs/iotics-identity-go)

Create Data Mesh. Use interoperable digital twins to create data interactions and build powerful real-time data products. This repository is a library for Decentralised Identity (DID) management with Iotics for applications in go.

You need to have an IOTICSpace to take advantage of this DID SDK. Contact <a href="mailto:product@iotics.com">product@iotics.com</a> for a free trial or [![sign up](https://img.shields.io/badge/sign%20up-164194.svg?style=flat)](https://www.iotics.com/signup-preview-program/)

## Identity SDK

This SDK is used to manage identities and authentication in the Iotics Host.

The SDK is split into two API's according to the user needs:

* [High level identity API](pkg/api): minimal set of features to interact with Iotics Host
* [Advanced identity API](pkg/advancedapi): set of features for advanced identities management

## How to

See tutorials on [docs.iotics.com](https://docs.iotics.com/docs/create-decentralized-identity-documents).

[Foreign Function Interface](./ffi/rust/README.md).

## Reporting issues

The issue tracker for this project is currently located at [GitHub](https://github.com/Iotic-Labs/iotics-identity-go/issues).

Please report any issues there with a sufficient description of the bug or feature request. Bug reports should ideally be accompanied by a minimal reproduction of the issue. Irreproducible bugs are difficult to diagnose and fix (and likely to be closed after some period of time).

Bug reports must specify the version of the `iotics-identity-go` module.

## Contributing

This project is open-source and accepts contributions. See the [contribution guide](./CONTRIBUTING.md) for more information.

## License

Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) in the project root for license information.

## Technology Used

* Markdown
* Golang
* DID
* BDD
