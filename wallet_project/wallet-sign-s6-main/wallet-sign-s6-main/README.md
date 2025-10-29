<!--
parent:
  order: false
-->

<div align="center">
  <h1> Wallet Offline Sign Service </h1>
</div>

<div align="center">
  <a href="https://github.com/dapplink-baas/wallet-sign-server/releases/latest">
    <img alt="Version" src="https://img.shields.io/github/tag/dapplink-baas/wallet-sign-server.svg" />
  </a>
  <a href="https://github.com/dapplink-baas/wallet-sign-server/blob/main/LICENSE">
    <img alt="License: Apache-2.0" src="https://img.shields.io/github/license/dapplink-baas/wallet-sign-server.svg" />
  </a>
  <a href="https://pkg.go.dev/github.com/dapplink-baas/wallet-sign-server">
    <img alt="GoDoc" src="https://godoc.org/github.com/dapplink-baas/wallet-sign-server?status.svg" />
  </a>
  <a href="https://goreportcard.com/report/github.com/dapplink-baas/wallet-sign-server">
    <img alt="Go report card" src="https://goreportcard.com/badge/github.com/dapplink-baas/wallet-sign-server"/>
  </a>
</div>

This is a wallet offline sign service support ECDSA and EdDSA for dapplink wallet bass.


**Note**: Requires [Go 1.23.8+](https://golang.org/dl/)

## Architecture

TBD

## Installation

For prerequisites and detailed build instructions please read the [Installation](https://github.com/dapplink-baas/wallet-sign-server/) instructions. Once the dependencies are installed, run:

```bash
make 
```

Or check out the latest [release](https://github.com/dapplink-baas/wallet-sign-server).


## Setup And Run

- Config yaml
```
level_db_path: "./data/keys"
rpc_server:
  host: 0.0.0.0
  port: 8186
credentials_file: "./"
key_name: "hsm"
key_path: "./keypath"
hsm_enable: false

chains: [Bitcoin, Ethereum, Solana]
```

- Run service

```
./wallet-sign-server rpc
```



