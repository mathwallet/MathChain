# MathChain

MathChain is the Polkadot Smart Wallet Parachain based on Substrate

## Basic Module

### DID

Social recovery to keep account safe

### KayWhySee

Connect DID with real ID

### DAO

Support project on-chain governance

### EVM

Run solidity smart contracts as layer 2

### Roadmap

https://docs.mathchain.org/en/milestone/

### Website

https://mathchain.org

### About

http://blog.mathwallet.org/?p=2036

### Explorer

http://scan.boka.network/#/Galois

### Build from Sourcecode

1、The first thing you will need to do is prepare the computer for Rust development. This is same as substrate installation. Here is the document: https://substrate.dev/docs/en/knowledgebase/getting-started/

2、Clone MathChain from Github:

``` git clone https://github.com/mathwallet/MathChain.git ```

3、Enter the directory:

``` cd MathChain ```

4、Init the submodule:

``` git submodule update --init --recursive ```

5、Now you can build the MathChain from source code:

``` cargo build --release ```
