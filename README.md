# MathChain

Layer 2 blockchain based on Substrate

### Website

https://mathchain.org

### Testnet Explorer

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
