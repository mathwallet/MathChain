#! /usr/bin/sh

# This file is part of Darwinia.

# Copyright (C) 2018-2020 Darwinia Networks
# SPDX-License-Identifier: GPL-3.0

# Darwinia is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Darwinia is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Darwinia.  If not, see <https://www.gnu.org/licenses/>.

echo -e '\e[1;32m🔧 Building Docker Image(s)\e[0m'
docker build -f docker/Dockerfile.x86_64-linux-gnu -t x86_64-linux-gnu . #&> /dev/null
docker build -f docker/Dockerfile.aarch64-linux-gnu -t aarch64-linux-gnu . #&> /dev/null

echo -e '\e[1;32m📥 Installing Cross Compile Toolchain(s)\e[0m'
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain nightly-2020-10-06 #&> /dev/null
source ~/.cargo/env
cargo install cross --git https://github.com/AurevoirXavier/cross --branch support-multi-sub-targets #&> /dev/null
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu wasm32-unknown-unknown #&> /dev/null

echo -e "\e[1;32m🧬 Building mathchain-$1-x86_64-linux-gnu-glibc-2.17-llvm-3.8 \e[0m"
cross build --release --target x86_64-unknown-linux-gnu --sub-targets wasm32-unknown-unknown #&> /dev/null

# echo -e "\e[1;32m🧬 Building mathchain-$1-aarch64-linux-gnu-glibc-2.23-llvm-3.8 \e[0m"
# RUSTFLAGS='-C link-args=-latomic' SKIP_WASM_BUILD=1 cross build --locked --release --target aarch64-unknown-linux-gnu #&> /dev/null

echo -e '\e[1;32m📦 Packing WASM(s)\e[0m'
rm -rf wasm
mkdir -p wasm
cp target/x86_64-unknown-linux-gnu/release/wbuild/mathchain-runtime/mathchain_runtime.compact.wasm wasm
cp target/x86_64-unknown-linux-gnu/release/wbuild/target/wasm32-unknown-unknown/release/mathchain_runtime.wasm wasm

echo -e '\e[1;32m📦 Packing Executable(s)\e[0m'
rm -rf release
mkdir -p release
cd release
cp ../wasm/* .
cp ../target/x86_64-unknown-linux-gnu/release/mathchain .
tar cjSf mathchain-$1-x86_64-linux-gnu-glibc-2.17-llvm-3.8.tar.bz2 mathchain
rm mathchain
# cp ../target/x86_64-unknown-linux-gnu/release/mathchain .
# tar cjSf mathchain-$1-aarch64-linux-gnu-glibc-2.23-llvm-3.8.tar.bz2 mathchain
# rm mathchain

echo -e '\e[1;32m🔑 Generating File(s) Hash\e[0m'
for f in *
do
    md5sum $f >> ../md5sums.txt
done
for f in *
do
    sha256sum $f >> ../sha256sums.txt
done
mv ../md5sums.txt .
mv ../sha256sums.txt .