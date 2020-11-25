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
FROM iteringops/darwinia-builder:latest as builder

RUN rustup update && rustup default nightly

COPY . /source
WORKDIR /source

ENV TERM="xterm-256color"

RUN cargo build --release

FROM debian:stable-slim

RUN apt-get update && apt-get -y install openssl && apt-get clean
COPY --from=builder /source/target/release/darwinia /usr/local/bin/.

EXPOSE 30333 9933 9944
VOLUME ["/data"]

ENTRYPOINT [ "/usr/local/bin/darwinia" ]
