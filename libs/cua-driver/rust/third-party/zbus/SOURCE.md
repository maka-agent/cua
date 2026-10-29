<!-- SPDX-License-Identifier: MIT -->

# zbus source attribution

This directory contains the MIT-licensed `zbus 5.19.0` published package.
The copyright and permission notice are retained in `LICENSE`.

- Upstream: <https://github.com/z-galaxy/zbus>.
- Source revision: `7518d73db4dbf830ec1c9c43865bf8aeae9a8ffd`, package directory `zbus`.
- Published archive: <https://static.crates.io/crates/zbus/zbus-5.19.0.crate>.
- Archive SHA-256: `5db4be7c075cb421e4b7ee645541604239bd243ba7c357511f4ff3a74b555907`.

`Error::MissingErrorName(Message)` retains an error reply whose required error-name
header is absent. Its default display, description and source follow `InvalidReply`;
valid named errors and non-error invalid replies retain their upstream behavior.
The D-Bus connection, pending-call dispatch, serial routing and message decoder are
unchanged. AT-SPI consumers can inspect the retained reply with the existing decoder.

Downstream Cargo workspace roots must select this patched package explicitly in
`[patch.crates-io]`. For Git dependencies, use the same Cua revision as the driver;
Cargo does not inherit a dependency workspace's patch declarations.
