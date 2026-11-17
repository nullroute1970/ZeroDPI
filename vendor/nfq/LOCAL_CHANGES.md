# Local changes to nfq 0.2.5

Source: the published `nfq` 0.2.5 crate from crates.io
([upstream](https://github.com/nbdd0121/nfq-rs)). The original MIT and Apache
licenses are included. `Cargo.toml` is the upstream `Cargo.toml.orig`.

The API change is an `AsRawFd` implementation for `Queue`. This borrows
the existing socket descriptor without transferring ownership or changing how
packets are received or verdicts are sent. ZeroDPI needs the descriptor to wait
for NFQUEUE readability with `poll`, instead of sleeping after `WouldBlock`.

One existing hardware-address slice also uses an explicit reference instead of
an implicit raw-pointer autoref. Recent Rust compilers reject the implicit form
when this crate is built as a local dependency. The slice and its lifetime are
unchanged.

Trailing whitespace in the upstream README example was removed.

The root workspace patches the existing nfq dependency to this copy; the
upstream crate is excluded from workspace formatting and linting. Keep other
upstream source files unchanged so the patch remains easy to compare and remove
when a suitable published release exposes the descriptor.
