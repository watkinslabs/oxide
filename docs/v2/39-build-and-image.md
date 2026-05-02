# 39 Build + Image — v2 deferred entries

Carried at freeze 2026-05-02.

## `cargo-bake` for image

Deferred; `xtask` is sufficient.

## Reproducible musl build

v1 pins the musl source hash + vendors it.

## Multi-arch single boot.img

No; one image per arch.
