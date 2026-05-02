# 40 CI + Soak — v2 deferred entries

Carried at freeze 2026-05-02.

## Soak rotation order

v1 lean = weighted, sched-canary at 30% (highest historical bug density).

## Bench job skip on docs-only PRs

v1 = yes; path filter excludes docs/ from bench-job triggers.

## Self-hosted runner security

v1 lean = ephemeral mode (fresh container per job) for secret-leak protection.

## Cloud overflow when soak box busy

Defer Terraform-driven GCP/Hetzner spin-up until soak box becomes a measured bottleneck.
