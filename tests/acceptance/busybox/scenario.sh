#!/bin/sh
# busybox v1 acceptance scenario per `43§5`. Drive interactively
# from the qemu-mcp serial-bridge:
#
#   1. Boot to `oxide login:`
#   2. login as root (no password)
#   3. /bin/busybox echo HELLO_FROM_BUSYBOX
#   4. Expect substring `HELLO_FROM_BUSYBOX` in output before any
#      [FAULT] line.
#
# This file is documentation; the harness reads it line-for-line.
# Lines starting with `>` are sent to serial; lines starting with
# `<` are expected substrings; everything else is a comment.

> root
>
> /bin/busybox echo HELLO_FROM_BUSYBOX
< HELLO_FROM_BUSYBOX
