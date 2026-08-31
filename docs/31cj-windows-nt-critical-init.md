# Windows NT critical-section initialization

Status: FROZEN
Date: 2026-08-31

The three native critical-section initialization forms write the 64-bit user
layout's debug marker, unlocked lock count, zero owner/recursion/semaphore
state, and requested spin count. Acquisition and release continue to use the
native mutant-backed owner; Linux mutex and futex paths are unchanged.
