# KI-0895 — disproven teardown hypothesis

Status: resolved false positive. Branch: B3630-paint-region-collapse.

`bridge.rs::window(hwnd)` only converts a nonzero32-bit handle to WindowId;
it does not query WindowManager. `publish_destroy_current` ignores the result
of clearing presentation readiness and proceeds to enqueue Destroy after
canonical teardown. Therefore the missing-live-HWND rejection described in
KI-0895 does not occur. No destruction implementation was changed for this
hypothesis. The last preview's bridge refusals still need their actual cause
resolved; this audit does not attribute stale surfaces to destruction.
