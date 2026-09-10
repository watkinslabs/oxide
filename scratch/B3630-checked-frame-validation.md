# Checked frame submission

- KI0900: unchecked image requests returned success before X11 rejection; response0 was discarded by generic event decoding. Frame/replay now submits checked tile requests and consumes every result before acknowledging. Request cookies are transient for one batch; no persistent tracking registry or per-tile submission wait.
- Actual Xvfb server-side window destruction reproduces false successful Frame ACK0 instead of failure1. /tmp/B3630-draw-error-red.log. Corrected code returns failure on the actual bridge protocol and logs HWND, X11 request sequence, resource/error/opcodes.
- Earlier rejected request followed by successful final request still fails the batch. Checking only the last cookie fails this regression: /tmp/B3630-draw-batch-control.log. All checked results are consumed, including after one fails; broken connections also fail completion.
- Restored103 compositor tests PASS (96 library+7 integration), /tmp/B3630-draw-restored-tests.log. Both release builds PASS, /tmp/B3630-draw-build-{x86,arm}.log. ARM uses existing completed Fedora sysroot; system sysroot unchanged.
- All production image submissions use checked form through x11/requests.rs; unused unchecked FFI removed. Kernel code unchanged since validated teardown0d529870e; its both-architecture build/feature/frame/stack evidence remains applicable.
- No boot or visual Notepad acceptance in this repair. Successful request completion establishes server acceptance, not compositor scanout or screenshot correctness.
- x86 release artifact target/B3630-compositor-checked-release-x86: SHA256 9d2d07c8452d9035c73f44edf9dab9fc00caa54de5aa8c2310b8c04e884f6a3e.
- arm release artifact target/B3630-compositor-checked-release-arm: SHA256 6d902f38162b1b4ecb7c84f1e073117b257869bc7aa390603946de18ae2abf63.
- Runtime0314a2e42 pushed in f9b73e77e; remote SHA verified. Push180 isolated hosted checks and both feature checks PASS; only documented KI0019 lint/test-build/stack baseline exceptions.
