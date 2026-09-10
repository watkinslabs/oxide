# Notepad menu observation

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0925 menu OCR |

Real guest screenshot crop retains underlined menu glyphs. Full-frame sparse OCR loses File; original menu lookup fails the fixture. Overlapping enlarged row crops recover the exact complete File/Edit/Format/View/Help sequence before returning scaled screen coordinates. Existing exact full-frame lookup remains valid. No approximate spelling, changed timeout or skipped document check.

Actual source before correction:1failed/1passed, /tmp/B3630-menu-ocr-red.log. Corrected:2passed, /tmp/B3630-menu-ocr-green.log. Erasing the actual menu must still return None. Fixture is the unmodified Notepad window crop from diagnostic4127818. Adjacent menu/frame/document/launch tests:19passed, /tmp/B3630-menu-ocr-tests.log. Live verification pending.
