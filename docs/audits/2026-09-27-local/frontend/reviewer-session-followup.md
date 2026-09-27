# Independent-review follow-up: persistent session-only warning

The independent reviewer confirmed that `recover()` clears the prior result before retrying. Although the current credential remained session-only, its storage warning disappeared during the second attempt and after a rejected wallet signature.

A controlled Chromium test performed one confirmed recovery with quota-denied persistence, held the next metadata request at a barrier, then rejected the second signature. Its failed-before assertion observed `{during: null, after: null}` instead of the required session-only notice (`reviewer-session-failed-before.log`, one failed test, exit 1).

`RecoveryPanel` now derives the storage notice directly from the current client's `credentialStorage`. The per-attempt result contains only the latest successful generation. Clearing the result cannot clear the persistent notice; failure and notice remain visible together. No changes to other production source were made.

Validation on this follow-up source:

- Chromium + WebKit targeted browser regression: 2 passed, exit 0.
- `RecoveryPanel.test.tsx`: 4 passed, exit 0, including a pending/rejected retry unit test.
- Frontend typecheck: exit 0.

The previous 36/36 full browser run remains historical evidence on its recorded source fingerprint. Its exact-source coverage is stale after this component/test change. The subsequent final aggregate run passed all 38 browser cases (19 per engine) on the same follow-up source. See `final-browser.log`, `final-source-manifest.json` and `evidence.json`.
