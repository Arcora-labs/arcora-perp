# Local account migration rehearsal

Scope: base `098e4952c189f92e4293ed7d49f81222b626e406`, isolated local worktree. This is a deployment procedure for review, not permission to publish.

1. Record matching frontend bundle, gateway SHA and public deployment tuple (canonical HTTP base, chainId, vault). Preserve the existing snapshot and take an authenticated backup using the gateway procedure. Never erase balances or reset a snapshot to resolve a browser credential error.
2. Test schema-2 reads against `/v1/accounts/me`. A scope mismatch, malformed record or rejected credential must show unavailable account state, preserve the record and offer Recover. Do not register a replacement for these cases.
3. A legacy `darkperp.v1Account` record supplies only a validated public 32-byte owner hint in Recover. Its unscoped API key is neither copied into schema 2 nor transmitted. The user confirms the intended deployment and selects the previously bound recovery-authorizer wallet. Never ask for a seed/private key or API key in the owner input.
4. Keep the old record intact during wallet-authorized recovery. Accept only a confirmed durable response with the requested owner and next server recovery nonce. A wallet rejection causes no mutation. A timeout leaves an unknown outcome; a key retained in storage may already be revoked.
5. Verify recovered balance, positions and withdrawal history through authenticated reads. A missing read is displayed as unavailable placeholders, never evidence of zero balance. Another same-origin tab adopts only a newer server-validated credential for the same owner.
6. If confirmed credentials cannot be persisted, keep this tab open and show session-only access. Reload can restore the revoked old bytes; use wallet recovery again. Do not export the replacement key to console, URL or screenshots.
7. Roll back frontend and gateway together only after checking credential/schema and snapshot version compatibility. A previous frontend that understands only unscoped credentials is not a safe automatic rollback target. Do not revert a confirmed server recovery nonce or attempt to revive an old key.

Automated fixture evidence covers legacy, schema mismatch, malformed record, native cross-tab storage and quota failure. Manual real extension wallet, real Safari, OS private mode, deployment switch and lost-authorizer support procedures remain external/manual gates. Headless WebKit is not Safari, and a synthetic EIP-1193 provider is not an extension wallet.
