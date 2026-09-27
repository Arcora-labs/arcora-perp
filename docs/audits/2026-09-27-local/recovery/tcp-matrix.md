# Real transport matrix

The S1 suite uses actual localhost Axum/Tungstenite sockets. `deterministic-race-tests.log` initially selected 31 tests and passed all 31; an additional controlled AuthOk race was then added for the parent's final integrated suite. Do not transfer the 31-test result to that later test until its own/final log passes.

| Scenario | Exact test | What proves it |
|---|---|---|
| Idle revoked without traffic | `direct_idle_revocation_requires_transport_closure_not_silence` | Actual Close/EOF/reset, with no tick/private/client frame needed |
| Queued private event behind rotation | `s1f_queued_private_event_cannot_cross_rotation` | Writer fence queues recovery before event delivery; no private event crosses generation |
| Account A waits for disk while B receives private event | `direct_other_account_delivers_while_recovery_waits_for_disk` | Parked snapshot ACK and B event over real socket within 1s |
| Stalled private send with multiple same-owner sockets | `local_tcp_backpressure_has_bounded_send_and_other_account_progress` | Requested 8KiB send buffer, one 8MiB event, two unread A sockets; B private event proceeds; read lease releases at deadline; both A sockets physically close |
| AuthOk queued behind recovery | `local_tcp_auth_ok_queued_behind_rotation_never_discloses_stale_success` | FIFO write fence plus watch subscriber count is an explicit auth boundary; stale socket gets no authOk and must close |
| Completed send versus rotation | `s1f_send_lease_fences_rotation_without_holding_gw` | Controlled future at production send boundary; local mutex is available to other accounts; this row is not a TCP pressure test |
| Deadline release | `s1f_stalled_send_releases_lease_on_deadline` | Paused Tokio clock and never-completing send; separate unit evidence, not real TCP |
| Slow-reader regression test no longer passes on timeout | `ws_revocation_race_slow_consumer_and_no_lock_across_send` | Timeout now fails; arbitrary error is not closure; no payload after revocation error |

The managed local tests assert event receiver count returns to its pre-connection baseline and join the listener task. The pressure measurement was B=1ms, account lease release=2089ms, receiver baseline=0 in the recorded initial run; see `latency-observations.json`. This is one observation, not p95/p99 or a WAN/performance guarantee.

Still open for full S1-02: forced peer RST during each distinct partial-write/flush boundary and repeated long-running process-wide file-descriptor census. Existing tests run on loopback; physical-network behavior is not inferred.
