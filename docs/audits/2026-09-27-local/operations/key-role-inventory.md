# Key and role inventory (no values)

| Capability | Source/config | Storage and rotation boundary |
|---|---|---|
| Custody spend keys | gateway account records / sealed snapshot | Gateway has plaintext in memory; back up authenticated snapshot with the enclave seed separately. Account recovery rotates API access, not ownership trust. |
| Enclave signing/sealing | ENCLAVE_SEED / encrypted keystore | Preserve snapshot decryptability and current epoch; do not substitute the public demo seed in production. |
| Gateway deposit signer | GATEWAY_SIGNER_KEY | Bound to vault gatewaySigner; changing the environment alone does not rotate contract authority. |
| Sequencer L1 signer | L1_SEQUENCER_KEY | Controls settlement/bond; rotation requires an explicit deployment/role plan and external authorization. |
| Oracle publisher | ORACLE_SIGNER_KEY | Trusted external price authority; rotation must match market key pins/native guest inputs. |
| Recovery authorizer | caller signer or bound deposit wallet | Owner/deployment/nonce-bound signatures; old generations revoked. Never collect user seed phrases. |
| FIN admin | FIN_ADMIN_KEY | Operational resume, insurance/wind-down actions; store out of repository, restrict routing. |
| Prover transport | PROVER_SEAL_ROOT + attested session | Measurement/expiry/restart handshake; no production DEV_INSECURE fallback. |
| Governance / verifier | contract immutable/configured addresses, programVKey | Separate privileged release decision; no rotation performed here. |

Real custodians, on-call owners and escalation destinations were not provided and are **unassigned**. No live secret inventory was read. This blocks operational readiness; it does not block deterministic local checks. Existing repository descriptions of custodial/trusted oracle roles remain applicable.
