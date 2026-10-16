/// Contract addresses are baked in at build time so a new deployment
/// (docs/REDEPLOY-CC-RUNBOOK.md) only needs VITE_MOCK_USDC and
/// VITE_COLLATERAL_VAULT, not a source edit. Unset keeps the recorded
/// deployment; a malformed value fails loudly rather than pointing users'
/// deposits and claims at the wrong contract.
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export function resolveContractAddress(value: string | undefined, fallback: string, name: string): string {
  if (value === undefined || value === "") return fallback;
  if (!ADDRESS.test(value)) throw new Error(`${name} must be a 20-byte 0x address`);
  return value;
}
