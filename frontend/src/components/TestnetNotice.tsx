import { useState } from "react";
import { MOCK_USDC, COLLATERAL_VAULT as VAULT } from "../api/wallet";

/// Honest public-testnet disclosure: what is REAL and what is a STAND-IN, plus how
/// to get test USDC. Dismissible (persisted), but shown on first visit so no one
/// mistakes the testnet for a mainnet with real funds. Kept deliberately blunt.
/// Contract addresses come from api/wallet.ts — ONE place to update on redeploy.
// v3: clean pre-alpha redeploy (2026-07-09) — fresh stack, so the faucet addresses
// changed again; re-show once so returning users mint into the live vault.
const DISMISS_KEY = "dp_testnet_notice_dismissed_v3";

export function TestnetNotice() {
  const [open, setOpen] = useState(
    () => typeof localStorage === "undefined" || localStorage.getItem(DISMISS_KEY) !== "1",
  );
  const [showFaucet, setShowFaucet] = useState(false);
  if (!open) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      /* private mode — just close for the session */
    }
    setOpen(false);
  };

  return (
    <div className="banner banner--notice" role="note">
      <div className="banner__main">
        <span className="banner__dot" />
        <span>
          <strong className="banner__title">Public testnet — funds are not real.</strong>{" "}
          <span className="banner__desc">
            Settlement runs on Base Sepolia with <strong>test USDC</strong>. Matching runs
            in a real Azure TDX enclave (attested), and settlement is now enforced by{" "}
            <strong>real zk validity proofs</strong> (SP1/Groth16, verified on-chain) —
            produced by a dev prover that is not yet TEE-attested. Deposits and orders
            confirm instantly (soft finality); on-chain <strong>SETTLED</strong> finality
            and withdrawals lag <strong>~a proof interval (~10–20&nbsp;min)</strong>. Orders
            reach the gateway over TLS. Don't send anything you can't lose.
          </span>
        </span>
      </div>
      <div className="banner__actions">
        <button className="banner__btn" onClick={() => setShowFaucet((v) => !v)}>
          Get test USDC
        </button>
        <button className="banner__btn" onClick={dismiss} aria-label="Dismiss">
          Got it
        </button>
      </div>
      {showFaucet && (
        <div className="banner__faucet">
          <p className="banner__desc">
            The collateral token is an open-mint MockUSDC (6 decimals). Mint to your wallet,
            then deposit to the vault — e.g. with Foundry <code>cast</code> (mints 1,000 USDC):
          </p>
          <pre className="banner__code">
            {`# 1. mint 1,000 test USDC to yourself\n`}
            {`cast send ${MOCK_USDC} \\\n`}
            {`  "mint(address,uint256)" <YOUR_ADDR> 1000000000 \\\n`}
            {`  --rpc-url https://sepolia.base.org --private-key <YOUR_KEY>\n\n`}
            {`# 2. approve + deposit into the vault\n`}
            {`cast send ${MOCK_USDC} "approve(address,uint256)" ${VAULT} 1000000000 \\\n`}
            {`  --rpc-url https://sepolia.base.org --private-key <YOUR_KEY>\n`}
            {`cast send ${VAULT} "deposit(uint256)" 1000000000 \\\n`}
            {`  --rpc-url https://sepolia.base.org --private-key <YOUR_KEY>`}
          </pre>
          <p className="banner__desc">
            Then register an API key on the <strong>API</strong> tab and POST the deposit tx
            hash to <code>/v1/accounts/deposit/onchain</code> to credit your account.
          </p>
          <p className="banner__desc">
            You'll also need a little <strong>Base Sepolia ETH</strong> for gas (the deposit
            and later the withdrawal claim are on-chain). Grab some from a faucet such as{" "}
            <a href="https://www.alchemy.com/faucets/base-sepolia" target="_blank" rel="noreferrer">
              alchemy.com/faucets/base-sepolia
            </a>.
          </p>
        </div>
      )}
    </div>
  );
}
