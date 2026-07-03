import { useState } from "react";

/// Honest public-testnet disclosure: what is REAL and what is a STAND-IN, plus how
/// to get test USDC. Dismissible (persisted), but shown on first visit so no one
/// mistakes the testnet for a mainnet with real funds. Kept deliberately blunt.
const MOCK_USDC = "0xF9bd3AD70bA831b92e9F07D08121c6A750B3612a";
const VAULT = "0x3A3939E1C5De10D41942a85D4A14ac8160779bF4";
const DISMISS_KEY = "dp_testnet_notice_dismissed_v1";

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
            in a real Azure TDX enclave (attested), but fund-safety proofs are{" "}
            <strong>mocked</strong> (MockZkVerifier) and orders reach the gateway over TLS,
            not yet encrypted to the enclave. Don't send anything you can't lose.
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
        </div>
      )}
    </div>
  );
}
