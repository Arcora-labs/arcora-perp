import { useState } from "react";
import { MOCK_USDC, COLLATERAL_VAULT as VAULT } from "../api/wallet";

// Configuration is not evidence of a running chain, attested enclave or proof.
// v6 resurfaces the custody, price and exit trust boundaries once.
const DISMISS_KEY = "dp_testnet_notice_dismissed_v6";

export function TestnetNotice() {
  const [open, setOpen] = useState(() => {
    try { return typeof localStorage === "undefined" || localStorage.getItem(DISMISS_KEY) !== "1"; }
    catch { return true; } // denied storage must not prevent account recovery
  });
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
          <strong className="banner__title">Test environment — test assets only.</strong>{" "}
          <span className="banner__desc">
            Order acceptance does not mean on-chain settlement. Check <strong>Health</strong>{" "}
            and <strong>Explorer</strong> for deployment and transaction status.
            {" "}This alpha is custodial: the gateway holds spending keys and signs prices.
            The prover operator can access private trade data. Only published withdrawal claims
            can be claimed independently; new exits depend on the operator and, during final wind-down, governance.
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
            For the configured Base Sepolia deployment, mint test MockUSDC (6 decimals)
            to your wallet. This Foundry <code>cast</code> example mints 1,000 test USDC:
          </p>
          <pre className="banner__code">
            {`# 1. mint 1,000 test USDC to yourself\n`}
            {`cast send ${MOCK_USDC} \\\n`}
            {`  "mint(address,uint256)" <YOUR_ADDR> 1000000000 \\\n`}
            {`  --rpc-url https://sepolia.base.org --private-key <YOUR_KEY>\n\n`}
            {`# 2. approve the vault\n`}
            {`cast send ${MOCK_USDC} "approve(address,uint256)" ${VAULT} 1000000000 \\\n`}
            {`  --rpc-url https://sepolia.base.org --private-key <YOUR_KEY>`}
          </pre>
          <p className="banner__desc">
            The deposit itself is <strong>gateway-authorized</strong> (SEC-019): the vault
            requires an <code>ownerCommit</code> + signature issued by{" "}
            <code>POST /v1/accounts/deposit/authorize</code>, so a bare{" "}
            <code>cast send</code> can no longer enter the vault. Use the in-app flow
            (<strong>Connect wallet → Deposit</strong>) — it authorizes and deposits for you.
          </p>
          <p className="banner__desc">
            Keep the original deposit transaction hash. The finalized ingester credits
            the authorized deposit to the same trading account when finalized. If credit
            is still pending, check that transaction again — do not send another deposit.
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
