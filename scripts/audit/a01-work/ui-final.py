from pathlib import Path
import sys
r=Path(sys.argv[1])
p=r/'frontend/src/api/realClient.ts';s=p.read_text()
s=s.replace('  settlementHealth?: unknown;','  depositIngestion?: unknown;\n  settlementHealth?: unknown;')
s=s.replace('  private ownRefreshAgain = false;', '''  private ownRefreshAgain = false;
  // Public progress is only a refresh hint; balances come from authenticated reads.
  private depositRefreshHint: string | null = null;''')
s=s.replace('      this.ws = new WebSocket(this.wsUrl);', '      this.depositRefreshHint = null;\n      this.ws = new WebSocket(this.wsUrl);')
s=s.replace('            this.setState(parseState(msg.state));', '''            this.setState(parseState(msg.state));
            this.refreshAfterDeposit(msg.state.depositIngestion);''')
pos=s.index('  private scheduleReconnect() {')
s=s[:pos]+'''  private refreshAfterDeposit(value: unknown): void {
    if (!value || typeof value !== "object" || this.disposed || !this.hasAccount()) return;
    const d = value as Record<string, unknown>;
    if (d.state !== "ready" || typeof d.consumedCount !== "number" ||
        !Number.isSafeInteger(d.consumedCount) || d.consumedCount < 0 ||
        typeof d.consumedTip !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(d.consumedTip)) return;
    const hint = `${d.consumedCount}:${d.consumedTip}`;
    if (hint === this.depositRefreshHint) return;
    this.depositRefreshHint = hint;
    void this.refreshOwnState();
  }

'''+s[pos:];p.write_text(s)
p=r/'frontend/src/api/realClient.test.ts';s=p.read_text();s+='''

describe("A01 automatic own-balance refresh", () => {
  it("refreshes owned balance without confirm and deduplicates progress hints", async () => {
    const client = await bootstrapClient();
    const frame = (state: string, count: number, tip: string) => {
      lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: {
        ...demoState, depositIngestion: { state, consumedCount: count, consumedTip: tip },
      } }) });
    };
    const tip = "0x" + "12".repeat(32);
    meFields = { ...defaultMeFields(), settledBalance: "555666777888" };
    frame("paused", 1, tip);
    await client.ownStateSettled();
    expect(client.getState().account.settledBalance).toBe(BigInt(V1_BALANCE));
    frame("ready", 1, tip);
    await client.ownStateSettled();
    expect(client.getState().account.settledBalance).toBe(555_666_777_888n);
    const reads = calls.filter((c) => c.path === "/v1/accounts/me").length;
    frame("ready", 1, tip);
    frame("ready", 2, "malformed");
    await client.ownStateSettled();
    expect(calls.filter((c) => c.path === "/v1/accounts/me").length).toBe(reads);
    expect(calls.some((c) => c.path === "/v1/accounts/deposit/onchain")).toBe(false);
    meFields = { ...defaultMeFields(), settledBalance: "666777888999" };
    frame("ready", 2, "0x" + "23".repeat(32));
    await client.ownStateSettled();
    expect(client.getState().account.settledBalance).toBe(666_777_888_999n);
    client.dispose();
  });
});
'''
# Keep independent A01 tests away from the location where PR4 appends its tests.
a=s.index('describe("A01 autonomous deposit receipts"');tail=s[a:];s=s[:a].rstrip()+'\n'
i=s.index('// Audit remediation: proof material');s=s[:i]+tail+'\n\n'+s[i:];p.write_text(s)
p=r/'docs/API.md';s=p.read_text().replace('`deposit_ingestion` object exposes readiness, dirty state, count/tip, anchor, halt,', '`depositIngestion` object exposes readiness (paused while durability is dirty), count/tip, anchor, halt,');p.write_text(s)
p=r/'crates/gateway/src/main.rs';s=p.read_text().replace('/// Credit a real on-chain USDC deposit: verify the `vault.deposit` tx via the L1\n/// bridge, enforce the `from`==bound-address binding + tx dedup, and fund the engine.','/// Optional owned receipt from the shared finalized ingester. This endpoint\n/// cannot choose routing, bypass L1 ordering, or consume a deposit a second time.');p.write_text(s)
