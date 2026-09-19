#!/usr/bin/env python3
"""Pinned S1 patch and offline verification. Never publishes or contacts a chain."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tempfile

BASE = "f997f8b96279bd06ec1808f6b9cb2a6aeb25cc5e"
BRANCH = "fix/s1-rotation-fence-2026-09-19"
ROOT = Path.cwd()
HERE = Path(__file__).resolve().parent
OUT = ROOT / "target/s1-followup-evidence"
OUT.mkdir(parents=True, exist_ok=True)
records = []

def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()

def run(name, command, cwd=ROOT, expected=0):
    with (OUT / f"{name}.log").open("w") as log:
        result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                                timeout=1100, env={**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target")})
    text = (OUT / f"{name}.log").read_text()
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    summaries = re.findall(r"test result: .*", clean)
    records.append({"name":name, "command":command, "exit_code":result.returncode,
                    "expected_exit":expected, "summaries":summaries})
    (OUT / "commands.json").write_text(json.dumps(records, indent=2)+"\n")
    print(name, "exit", result.returncode, *summaries, sep="\n", flush=True)
    if result.returncode != expected:
        print(clean[-12000:], flush=True)
        raise SystemExit(f"{name} failed; no candidate will be published")
    return clean

def replace(text, old, new, count=1):
    assert text.count(old) == count, (old[:80], text.count(old), count)
    return text.replace(old, new)

assert os.environ.get("GITHUB_REPOSITORY") == "Kubudak90/dark-perp"
assert os.environ.get("GITHUB_REF") == f"refs/heads/{BRANCH}"
assert git("rev-parse", "HEAD") == os.environ["GITHUB_SHA"]
assert not git("status", "--porcelain")
for path, expected in {
    "crates/gateway/src/main.rs": "8fd7d659e6703e6e06cb15df9247cbd9f53107da",
    "crates/gateway/src/account_recovery.rs": "32df7f44c10d5ac68f60cd658ef1981a87aed4cd",
    "crates/gateway/src/s1_recovery_ws_tests.rs": "61b54f10035e3455568c27bc1917c23f39441121",
}.items():
    assert git("hash-object", path) == expected, f"source moved: {path}"
    assert git("rev-parse", f"{BASE}:{path}") == expected

# Known-bad source in a disposable detached worktree; no branch reset.
baseline = Path(tempfile.mkdtemp(prefix="s1-baseline-")) / "repo"
subprocess.run(["git","worktree","add","--detach",str(baseline),BASE], check=True)
repros = (HERE / "repros.rs").read_text()
p = baseline / "crates/gateway/src/s1_recovery_ws_tests.rs"
p.write_text(p.read_text()+repros)
text = run("baseline-reproductions", ["cargo","test","--locked","-p","gateway","s1f_","--","--test-threads=1"], baseline, 101)
assert "test result: FAILED. 0 passed; 2 failed;" in text, "not two runtime reproductions"
for name in ["s1f_concurrent_rotation_is_serialized_through_ack", "s1f_idle_authenticated_socket_closes_without_traffic"]:
    assert f"{name} ... FAILED" in text, name

p = ROOT / "crates/gateway/src/main.rs"
s = p.read_text()
s = replace(s, "mod account_recovery;", "mod account_recovery;\nmod credential_session;")
s = replace(s, "    recovery_last: Option<(u64, [u8; 32])>,", "    recovery_last: Option<(u64, [u8; 32])>,\n    /// Runtime-only synchronization; no positional or trailer schema change.\n    #[serde(skip)]\n    credential_control: Arc<credential_session::Control>,")
s = replace(s, "                recovery_last: None,", "                recovery_last: None,\n                credential_control: Arc::default(),")
old = "\n            recovery_last: None,\n"
s = replace(s, old, old + "            credential_control: Arc::default(),\n")
start = s.index("    /// Owner (hex) + recovery nonce at auth time,")
end = s.index("    fn v1_account(", start)
s = s[:start]+s[end:]
start = s.index("async fn post_v1_recovery(")
end = s.index("\n/// Bind the external EOA", start)
s = s[:start]+'''async fn post_v1_recovery(
    State(app): State<Shared>,
    Json(req): Json<RecoveryReq>,
) -> impl IntoResponse {
    account_recovery::post(app, req).await
}
'''+s[end:]
start = s.index("async fn ws_v1_loop(")
end = s.index("\nasync fn get_state(", start)
s = s[:start]+'''async fn ws_v1_loop(socket: WebSocket, app: Shared) {
    credential_session::serve(socket, app).await;
}
'''+s[end:]
p.write_text(s)

p = ROOT / "crates/gateway/src/account_recovery.rs"
s = p.read_text()
old = '''    pub(super) fn recover_account(
        &mut self,
        owner: PubKey,
        nonce: u64,
        sig: &[u8; 65],
    ) -> Result<[u8; 32], String> {'''
new = '''    pub(super) fn recovery_control(&self, owner: &PubKey) -> Option<Arc<credential_session::Control>> {
        self.accounts.values().find(|a| &a.wallet.owner == owner)
            .map(|a| a.credential_control.clone())
    }

    // Synchronous unit-test callers must also respect the send fence. HTTP
    // acquires it asynchronously without holding Gw, using the method below.
    #[cfg(test)]
    pub(super) fn recover_account(
        &mut self, owner: PubKey, nonce: u64, sig: &[u8; 65],
    ) -> Result<[u8; 32], String> {
        let control = self.recovery_control(&owner).ok_or("Unknown account owner.")?;
        let fence = control.fence.clone().try_write_owned()
            .map_err(|_| "credential send/recovery in progress; retry")?;
        self.recover_account_fenced(owner, nonce, sig, &control, &fence)
    }

    fn recover_account_fenced(
        &mut self,
        owner: PubKey,
        nonce: u64,
        sig: &[u8; 65],
        control: &Arc<credential_session::Control>,
        _fence: &tokio::sync::OwnedRwLockWriteGuard<()>,
    ) -> Result<[u8; 32], String> {'''
s = replace(s, old, new)
s = replace(s, '        let (expected, current) = {', '''        if !Arc::ptr_eq(&self.accounts[&old].credential_control, control) {
            return Err("account recovery fence changed; retry".into());
        }
        let (expected, current) = {''')
s = replace(s, '                    if last_nonce == nonce {', '                    if last_nonce == nonce && last_key == old {')
s = replace(s, '        a.recovery_last = Some((nonce, new_key));', '''        a.recovery_last = Some((nonce, new_key));
        // Notify existing subscribers even after restore creates fresh controls.
        a.credential_control.changed.send_replace(next);''')
s = replace(s, '\n#[cfg(test)]\n#[path = "account_recovery_tests.rs"]', '\n'+(HERE / "http_recovery.rs").read_text()+'\n#[cfg(test)]\n#[path = "account_recovery_tests.rs"]')
p.write_text(s)
(ROOT / "crates/gateway/src/credential_session.rs").write_text((HERE / "credential_session.rs").read_text())
p = ROOT / "crates/gateway/src/s1_recovery_ws_tests.rs"
p.write_text(p.read_text()+repros+(HERE / "fence_tests.rs").read_text())

run("format", ["cargo","fmt","--all"])
run("focused", ["cargo","test","--locked","-p","gateway","s1f_","--","--test-threads=1"])
run("gateway", ["cargo","test","--locked","-p","gateway"])
run("clippy", ["cargo","clippy","--workspace","--all-targets","--locked","--","-D","warnings"])
run("format-check", ["cargo","fmt","--all","--check"])
run("diff-check", ["git","diff","--check"])

source_paths = ["crates/gateway/src/"+n for n in ["main.rs","account_recovery.rs","credential_session.rs","s1_recovery_ws_tests.rs"]]
evidence = {
    "base_sha": BASE, "bootstrap_sha": os.environ["GITHUB_SHA"],
    "workflow_run": os.environ["GITHUB_RUN_ID"], "commands": records,
    "source_sha256": {p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source_paths},
    "baseline": "Two failing runtime assertions; unchanged tests pass on fixed sources",
    "limitations": ["Final source commit CI must be independently checked after publishing", "Only controlled ACKs except one actual encrypted snapshot write/fsync/restore test", "No physical process kill or power-loss drill", "Send-stall seam uses a controlled future at production helper; TCP backpressure stress not performed", "No real SP1 ELF/vkey/proof, no deployment/live-chain operations", "Full S1 matrix and codebase audit not closed"],
}
(ROOT / "docs/audits/2026-09-19-s1-fence-evidence.json").write_text(json.dumps(evidence, indent=2)+"\n")
report = '''# S1 devamı: recovery yanıtı ve WebSocket rotation sınırı

Taban: `f997f8b96279bd06ec1808f6b9cb2a6aeb25cc5e` (PR #14 birleşmiş).
Kaynak hash'leri, komut/exit kodları ve doğrulama run'ı
`2026-09-19-s1-fence-evidence.json` içindedir. Bu run final-head CI değildir.

## Bulgular ve düzeltmeler

- PR #14 HTTP handler'ı ACK beklerken superseded olan key'i confirmed diye
  döndürebiliyordu. Hesap başına sabit exclusive fence; mutation, ACK ve yanıt
  oluşturmayı birlikte sıralar. Son kontrolde key, owner, nonce, fence kimliği
  ve güncel authorizer yeniden doğrulanır. Conflict yanıtında key bulunmaz.
- WS generation kontrolü ile async gönderim arasında yarış vardı. AuthOk ve
  authenticated gönderim aynı hesap fence'inin read lease'ini transport yazımı
  boyunca tutar. Genel Gw kilidi ağ bekleyişinde tutulmaz.
- Boşta oturum artık trafiğe ihtiyaç duymadan watch bildirimiyle iptal edilir.
  Gönderim ve lease bekleyişi iki saniye ile sınırlıdır. Başarısızlıkta socket
  düşürülür; fence dışında tekrar flush yapılmaz.
- Fence serde-skip'tir, key rotation sırasında aynı hesapla taşınır ve restore'da
  yeniden oluşur. Snapshot formatı ve deposit referansları değiştirilmedi.
- Recovery yanıtları Cache-Control: no-store taşır.

## Kanıtın sınırı

İki değişmeden kullanılan gerçek route/socket testi PR #14 tabanında assertion
ile başarısız, yamalı kaynakta başarılıdır. Diğer testler devam eden gönderim,
gönderim timeout'u, kuyruktaki özel event, dolu/kapalı snapshot kuyruğu, kesin
noktada request iptali, gerçek şifreli snapshot write/fsync/restore ve ACK sonrası
authorizer kontrolünü kapsar. Send-stall future ve authorizer değişimi kontrollü
fixture'dır; tam TCP backpressure veya rebind E2E kanıtı değildir.

ACK, seri snapshot writer'ın capture/write işleminden sonra gelir. HTTP fence'i
aynı hesabın sonraki rotation'ını yanıt oluşturulana kadar bekletir. Daha sonra
bilinçli yapılan rotation ağdaki yanıtı geçersizleştirebilir; TCP'ye daha önce
verilen byte'lar geri alınamaz. Garanti sunucu mutation/gönderim sıralamasıdır,
istemcinin ağdan teslim alma anıyla atomiklik değildir.

PR #14 raporundaki eski davranış için 'kalıcı kilitlenme' ifadesi fazla güçlüydü:
wallet authorizer yeni public challenge okuyup tekrar yetki verebilirdi.
Idempotency kaydı halen process-local'dir. Restart sonrası gerçek restore nonce'u
okunmalıdır, körlemesine nonce+1 kullanılmaz. Nonce tükenmesi fail-closed kalır.

## Açık kalanlar

Exact final-head CI ve kalan yetki/rebind/transport/failure matrisi doğrulanana
kadar S1 kapanmadı. Fiziksel crash drill, gerçek SP1, deployment ve canlı zincir
işlemi yapılmadı. S2 ancak S1 sonrasında ele alınır.
'''
(ROOT / "docs/audits/2026-09-19-s1-fence-followup.md").write_text(report)
for name in ["ROADMAP.md", "AUDIT_HANDOFF.md"]:
    p = ROOT / "docs" / name
    title, rest = p.read_text().split("\n", 1)
    note = '''

> **S1 devamı (19 Eylül 2026):** PR #14 `f997f8b` ile birleşti, ancak S1'i
> kapatmadı. HTTP ACK/rotation ve WS check/send/idle eksikleri bağımsız testlerle
> yeniden üretildi. [Devam raporu](audits/2026-09-19-s1-fence-followup.md) ve
> [kaynak-bağlı kanıt](audits/2026-09-19-s1-fence-evidence.json) esas alınmalıdır.
> Final-head CI ve kalan S1 matrisi henüz kapanış kanıtı değildir; S2'ye geçmeyin.
'''
    if name == "ROADMAP.md":
        start = rest.index("### S1.")
        end = rest.index("### S2.", start)
        section = rest[start:end].replace("- [x]", "- [ ]")
        section = section.replace("**Bitiş kanıtı:**", "**PR #14 tarihsel kaydı, S1 kapanış kanıtı değildir:**")
        rest = rest[:start]+section+rest[end:]
    p.write_text(title+note+rest)
# Remove temporary patch transport from the candidate; existing CI is unchanged.
for name in ["apply_and_verify.py", "credential_session.rs", "http_recovery.rs", "repros.rs", "fence_tests.rs"]:
    (HERE/name).unlink()
(ROOT / ".github/workflows/s1-followup-patch.yml").unlink()
subprocess.run(["git","add","-A"], check=True)
allowed = set(source_paths + ["docs/ROADMAP.md","docs/AUDIT_HANDOFF.md","docs/audits/2026-09-19-s1-fence-followup.md","docs/audits/2026-09-19-s1-fence-evidence.json", ".github/workflows/s1-followup-patch.yml"] + ["scripts/audit/s1-followup/"+n for n in ["apply_and_verify.py","credential_session.rs","http_recovery.rs","repros.rs","fence_tests.rs"]])
changed = set(git("diff","--cached","--name-only").splitlines())
assert changed <= allowed, changed-allowed
subprocess.run(["git","diff","--cached","--check"], check=True)
(OUT / "candidate.patch").write_bytes(subprocess.check_output(["git","diff","--cached","--binary"]))
(OUT / "candidate.json").write_text(json.dumps({"base_sha":BASE,"input_sha":os.environ["GITHUB_SHA"],"branch":BRANCH,"tree":git("write-tree"),"allowed_paths":sorted(allowed),"source_sha256":evidence["source_sha256"]},indent=2)+"\n")
print("CANDIDATE_READY", git("write-tree"), flush=True)
