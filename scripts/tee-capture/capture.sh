#!/usr/bin/env bash
# Capture a live Azure TDX + vTPM attestation bundle for the dark-perp gateway.
# Run ON the confidential VM (needs tpm2-tools, cargo, sudo). The output dir is
# what the gateway's ATTESTATION_DIR should point at — six artifacts:
# quote.bin collateral.json hcl_report.bin ak_quote_msg.bin ak_quote_sig.bin pcrs.txt
set -euo pipefail
OUT="${1:-$HOME/attestation-live}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"

# 1. HCL report — vTPM NV index 0x01400001 (see vtpm.rs::runtime_data).
sudo tpm2_nvread 0x01400001 > "$OUT/hcl_report.bin"

# 2+3. TD report → IMDS TD quote; fresh PCS collateral; offline verify sanity.
cargo run --release --quiet --manifest-path "$HERE/Cargo.toml" -- "$OUT"

# 4. AK quote (the Azure HCL AK, persistent 0x81000003) over the measured-boot
#    PCR set 0..16 — the verifier recomputes pcrDigest over exactly this range.
sudo tpm2_quote -c 0x81000003 \
  -l "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16" -g sha256 \
  -m "$OUT/ak_quote_msg.bin" -s "$OUT/ak_quote_sig.bin" -o "$OUT/ak_pcrs.out" >/dev/null

# 5. The PCR values themselves ("N : 0x…" lines, parsed by the gateway).
sudo tpm2_pcrread sha256 > "$OUT/pcrs.txt"

echo "captured → $OUT"
ls -l "$OUT"
