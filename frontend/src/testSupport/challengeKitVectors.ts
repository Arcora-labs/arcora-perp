// The challenge-kit vectors shared with scripts/challenge/test_challenge_kit.py,
// read off disk at test time: a compile-time import would make the production
// `tsc -b` depend on a file outside frontend/, and Vite rewrites
// `new URL(literal, import.meta.url)` into a dev-server URL.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Receipt } from "../domain/types";
import type { ChallengeKit } from "../domain/challengeKit";

export interface ChallengeKitVectors {
  authTag: string;
  enclaveSigner: string;
  digestVectors: Array<{
    name: string; chainId: number; settlement: string; orderHash: string; seqNo: number;
    recvTimeMs: number; batchIdHint: number; beneficiary: string; digest: string;
  }>;
  acceptReceipt: Receipt & { windowId: number };
  kit: ChallengeKit;
}

const repoRoot = fileURLToPath(import.meta.url).replace(/frontend[\\/]src[\\/]testSupport[\\/][^\\/]+$/, "");

export const CHALLENGE_KIT_VECTORS: ChallengeKitVectors = JSON.parse(
  readFileSync(`${repoRoot}scripts/challenge/fixtures/challenge-kit-vectors.json`, "utf8"),
);
