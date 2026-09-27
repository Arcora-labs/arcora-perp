import { vi } from "vitest";
/** Deterministic origin-wide lock mock shared by clients in each unit test. */
export function installTestLocks(): void {
  const tails = new Map<string, Promise<void>>();
  const request = async <T>(name: string, optionsOrCallback: LockOptions | LockGrantedCallback<T>, callback?: LockGrantedCallback<T>): Promise<T> => {
    const options = typeof optionsOrCallback === "function" ? {} : optionsOrCallback;
    const fn = typeof optionsOrCallback === "function" ? optionsOrCallback : callback!;
    const before = tails.get(name);
    if (before && options.ifAvailable) return await fn(null);
    let release!: () => void;
    const done = new Promise<void>(r => { release = r; });
    tails.set(name, done);
    try {
      if (before) await before;
      return await fn({ name, mode: "exclusive" } as Lock);
    } finally {
      release();
      if (tails.get(name) === done) tails.delete(name);
    }
  };
  const copy = Object.create(navigator) as Navigator;
  Object.defineProperty(copy, "locks", { configurable: true, value: { request } });
  vi.stubGlobal("navigator", copy);
}
