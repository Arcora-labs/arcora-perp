// Minimal ambient declarations for the few Node built-ins used by Node-side test
// helpers (e.g. reading a source file off disk to assert on it). The frontend app
// ships no Node deps, so we don't pull in all of @types/node — just what tests touch.
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
}
declare module "node:url" {
  export function fileURLToPath(url: string | URL): string;
}
