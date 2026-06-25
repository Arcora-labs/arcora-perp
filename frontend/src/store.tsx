import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { ClientState, DarkPerpClient } from "./api/client";
import { MockDarkPerpClient } from "./api/mockClient";

interface Store {
  client: DarkPerpClient;
  state: ClientState;
}

const Ctx = createContext<Store | null>(null);

export function StoreProvider({ children }: { children: ReactNode }) {
  // swap MockDarkPerpClient for the real client later; nothing else changes.
  const client = useMemo(() => new MockDarkPerpClient(), []);
  const [state, setState] = useState<ClientState>(() => client.getState());

  useEffect(() => client.subscribe(setState), [client]);

  return <Ctx.Provider value={{ client, state }}>{children}</Ctx.Provider>;
}

export function useStore(): Store {
  const s = useContext(Ctx);
  if (!s) throw new Error("useStore must be used within StoreProvider");
  return s;
}
