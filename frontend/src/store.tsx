import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { ClientState, DarkPerpClient } from "./api/client";
import { MockDarkPerpClient } from "./api/mockClient";

interface Store {
  client: DarkPerpClient;
  state: ClientState;
  /// Transient UI signal: a price the order book wants the ticket to adopt as its
  /// limit price (click-to-price). The ticket consumes and clears it. `null` = none.
  prefillPrice: bigint | null;
  setPrefillPrice: (p: bigint | null) => void;
}

const Ctx = createContext<Store | null>(null);

export function StoreProvider({ children }: { children: ReactNode }) {
  // swap MockDarkPerpClient for the real client later; nothing else changes.
  const client = useMemo(() => new MockDarkPerpClient(), []);
  const [state, setState] = useState<ClientState>(() => client.getState());
  const [prefillPrice, setPrefillPrice] = useState<bigint | null>(null);

  useEffect(() => client.subscribe(setState), [client]);

  return (
    <Ctx.Provider value={{ client, state, prefillPrice, setPrefillPrice }}>{children}</Ctx.Provider>
  );
}

export function useStore(): Store {
  const s = useContext(Ctx);
  if (!s) throw new Error("useStore must be used within StoreProvider");
  return s;
}
