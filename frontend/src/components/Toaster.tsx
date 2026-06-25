import { useEffect, useState } from "react";
import { useStore } from "../store";
import type { OrderEvent } from "../api/client";

interface Toast extends OrderEvent {
  id: number;
}

let nextId = 0;

/// Transient notifications for order lifecycle events (ACCEPTED → MATCHED →
/// SETTLED / CANCELLED). The colour tracks the finality so MATCHED reads as
/// provisional and SETTLED as final.
export function Toaster() {
  const { client } = useStore();
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    return client.onOrderEvent((e: OrderEvent) => {
      const id = nextId++;
      setToasts((ts) => [...ts, { ...e, id }]);
      setTimeout(() => setToasts((ts) => ts.filter((t) => t.id !== id)), 4200);
    });
  }, [client]);

  return (
    <div className="toaster" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast--${t.kind.toLowerCase()}`} role="status">
          <span className="toast__kind">{t.kind}</span>
          <span className="toast__msg">{t.message}</span>
        </div>
      ))}
    </div>
  );
}
