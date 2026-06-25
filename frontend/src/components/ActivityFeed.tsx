import { useEffect, useRef, useState } from "react";
import { useStore } from "../store";
import type { OrderEvent } from "../api/client";

interface Entry extends OrderEvent {
  id: number;
}

const CAP = 24; // events retained

/// A persistent, chronological log of order-lifecycle events. The Toaster shows
/// each event transiently; this keeps the history (newest first) so a trader can
/// see the ACCEPTED → MATCHED → SETTLED progression after the toast is gone. The
/// colour tracks finality, so MATCHED still reads as provisional vs SETTLED final.
export function ActivityFeed() {
  const { client } = useStore();
  const [entries, setEntries] = useState<Entry[]>([]);
  const idRef = useRef(0);

  useEffect(() => {
    return client.onOrderEvent((e: OrderEvent) => {
      const id = idRef.current++;
      setEntries((xs) => [{ ...e, id }, ...xs].slice(0, CAP));
    });
  }, [client]);

  return (
    <div className="card">
      <h3 className="card__title">Activity</h3>
      {entries.length === 0 ? (
        <p className="muted">No activity yet. Place an order to see its lifecycle stream.</p>
      ) : (
        <ul className="activity" aria-label="Order lifecycle events">
          {entries.map((e) => (
            <li key={e.id} className="activity__row">
              <span className={`activity__kind badge badge--${e.kind.toLowerCase()}`}>{e.kind}</span>
              <span className="activity__msg">{e.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
