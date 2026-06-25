import { useEffect, useRef, useState } from "react";

/// Returns a transient flash class ("flash-up"/"flash-down") whenever `value`
/// changes direction — the classic green/red tick flash on live prices. Clears
/// itself after the animation so it re-fires on the next change.
export function useFlash(value: bigint): "" | "flash-up" | "flash-down" {
  const prev = useRef(value);
  const [cls, setCls] = useState<"" | "flash-up" | "flash-down">("");
  useEffect(() => {
    if (value > prev.current) setCls("flash-up");
    else if (value < prev.current) setCls("flash-down");
    prev.current = value;
    const t = setTimeout(() => setCls(""), 500);
    return () => clearTimeout(t);
  }, [value]);
  return cls;
}
