import { useEffect, useId, useRef, type ReactNode } from "react";

/** Native modal supplies focus trapping, Escape and inert background. */
export function Dialog({ title, children, onClose, wide = false, busy = false }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean; busy?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  const headingId = useId();
  useEffect(() => {
    const dialog = ref.current;
    const previous = document.activeElement as HTMLElement | null;
    if (dialog && !dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    return () => { dialog?.close?.(); previous?.focus(); };
  }, []);
  return <dialog ref={ref} className={`warm-dialog ${wide ? "warm-dialog--wide" : ""}`} aria-labelledby={headingId}
    onCancel={e => { e.preventDefault(); if (!busy) onClose(); }}>
    <div className="warm-dialog__head"><h2 id={headingId}>{title}</h2><button type="button" className="dialog-close" aria-label="Close dialog" onClick={onClose} disabled={busy}>×</button></div>
    {children}
  </dialog>;
}
