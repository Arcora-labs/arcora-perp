import { FINALITY_COPY, type Finality } from "../domain/types";

const ORDER: Finality[] = ["ACCEPTED", "MATCHED", "SETTLED"];

export function FinalityBadge({ finality }: { finality: Finality }) {
  return (
    <span className={`badge badge--${finality.toLowerCase()}`} title={FINALITY_COPY[finality].hint}>
      {FINALITY_COPY[finality].label}
    </span>
  );
}

/// A legend that makes MATCHED ≠ SETTLED unmistakable (§3). The design will
/// restyle this; the three-state semantics must survive any restyle.
export function FinalityLegend() {
  return (
    <div className="card finality-legend">
      <h3 className="card__title">Finality</h3>
      <ol className="finality-legend__steps">
        {ORDER.map((f, i) => (
          <li key={f} className="finality-legend__step">
            <span className="finality-legend__index">{i + 1}</span>
            <FinalityBadge finality={f} />
            <p className="finality-legend__hint">{FINALITY_COPY[f].hint}</p>
          </li>
        ))}
      </ol>
      <p className="finality-legend__warn">
        Binding finality is <strong>SETTLED</strong>. “Matched” is a good-faith
        preconfirmation — not financial certainty, and not withdrawable.
      </p>
    </div>
  );
}

/// A compact horizontal progress for a single order's finality.
export function FinalityProgress({ finality }: { finality: Finality }) {
  const reached = ORDER.indexOf(finality);
  return (
    <div className="finality-progress" aria-label={`finality: ${finality}`}>
      {ORDER.map((f, i) => (
        <span
          key={f}
          className={`finality-progress__dot ${i <= reached ? "is-on" : ""} dot--${f.toLowerCase()}`}
          title={f}
        />
      ))}
    </div>
  );
}
