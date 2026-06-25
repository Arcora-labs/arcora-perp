import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

/// Catches render/runtime errors anywhere in the subtree so a single component fault
/// shows a graceful, contained fallback instead of white-screening the whole app.
/// Styled entirely with design tokens, so it survives any reskin. The copy is
/// careful: a UI fault is NOT a protocol action — funds/orders are unaffected.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // surface for debugging; a production app would also report to telemetry
    console.error("UI error boundary caught:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="errorboundary" role="alert">
          <h2 className="errorboundary__title">Something went wrong</h2>
          <p className="errorboundary__msg">
            A display error was caught and contained. Your funds and orders are
            unaffected — this is a UI fault, not a protocol action.
          </p>
          <pre className="errorboundary__detail mono">{this.state.error.message}</pre>
          <button className="btn btn--ghost" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
