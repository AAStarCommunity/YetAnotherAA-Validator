// Error boundary for every sink: see lib/safe-error.mjs for the rule. SinkError is a SafeError,
// so a sink's own refusals pass through publishRecord as written and nothing else does.
import { SafeError, safeCode, guarded } from "../lib/safe-error.mjs";

export class SinkError extends SafeError {
  constructor(message, code) {
    super(message, code);
    this.name = "SinkError";
  }
}

export { safeCode, guarded };
