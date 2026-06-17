import { Injectable } from "@nestjs/common";
import { Capability } from "./capability.interface.js";

/**
 * Microkernel capability registry (arch #67).
 *
 * Each optional module self-registers at construction time. The registry is a
 * global singleton (CapabilityModule is @Global) so every module can inject it
 * without re-importing CapabilityModule. Query it for health checks, admin panels,
 * or startup-time conditional-load decisions.
 *
 * Registering the same name twice overwrites — the last constructor to run wins,
 * which matches NestJS module load order and lets tests re-register freely.
 */
@Injectable()
export class CapabilityRegistry {
  private readonly capabilities = new Map<string, Capability>();

  register(cap: Capability): void {
    this.capabilities.set(cap.name, cap);
  }

  list(): Capability[] {
    return [...this.capabilities.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  isEnabled(name: string): boolean {
    return this.capabilities.get(name)?.enabled ?? false;
  }
}
