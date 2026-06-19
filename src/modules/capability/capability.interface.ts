/** 'infra-core' = security-critical kernel (policy gate, key custody).
 *  'infra-app'  = application-level capability; can be absent without affecting
 *                 the DVT signing correctness (notifications, confirmation UI). */
export type CapabilityClass = "infra-core" | "infra-app";

export interface Capability {
  readonly name: string;
  readonly class: CapabilityClass;
  readonly description: string;
  readonly enabled: boolean;
}
