import { CapabilityRegistry } from "./capability-registry.service.js";

describe("CapabilityRegistry", () => {
  let registry: CapabilityRegistry;

  beforeEach(() => {
    registry = new CapabilityRegistry();
  });

  it("starts empty", () => {
    expect(registry.list()).toHaveLength(0);
  });

  it("registers and lists a capability", () => {
    registry.register({
      name: "policy",
      class: "infra-core",
      description: "DVT policy gate",
      enabled: true,
    });
    const list = registry.list();
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe("policy");
    expect(list[0].enabled).toBe(true);
  });

  it("isEnabled returns true for an enabled capability", () => {
    registry.register({
      name: "notify",
      class: "infra-app",
      description: "notifications",
      enabled: true,
    });
    expect(registry.isEnabled("notify")).toBe(true);
  });

  it("isEnabled returns false for a disabled capability", () => {
    registry.register({
      name: "confirm",
      class: "infra-app",
      description: "OOB confirm",
      enabled: false,
    });
    expect(registry.isEnabled("confirm")).toBe(false);
  });

  it("isEnabled returns false for an unregistered name", () => {
    expect(registry.isEnabled("nonexistent")).toBe(false);
  });

  it("re-registering the same name overwrites", () => {
    registry.register({ name: "policy", class: "infra-core", description: "old", enabled: false });
    registry.register({ name: "policy", class: "infra-core", description: "new", enabled: true });
    expect(registry.list()).toHaveLength(1);
    expect(registry.isEnabled("policy")).toBe(true);
    expect(registry.list()[0].description).toBe("new");
  });

  it("list returns capabilities sorted by name", () => {
    registry.register({ name: "notify", class: "infra-app", description: "", enabled: false });
    registry.register({ name: "confirm", class: "infra-app", description: "", enabled: false });
    registry.register({ name: "policy", class: "infra-core", description: "", enabled: true });
    const names = registry.list().map(c => c.name);
    expect(names).toEqual(["confirm", "notify", "policy"]);
  });
});
