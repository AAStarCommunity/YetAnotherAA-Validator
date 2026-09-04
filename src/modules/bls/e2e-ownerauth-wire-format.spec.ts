import { readFileSync, readdirSync } from "fs";
import { resolve, join } from "path";

/**
 * The ownerAuth WIRE FORMAT, guarded on the side that produces it.
 *
 * `POST /signature/sign` forwards `ownerAuth` verbatim to the account's
 * `isValidOwnerAuth(bytes32,bytes)` (see `blockchain.service.ts`, OWNER_AUTH_FN / OWNER_AUTH_MAGIC).
 * The DVT node deliberately does NOT inspect it — that is the whole point of delegating the decision
 * to the account. So nothing in `src/` can be wrong about the encoding, and nothing in `src/` can
 * notice when a CALLER is.
 *
 * The encoding is `1-byte tag ‖ payload`, tag `0x01` = owner ECDSA (k1) over `personal_sign(userOpHash)`,
 * and the account requires EXACTLY 66 bytes (docs/INTERFACES.md §1). Measured on Sepolia against
 * e2e_account `0x92EA8b02D34A4D5d10f0Db9Ea894e8bC72e292e8`, with the real owner key
 * (`owner()` = `0xb5600060…` = `PRIVATE_KEY_SUPPLIER`), one hash, two encodings:
 *
 *     0x01 ‖ sig  (66 bytes)  ->  0xa0cf00cf   accepted
 *     bare sig    (65 bytes)  ->  0xffffffff   rejected
 *
 * Both cells are real calls; the accepting one is what makes the rejecting one informative, rather
 * than "this account rejects everything".
 *
 * WHY THIS TEST EXISTS. Two of this repo's four E2E drivers sent the bare 65-byte signature —
 * `deploy/verify-prod-e2e.mjs` and `scripts/e2e/handleops-tx.mjs`. They were written before the tag
 * landed on CC-22, `scripts/e2e/realnode-e2e.mjs` and `scripts/e2e/selftest.mjs` were fixed then, and
 * the other two were not. They had therefore been unable to pass the gate on ANY account since, and
 * nothing said so: the failure surfaces as a 403 whose text names the NODE, so it reads like three
 * broken nodes rather than a stale client. An E2E script that cannot pass is worse than no script —
 * it is a green-looking button nobody presses twice.
 *
 * This asserts the property on the FILES rather than by running them, because the real thing needs
 * three live nodes, a funded key and the network. It is a cheap guard against the specific way this
 * broke: a fix applied to some copies of a hand-copied rule and not the others.
 */
const REPO = resolve(process.cwd());

/** Every script that posts to the node's sign endpoint — discovered, not hard-coded, so a NEW driver
 *  is covered the day it is written rather than the day someone remembers to list it here. */
function signEndpointDrivers(): { path: string; body: string }[] {
  const roots = ["scripts/e2e", "scripts", "deploy"];
  const found: { path: string; body: string }[] = [];
  for (const root of roots) {
    let entries: string[];
    try {
      entries = readdirSync(join(REPO, root));
    } catch {
      continue;
    }
    for (const f of entries) {
      if (!f.endsWith(".mjs")) continue;
      const path = join(root, f);
      const body = readFileSync(join(REPO, path), "utf8");
      if (body.includes("/signature/sign")) found.push({ path, body });
    }
  }
  return found;
}

const drivers = signEndpointDrivers();

describe("E2E drivers must build ownerAuth in the account's wire format", () => {
  /**
   * The control. A file scan that matches nothing passes every assertion below it, so the suite
   * would go green on the day someone renames the directory — reporting most loudly exactly when it
   * has stopped looking. The count is deliberately a floor, not an equality: adding a fifth driver
   * should not fail this test, only removing them all should.
   */
  it("finds the drivers at all (guard against a vacuous pass)", () => {
    expect(drivers.length).toBeGreaterThanOrEqual(4);
    const paths = drivers.map(d => d.path);
    expect(paths).toEqual(
      expect.arrayContaining([
        "scripts/e2e/realnode-e2e.mjs",
        "scripts/e2e/selftest.mjs",
        "scripts/e2e/handleops-tx.mjs",
        "deploy/verify-prod-e2e.mjs",
      ])
    );
  });

  it.each(drivers.map(d => d.path))("%s tags ownerAuth with 0x01", path => {
    const { body } = drivers.find(d => d.path === path)!;
    const assignments = body.match(/const ownerAuth\s*=.*/g) ?? [];
    // A driver that posts to the gate but never builds an ownerAuth is not "passing" — it is
    // unmeasured. Require the assignment to exist before judging its shape.
    expect(assignments.length).toBeGreaterThan(0);
    for (const line of assignments) {
      expect(line).toContain('"0x01"');
    }
  });

  it.each(drivers.map(d => d.path))("%s does not send a bare, untagged signature", path => {
    const { body } = drivers.find(d => d.path === path)!;
    // The exact shape that was broken: `const ownerAuth = await owner.signMessage(...)` with nothing
    // prepended. Matching the defect rather than the fix keeps this readable when the fix is
    // rewritten — a driver may build the tag any way it likes, but not this way.
    expect(body).not.toMatch(/const ownerAuth\s*=\s*await\s+\w+\.signMessage\(/);
  });

  /**
   * `localhost` is not a synonym for 127.0.0.1. It resolves to ::1 first on a dual-stack host, so any
   * unrelated IPv6 listener on the same port answers instead of the node. That is not hypothetical:
   * on 2026-09-01 a Next.js dev server held `*:3001` while the DVT containers bound 127.0.0.1 only,
   * and `scripts/e2e/selftest.mjs` died on `SyntaxError: Unexpected token 'I', "Internal S"...` —
   * a failure that names neither the port, the wrong server, nor the resolution rule. Every driver
   * takes its host from DVT_NODE_HOST, defaulting to the literal 127.0.0.1.
   */
  it.each(drivers.map(d => d.path))("%s addresses nodes by IP, not localhost", path => {
    const { body } = drivers.find(d => d.path === path)!;
    expect(body).not.toContain("http://localhost:");
  });

  /**
   * `0x45Dfe3D5…` implements ERC-1271 but not `isValidOwnerAuth` — verified on Sepolia, where the
   * call REVERTS while the same call on an AAStarAirAccountV7 returns a bytes4. It was the default
   * in `deploy/verify-prod-e2e.mjs` and hard-coded, with no override at all, in
   * `scripts/e2e/handleops-tx.mjs`. A default that cannot work is worse than a required argument:
   * the run gets further before it fails, and fails somewhere else.
   */
  it.each(drivers.map(d => d.path))(
    "%s does not resurrect the ERC-1271-only test account",
    path => {
      const { body } = drivers.find(d => d.path === path)!;
      expect(body.toLowerCase()).not.toContain("0x45dfe3d5938fdf5a8d30641c3fda9c9fb1f31ba9");
    }
  );
});
