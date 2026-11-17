Deployment gate: **FAIL**. I found six High-severity issues.

1. **High — A provider can consistently omit an operator and produce a false clear**  
   **File:** `deploy/pause-detector/lib/detect.mjs:564`, `deploy/pause-detector/lib/detect.mjs:572`, `deploy/pause-detector/lib/detect.mjs:656`, `deploy/pause-detector/run.mjs:313`  
   **Scenario:** The selected provider returns `[]` for an `OperatorConfigured` log in both the range query and the block-hash query. The two empty answers agree, so the watermark advances. The operator never enters the inventory; `results.every(...)` succeeds over the remaining or empty inventory, and `report.clear` becomes true while the omitted operator may be understaked. Both checks use the same provider, so they are not independent. The test fixture explicitly models consistent hiding at `check-pause-detector.mjs:727-752`.  
   **Suggested fix:** Cross-check operator logs with the fallback provider before advancing `checked` or reporting clear. At minimum, compare finalized log inventories from two independent providers; ideally also compare all per-operator decision inputs.

2. **High — `startBlock` is not authenticated, so a configuration mistake can omit existing operators permanently**  
   **File:** `deploy/pause-detector/run.mjs:67`, `deploy/pause-detector/lib/detect.mjs:93`, `deploy/pause-detector/lib/detect.mjs:420`, `deploy/pause-detector/lib/detect.mjs:656`  
   **Scenario:** `startBlock` is validated only as a positive integer. If it is accidentally set after an operator’s `OperatorConfigured` event, all scans begin after that event. The operator remains absent and the detector can report clear. Contract identity checks do not bind or verify the deployment block.  
   **Suggested fix:** Pin the expected deployment block in a reviewed artifact tied to the contract identity, and reject configuration disagreement. Add a deployment test with an operator configured immediately before the supplied `startBlock`.

3. **High — Environment-injection guards run after preload code can execute**  
   **File:** `deploy/pause-detector/detector.mjs:32`, `deploy/pause-detector/lib/guard.mjs:203`, `deploy/pause-detector/io.aastar.dvt-pause-detector.plist:18`, `deploy/pause-detector/io.aastar.dvt-pause-detector-deadman.plist:14`  
   **Scenario:** A stale inherited `NODE_OPTIONS=--require=<file-under-.aoa-pause-detector>` is processed before `detector.mjs` executes. The preload can read the RPC URLs/token and make unrestricted network requests before `launchProblems()` notices `NODE_OPTIONS` and exits. Combining `--require` with a widened `--allow-fs-read` can expose a private key before the guard runs. `DYLD_INSERT_LIBRARIES` is earlier still. Neither plist starts from a sanitized environment.  
   **Suggested fix:** Start Node through a minimal signed/hardened launcher that clears the environment before `execve`, supplying only the exact allowlist. Treat the in-process environment check as defense in depth, not prevention.

4. **High — The bundle’s integrity check is self-authenticating and does not pin the reviewed commit**  
   **File:** `deploy/pause-detector/bundle.mjs:58`, `deploy/pause-detector/bundle.mjs:62`, `deploy/pause-detector/bundle.mjs:105`, `deploy/pause-detector/lib/guard.mjs:324`, `deploy/pause-detector/io.aastar.dvt-pause-detector.plist:24`  
   **Scenario:** `MANIFEST.json` records a commit, but `bundleProblems()` never checks that field against `ab5317fbb150701d2b65ce26f395d25e502845e2` or any external expected value. An old bundle, a bundle built from the wrong clean commit, or dirty code bundled with `--allow-dirty` passes because its files match its own manifest. Launchd always runs the stable `app` path.  
   **Suggested fix:** Pin the expected 40-character commit and manifest SHA outside the bundle—such as exact loaded launch arguments or a signed deployment receipt—and verify both at startup and preflight. Remove `--allow-dirty` from the production-capable bundler, or mark dirty manifests and make runtime refuse them.

5. **High — Dependencies bypass the signing/network scan and are blessed without lockfile verification**  
   **File:** `deploy/pause-detector/no-signing-scan.mjs:123`, `deploy/pause-detector/no-signing-scan.mjs:128`, `deploy/pause-detector/bundle.mjs:65`, `deploy/pause-detector/bundle.mjs:84`, `deploy/pause-detector/bundle.mjs:101`  
   **Scenario:** The scan recognizes the bare `ethers` import but does not traverse it. The bundler then copies the entire resolved package and dependency closure from `node_modules`, including wallet/signing and networking code, without checking the installed bytes against `package-lock.json` integrity. A stale or tampered dependency can directly call `fetch` with `eth_sendTransaction`/`eth_sendRawTransaction`, read the detector’s secret files, or leak them; the application RPC allowlist and static scan do not mediate dependency code.  
   **Suggested fix:** Bundle only audited utility modules, verify every dependency’s exact version and integrity against the lockfile, and scan the actual executable dependency graph. For a hard no-send guarantee, enforce outbound RPC through a separate method-filtering proxy or OS-level egress control.

6. **High — Several common-mode failures stop both detector and dead-man silently**  
   **File:** `deploy/pause-detector/deadman-run.mjs:138`, `deploy/pause-detector/deadman-run.mjs:146`, `deploy/pause-detector/deadman-run.mjs:153`, `deploy/pause-detector/io.aastar.dvt-pause-detector-deadman.plist:16`  
   **Scenario:** If shared `config.json` is missing/corrupt, the shared Telegram token is unreadable, the common pinned Node binary disappears, or a dead-man runtime file fails verification, both jobs stop and neither can alert. They can write local stop status, but nothing checks it on a schedule. The README acknowledges these gaps, but they still violate “the dead-man itself must not fail silently.”  
   **Suggested fix:** Use an independent external heartbeat monitor or a watchdog with a separate runtime, minimal configuration, credentials, and preferably a second alert channel. Scheduled preflight alone is weaker but would at least close the indefinite-silence case.

7. **Medium — Failed alert delivery still refreshes the heartbeat**  
   **File:** `deploy/pause-detector/run.mjs:381`, `deploy/pause-detector/run.mjs:389`, `deploy/pause-detector/run.mjs:402`, `deploy/pause-detector/deadman-run.mjs:43`  
   **Scenario:** A canonical round finds an actionable condition, but Telegram delivery fails. The detector nevertheless writes a fresh heartbeat. If Telegram works during dead-man runs but repeatedly fails during hourly detector runs, the dead-man considers the detector alive and sends no outage warning.  
   **Suggested fix:** Refresh the heartbeat only when the round completed and all due alerts were delivered, or make the dead-man inspect detector status and alert on `delivery.ok === false`.

8. **Medium — Future block timestamps bypass frozen-head detection**  
   **File:** `deploy/pause-detector/lib/detect.mjs:87`  
   **Scenario:** A provider supplies a frozen head with a timestamp far in the future, or the Mini’s clock is substantially behind. `now / 1000 - timestamp` is negative and therefore never exceeds `maxHeadAgeSec`; the frozen state can be reported clear.  
   **Suggested fix:** Reject timestamps more than a small permitted future skew, and treat substantial local-clock disagreement as unknown.

9. **Medium — RPC and Telegram response bodies are unbounded**  
   **File:** `deploy/pause-detector/run.mjs:102`, `deploy/pause-detector/run.mjs:111`, `deploy/pause-detector/lib/notify.mjs:94`, `deploy/pause-detector/lib/notify.mjs:103`  
   **Scenario:** An endpoint streams a very large JSON response within the timeout. `res.json()` buffers and parses it without a content-length or byte limit, potentially exhausting memory. A hostile Telegram response affects both detector and dead-man, creating another common-mode failure.  
   **Suggested fix:** Enforce response-size limits while streaming, reject excessive `Content-Length`, and cap log counts and encoded result sizes before parsing/processing.

10. **Medium — The no-signing scanner explicitly permits a simple computed-name bypass**  
    **File:** `deploy/pause-detector/no-signing-scan.mjs:225`  
    **Scenario:** Code such as `const a="send"; const b="Transaction"; const k=a+b; client[k](tx)` passes: the individual strings do not match `sendTransaction`, and an identifier used as a computed property is allowed. This can introduce a send path while the CI scan remains green.  
    **Suggested fix:** Reject all computed member access in runtime modules unless it matches a narrowly enumerated safe pattern, or add data-flow/constant-folding analysis and adversarial controls for multi-variable string construction.

11. **Low — Persistent state has an implicit approximately 1 MiB lifetime limit**  
    **File:** `deploy/pause-detector/lib/guard.mjs:240`, `deploy/pause-detector/lib/detect.mjs:102`, `deploy/pause-detector/lib/detect.mjs:597`  
    **Scenario:** The operator inventory only grows, but `readOwn()` refuses files over 1 MiB. Once `state.json` crosses that size, the following run refuses to load it and the detector remains unavailable until manually repaired.  
    **Suggested fix:** Use an explicit scalable state format or raise/configure the bound with an operator-count limit and an alert well before exhaustion.

I did not execute the test suites because they create loopback network/RPC endpoints and the review rules prohibit network or RPC activity.