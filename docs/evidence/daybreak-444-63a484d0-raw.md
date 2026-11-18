- **High — `deploy/reregister-guardians.mjs:813-833,1194-1201`**  
  The live-chain gate relies only on `chainId`. A Sepolia fork normally retains chain ID `11155111`; if it contains the same deployments and state, every version, owner, wiring, and address check can pass. `--broadcast` then gives that fork RPC a valid Sepolia-signed raw transaction and reports success although canonical Sepolia is unchanged. The transaction may also be replayable on canonical Sepolia while its nonce remains valid.  
  **Suggested fix:** require an explicit live-broadcast mode that rejects localhost/private RPC endpoints and pins an approved RPC host plus a recent canonical finalized block hash. Keep all local rehearsals on a distinct chain ID such as `31337`; never sign with a live key when the endpoint could be a same-chain-ID fork.

- **Medium — `deploy/reregister-guardians.mjs:1076-1095,1197-1204`**  
  An already-active validator is accepted whenever its slot matches, without comparing its existing BLS public key to the requested key. A stale or mistaken node file containing a different valid keypair therefore passes every gate and can replace the live guardian’s key. The post-send read-back also treats the newly requested key as authoritative, so it will report success rather than detect the unintended rotation.  
  **Suggested fix:** when `existing.active` is true, require the complete on-chain public key to equal `pkWords`. Require a separate, explicit key-rotation mode for changing an active key.

- **Medium — `deploy/reregister-guardians.mjs:1072-1105`; `docs/rc8-deploy-day-dvt.md:192-207`**  
  The documented return-after-exit path requires restored `ROLE_DVT` and at least `minStake`, but the tool checks only suspension, slot, and BLS-key ownership. Because the owner registration path admits any validator, a SAFE can export and execute apparently successful calldata for a guardian that has not restored its role/stake; its key may be present while its signatures remain ineligible.  
  **Suggested fix:** add fail-closed Registry checks for `hasRole(ROLE_DVT)`, `getEffectiveStake`, and the current role minimum in a dedicated re-admission mode, or make the documentation require recorded external eligibility checks before export and SAFE execution.

- **Medium — `deploy/reregister-guardians.mjs:884-915,1143-1177`; `docs/rc8-deploy-day-dvt.md:176-190`**  
  Post-deployment export checks Registry routing only while generating the file. The calldata contains no state commitment or expiry. If `Registry.blsAggregator()` changes before the SAFE executes it, registration against the old DVTValidator/aggregator can still succeed while updating an aggregator the Registry no longer uses. The SAFE checklist does not require rechecking routing, versions, owner, suspension, or slot state.  
  **Suggested fix:** enforce current Registry routing in the on-chain registration path or an assertion wrapper. Until then, require regeneration immediately before execution and expand the SAFE checklist to repeat every state gate at the execution block.

- **Medium — `deploy/rehearse-reregister-plan.sh:23,36,60-66,101-104,121-132`**  
  `SP_COMMIT` is only a caller-provided label; it is never tied to `SP_DIR`, its source, or deployed artifacts. `EXPECT_VERSIONS` is also caller-provided. A stale or different checkout retaining the same version strings can therefore pass while the output claims it rehearsed the requested commit.  
  **Suggested fix:** verify `git -C "$SP_DIR" rev-parse HEAD` equals `SP_COMMIT` and reject relevant dirty files. For tarball-based rehearsals, verify source and artifact hashes against a commit-derived manifest before deployment.

- **Low — `deploy/reregister-guardians.mjs:317-344`; `docs/rc8-deploy-day-dvt.md:167-174`**  
  The claim that `--plan` and `--export-pop` “read no key” is not literally true. The program reads and parses the entire environment file before deciding not to assign `REREGISTER_OWNER_PRIVATE_KEY`; any EOA secrets in that file enter process memory in export-only modes.  
  **Suggested fix:** require a dedicated RPC-only environment file for export modes, or accept the RPC URL through a secret-free input and do not open the broader deployment environment file.

Static syntax checks and `git diff --check` passed at the requested HEAD. No network, chain, RPC, or secret-bearing files were accessed.