// Filebase pinner (W2): IPFS RPC add with a bucket-scoped token.
// Docs (2026-11): POST https://rpc.filebase.io/api/v0/add, multipart `file`, `cid-version` (default
// 0, so 1 is always set), Authorization: Bearer <bucket token>. UNVERIFIED: whether `raw-leaves`
// is honoured; the returned CID is compared with the local one by publishRecord, so a mismatch is
// a failed pin, never a wrong publication. Never configure the account S3 key/secret here.
import { fetchWithTimeout, fetchBounded, httpError } from "./http.mjs";

export function filebasePinner({
  token,
  gateway = "https://ipfs.filebase.io",
  rpcUrl = "https://rpc.filebase.io/api/v0/add",
}) {
  if (!token) throw new Error("filebase: bucket token required");
  return {
    name: "filebase",
    async upload(bytes) {
      const form = new FormData();
      form.append("file", new Blob([bytes], { type: "application/json" }), "record.json");
      const url = `${rpcUrl}?cid-version=1&raw-leaves=true&pin=true`;
      const res = await fetchWithTimeout(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      if (!res.ok) throw await httpError("filebase add", res);
      const j = await res.json();
      return { cid: j?.Hash ?? null };
    },
    async fetchPublic(cid) {
      return fetchBounded(`${gateway.replace(/\/$/, "")}/ipfs/${cid}`);
    },
  };
}
