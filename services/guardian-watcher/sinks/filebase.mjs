// Filebase pinner (W2): IPFS RPC add with a bucket-scoped token.
// Docs (2026-11): POST https://rpc.filebase.io/api/v0/add, multipart `file`, `cid-version` (default
// 0, so 1 is always set), Authorization: Bearer <bucket token>. UNVERIFIED: whether `raw-leaves`
// is honoured; the returned CID is compared with the local one by publishRecord, so a mismatch is
// a failed pin, never a wrong publication. Never configure the account S3 key/secret here.
import { request, jsonOf, fetchBounded, SinkHttpError } from "./http.mjs";
import { CID_RE } from "./cid-shape.mjs";

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
      const r = await request("filebase add", url, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      const j = jsonOf("filebase add", r);
      const cid = j?.Hash ?? null;
      // The provider's value is untrusted text (it could echo a token): only a CID-shaped
      // string leaves this sink, and publishRecord compares it with the local CID.
      if (typeof cid !== "string" || !CID_RE.test(cid))
        throw new SinkHttpError("filebase add", "response has no valid CID");
      return { cid };
    },
    async fetchPublic(cid) {
      if (!CID_RE.test(String(cid))) return null; // only a base32 CIDv1 enters the URL
      return fetchBounded(`${gateway.replace(/\/$/, "")}/ipfs/${cid}`);
    },
  };
}
