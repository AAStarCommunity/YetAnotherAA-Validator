// Pinata pinner (W2): direct upload to the v3 Files API, public network, CIDv1.
// Docs (2026-11): POST https://uploads.pinata.cloud/v3/files, multipart `file`, `network`
// (default PRIVATE, so it is always set to public), `cid_version` (v1 = raw leaves, 256 KiB chunks).
// UNVERIFIED until the author's account exists: the exact form-field names and that a sub-256 KiB
// file comes back as a raw `bafkrei` CID; both are live pre-go-live cells. The CID returned is
// never trusted: publishRecord compares it with the local CID and fetches the bytes back.
import { request, jsonOf, fetchBounded, SinkHttpError } from "./http.mjs";
import { CID_RE } from "./cid-shape.mjs";

export function pinataPinner({
  token,
  gateway,
  uploadUrl = "https://uploads.pinata.cloud/v3/files",
  fields = {},
}) {
  if (!token) throw new Error("pinata: token required");
  if (!gateway) throw new Error("pinata: gateway (https://<name>.mypinata.cloud) required");
  return {
    name: "pinata",
    async upload(bytes) {
      const form = new FormData();
      form.append(
        fields.file ?? "file",
        new Blob([bytes], { type: "application/json" }),
        "record.json"
      );
      form.append(fields.network ?? "network", "public");
      form.append(fields.cidVersion ?? "cid_version", "v1");
      const r = await request("pinata upload", uploadUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      const j = jsonOf("pinata upload", r);
      const cid = j?.data?.cid ?? j?.cid ?? null;
      // The provider's value is untrusted text (it could echo a token): only a CID-shaped
      // string leaves this sink, and publishRecord compares it with the local CID.
      if (typeof cid !== "string" || !CID_RE.test(cid))
        throw new SinkHttpError("pinata upload", "response has no valid CID");
      return { cid };
    },
    async fetchPublic(cid) {
      if (!CID_RE.test(String(cid))) return null; // only a base32 CIDv1 enters the URL
      return fetchBounded(`${gateway.replace(/\/$/, "")}/ipfs/${cid}`);
    },
  };
}
