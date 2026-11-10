// Pinata pinner (W2): direct upload to the v3 Files API, public network, CIDv1.
// Docs (2026-11): POST https://uploads.pinata.cloud/v3/files, multipart `file`, `network`
// (default PRIVATE, so it is always set to public), `cid_version` (v1 = raw leaves, 256 KiB chunks).
// UNVERIFIED until the author's account exists: the exact form-field names and that a sub-256 KiB
// file comes back as a raw `bafkrei` CID; both are live pre-go-live cells. The CID returned is
// never trusted: publishRecord compares it with the local CID and fetches the bytes back.
import { request, jsonOf, fetchBounded } from "./http.mjs";

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
      return { cid: typeof cid === "string" ? cid : null };
    },
    async fetchPublic(cid) {
      if (!/^b[a-z2-7]{20,}$/.test(String(cid))) return null; // only a base32 CIDv1 enters the URL
      return fetchBounded(`${gateway.replace(/\/$/, "")}/ipfs/${cid}`);
    },
  };
}
