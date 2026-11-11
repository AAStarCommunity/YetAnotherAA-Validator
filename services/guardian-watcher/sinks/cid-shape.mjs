// The only CID form a sink accepts from a provider or puts into a URL: base32 lower CIDv1.
export const CID_RE = /^b[a-z2-7]{20,100}$/;
