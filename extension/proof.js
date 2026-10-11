/**
 * Request proofs.
 *
 * This reimplements `truepass_app_lib::browser::protocol::proof_payload`. The
 * two must agree byte for byte: length-prefixed fields, big-endian u32 lengths,
 * fixed order. If they drift, every request fails closed.
 *
 * Length prefixes are not decoration. Without them, origin "ab" + item "c" and
 * origin "a" + item "bc" would produce identical signed bytes, and a proof for
 * one would verify for the other.
 */

const encoder = new TextEncoder();

/** Encode one field as a 4-byte big-endian length followed by its UTF-8 bytes. */
function field(text) {
  const bytes = encoder.encode(text);
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false); // false = big-endian
  out.set(bytes, 4);
  return out;
}

function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/**
 * The bytes a request's proof is computed over.
 * Returns null for requests that carry no proof.
 */
export function proofPayload(request) {
  switch (request.type) {
    case "logins":
      return concat([field("logins"), field(request.id), field(request.origin)]);
    case "credential":
      return concat([
        field("credential"),
        field(request.id),
        field(request.origin),
        field(request.item_id),
      ]);
    case "capture":
      // Mirrors the Rust: the password is covered so a proof cannot be
      // replayed with a different one, and a missing username encodes the
      // same as an empty one.
      return concat([
        field("capture"),
        field(request.id),
        field(request.origin),
        field(request.username ?? ""),
        field(request.password),
      ]);
    default:
      // status and associate are unprovable by design: the first needs no
      // proof, the second is what establishes the key.
      return null;
  }
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** HMAC-SHA256 the payload with the association key. Returns lowercase hex. */
export async function computeProof(keyHex, request) {
  const payload = proofPayload(request);
  if (!payload) return null;

  const key = await crypto.subtle.importKey(
    "raw",
    fromHex(keyHex),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, payload));
}
