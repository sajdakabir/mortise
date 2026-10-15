/**
 * Regenerates the cross-implementation proof vectors pinned in
 * crates/mortise-app/tests/browser.rs.
 *
 * Run with: node extension/tools/gen-proof-vectors.mjs
 *
 * Only update those vectors when the protocol genuinely changes. If they start
 * failing without an intentional change, the two implementations have drifted
 * and the extension is about to stop working.
 */
import { computeProof, proofPayload } from "../proof.js";

const KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

const cases = [
  { type: "logins", id: "abcdef0123456789", origin: "https://github.com" },
  {
    type: "credential",
    id: "abcdef0123456789",
    origin: "https://github.com",
    item_id: "0102030405060708090a0b0c0d0e0f10",
  },
  { type: "logins", id: "ff", origin: "http://localhost:3000" },
  {
    type: "capture",
    id: "abcdef0123456789",
    origin: "https://github.com",
    username: "octocat",
    password: "hunter2",
  },
  // A capture with no username, to pin that it encodes as an empty field.
  {
    type: "capture",
    id: "abcdef0123456789",
    origin: "https://github.com",
    password: "hunter2",
  },
];

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

for (const request of cases) {
  console.log(`${request.type.padEnd(11)} payload ${hex(proofPayload(request))}`);
  console.log(`${"".padEnd(11)} proof   ${await computeProof(KEY, request)}`);
}
