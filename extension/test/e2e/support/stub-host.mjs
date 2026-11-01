#!/usr/bin/env node
/**
 * A stand-in for mortise-proxy + the app, for the end-to-end tests.
 *
 * Chrome spawns this exactly as it would spawn the real proxy: one process per
 * `sendNativeMessage`, one length-prefixed JSON frame in, one out. Everything
 * the extension does up to the native boundary is real, including the proofs,
 * which are checked here the way the app checks them — so a proof regression
 * fails these tests rather than passing silently against a lenient fake.
 *
 * State lives in the directory named by MORTISE_STUB_STATE, which the test
 * fixture creates per test and the browser passes down to its children:
 *
 *   vault.json     what the "app" knows — see `defaultVault` in fixtures.js
 *   requests.jsonl every request received, appended, for tests to assert on
 *
 * Fake credentials only. Nothing here is a real secret, which is why logging
 * requests in full is acceptable in a test and nowhere else.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

const STATE = process.env.MORTISE_STUB_STATE;

function readFrame() {
  const chunks = [];
  return new Promise((resolve) => {
    process.stdin.on("data", (chunk) => {
      chunks.push(chunk);
      const all = Buffer.concat(chunks);
      if (all.length >= 4 && all.length >= 4 + all.readUInt32LE(0)) {
        resolve(JSON.parse(all.subarray(4, 4 + all.readUInt32LE(0)).toString("utf8")));
      }
    });
  });
}

function writeFrame(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  // Exit once written: Chrome reads one reply per spawn and nothing else
  // will close stdin for us.
  process.stdout.write(Buffer.concat([header, body]), () => process.exit(0));
}

/** Independent of proof.js on purpose: this side plays the Rust. */
function payload(request) {
  const fields = {
    logins: () => ["logins", request.id, request.origin],
    credential: () => ["credential", request.id, request.origin, request.item_id],
    capture: () => [
      "capture",
      request.id,
      request.origin,
      request.username ?? "",
      request.password,
    ],
  }[request.type]?.();
  if (!fields) return null;
  return Buffer.concat(
    fields.map((f) => {
      const bytes = Buffer.from(f, "utf8");
      const len = Buffer.alloc(4);
      len.writeUInt32BE(bytes.length, 0);
      return Buffer.concat([len, bytes]);
    }),
  );
}

function proofValid(vault, request) {
  const bytes = payload(request);
  if (!bytes || request.id !== vault.association.id || typeof request.proof !== "string") {
    return false;
  }
  const expected = createHmac("sha256", Buffer.from(vault.association.key, "hex"))
    .update(bytes)
    .digest();
  const given = Buffer.from(request.proof, "hex");
  return given.length === expected.length && timingSafeEqual(given, expected);
}

const error = (code, message = code) => ({ type: "error", code, message });

function respond(vault, request) {
  switch (request.type) {
    case "status":
      return { type: "status", associated: vault.paired, unlocked: vault.unlocked };
    case "associate":
      if (!vault.approve) return { type: "approval_required", request_token: "stub-token" };
      return { type: "associated", id: vault.association.id, key: vault.association.key };
  }

  if (!proofValid(vault, request)) return error("not_associated", "This browser is not paired.");
  if (!vault.unlocked) return error("locked", "Unlock Mortise.");

  switch (request.type) {
    case "logins":
      return {
        type: "logins",
        items: vault.logins
          .filter((l) => l.origin === request.origin)
          .map(({ item_id, title, username }) => ({ item_id, title, username })),
      };
    case "credential": {
      // Same re-check the app makes: an id is only good on its own origin.
      const item = vault.logins.find(
        (l) => l.item_id === request.item_id && l.origin === request.origin,
      );
      if (!item) return error("not_permitted", "That item is not for this site.");
      return { type: "credential", username: item.username, password: item.password };
    }
    case "capture":
      return {
        type: "captured",
        queued: !vault.logins.some(
          (l) => l.origin === request.origin && l.password === request.password,
        ),
      };
    default:
      return error("bad_request", "Unrecognised message.");
  }
}

const request = await readFrame();
const vault = JSON.parse(readFileSync(join(STATE, "vault.json"), "utf8"));
appendFileSync(join(STATE, "requests.jsonl"), JSON.stringify(request) + "\n");

// Lets a test hold a reply open, to act while the extension is waiting.
const delay = vault.delayMs?.[request.type] ?? 0;
if (delay) await new Promise((r) => setTimeout(r, delay));

writeFrame(respond(vault, request));
