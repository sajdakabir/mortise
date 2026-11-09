import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// Exercise the credential-selection logic with DOM-shaped fields. Browser
// event delivery and layout still need the browser/manual tests.
const source = readFileSync(new URL("../../capture.js", import.meta.url), "utf8");
function capture(fields) {
  const scope = {
    querySelectorAll(selector) {
      return selector === "input" ? fields : fields.filter((f) => f.type === "password");
    },
    querySelector() {
      return fields.find((f) => f.autocomplete.split(/\s+/).includes("username") ||
        (f.type === "hidden" && ["username", "email"].includes(f.name))) ?? null;
    },
  };
  for (const field of fields) field.form = scope;
  const context = {
    chrome: {}, scope,
    document: { querySelectorAll: () => [], addEventListener() {}, documentElement: {} },
    MutationObserver: class { observe() {} },
    Node: { DOCUMENT_POSITION_FOLLOWING: 4 },
  };
  return JSON.parse(runInNewContext(source + "\nJSON.stringify(credentialIn(scope));", context));
}
function field(type, value, autocomplete = "", name = "") {
  return { type, value, autocomplete, name, disabled: false,
    getBoundingClientRect: () => ({ width: type === "hidden" ? 0 : 100, height: 20 }),
    compareDocumentPosition: () => 4 };
}

test("normal login captures the submitted username and password", () => {
  assert.deepEqual(capture([field("email", "alex@example.test"), field("password", "old")]),
    { username: "alex@example.test", password: "old" });
});
test("a password change selects the new password and retained username", () => {
  assert.deepEqual(capture([
    field("hidden", "alex", "username"), field("password", "old", "current-password"),
    field("password", "new", "new-password"), field("password", "new", "new-password"),
  ]), { username: "alex", password: "new" });
});
test("mismatched or empty confirmations never fall back to the old password", () => {
  for (const confirmation of ["different", ""]) {
    assert.equal(capture([
      field("password", "old", "current-password"), field("password", "new", "new-password"),
      field("password", confirmation, "new-password"),
    ]), null);
  }
});
test("identifier-first forms retain an explicitly named hidden username", () => {
  assert.deepEqual(capture([field("hidden", "alex", "", "username"), field("password", "saved")]),
    { username: "alex", password: "saved" });
});
test("empty forms and empty new-password fields produce no capture", () => {
  assert.equal(capture([]), null);
  assert.equal(capture([field("password", "", "new-password")]), null);
});
