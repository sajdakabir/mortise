import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const base = JSON.parse(readFileSync(join(root, "extension/manifest.json")));
const script = join(root, "extension/tools/package.sh");
const files = ["manifest.json", "background.js", "capture.js", "proof.js", "popup.html", "popup.js", "popup.css", "icons/icon32.png", "icons/icon128.png", "icons/icon256.png"].sort();

test("both packages contain only runtime files and share the same permissions", () => {
  for (const target of ["chromium", "firefox"]) {
    execFileSync("bash", [script, target], { stdio: "pipe" });
    const archive = join(root, `target/extension/mortise-extension-${target === "firefox" ? "firefox-" : ""}${base.version}.zip`);
    const entries = execFileSync("unzip", ["-Z1", archive], { encoding: "utf8" }).trim().split("\n").sort();
    assert.deepEqual(entries, files);
    const manifest = JSON.parse(execFileSync("unzip", ["-p", archive, "manifest.json"], { encoding: "utf8" }));
    assert.deepEqual(manifest.permissions, base.permissions);
    assert.deepEqual(manifest.host_permissions, base.host_permissions);
    assert.deepEqual(manifest.content_scripts, base.content_scripts);
    assert.equal(manifest.version, base.version);
    assert.equal(manifest.key, undefined);
    if (target === "firefox") {
      assert.deepEqual(manifest.background, { scripts: ["background.js"], type: "module" });
      assert.equal(manifest.minimum_chrome_version, undefined);
      assert.equal(manifest.browser_specific_settings.gecko.strict_min_version, "153.0");
      assert.equal(manifest.browser_specific_settings.gecko.id, "mortise@mortise.app");
      assert.deepEqual(manifest.browser_specific_settings.gecko.data_collection_permissions.required, ["authenticationInfo", "websiteActivity"]);
    } else {
      assert.deepEqual(manifest.background, base.background);
      assert.equal(manifest.browser_specific_settings, undefined);
    }
  }
});
