#!/usr/bin/env node
// Local, fake-login fixtures for manual browser checks. No credentials are
// logged or stored, and this server never connects to the Mortise vault.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const names = ["login", "multistep", "change-password", "spa", "iframe", "shadow"];
const pages = new URL("../test/e2e/pages/", import.meta.url);
const port = Number(process.env.MORTISE_TEST_PORT || 18787);
const index = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Mortise browser checks</title>
<style>body{font:16px system-ui;max-width:680px;margin:48px auto;padding:20px}li{margin:12px 0}</style>
<h1>Mortise browser checks</h1><p>Use fake credentials, for example <code>alex@example.test</code> and <code>demo-password-1</code>.</p>
<p>Mortise should save a submitted login while unlocked. Return to the form and use Fill to check it. This test site never stores submissions.</p>
<ul>${names.map((name) => `<li><a href="/${name}.html">${name}</a></li>`).join("")}</ul>
<p>Shadow-root forms remain a known limitation. The password-change fixture uses username <code>octocat</code>; save that account first.</p></html>`;
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  if (req.method === "POST" && url.pathname === "/signed-in") {
    req.resume(); // Discard the body; do not log, echo or persist passwords.
    req.on("end", () => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end('<!doctype html><title>Submitted</title><h1>Test login submitted</h1><a href="/login.html">Return to login</a> · <a href="/">All checks</a>');
    });
    return;
  }
  if (req.method !== "GET") { res.writeHead(405).end(); return; }
  res.setHeader("cache-control", "no-store");
  res.setHeader("content-type", "text/html; charset=utf-8");
  if (url.pathname === "/") { res.end(index); return; }
  const name = url.pathname.slice(1).replace(/\.html$/, "");
  if (!names.includes(name)) { res.writeHead(404).end(); return; }
  try { res.end(await readFile(new URL(`${name}.html`, pages))); }
  catch { res.writeHead(500).end("Could not read the test fixture."); }
});
server.on("error", (error) => { console.error(error.message); process.exitCode = 1; });
server.listen(port, "127.0.0.1", () => console.log(`Mortise test forms: http://127.0.0.1:${server.address().port}/ (fake credentials only)`));
