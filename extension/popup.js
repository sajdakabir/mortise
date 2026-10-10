/**
 * The popup. Talks only to the service worker, never to the native host.
 *
 * It also never learns a password: picking an entry asks the worker to fill,
 * and the secret goes from the app straight into the page's form field without
 * passing through this window.
 */

const app = document.getElementById("app");

const send = (command, args = {}) =>
  chrome.runtime.sendMessage({ command, ...args });

function el(tag, props = {}, children = []) {
  const node = Object.assign(document.createElement(tag), props);
  for (const child of [].concat(children)) {
    node.append(child);
  }
  return node;
}

/** Everything rendered here comes from the vault or the browser — but build it
 *  with textContent rather than innerHTML regardless. An item title is user
 *  data, and a popup is not the place to start trusting it. */
function notice(kind, title, body, action) {
  const box = el("div", { className: `notice ${kind}` }, [
    el("h2", { textContent: title }),
    el("p", { textContent: body }),
  ]);
  if (action) box.append(action);
  return box;
}

function button(label, onclick, plain = false) {
  return el("button", {
    className: `wide${plain ? " plain" : ""}`,
    textContent: label,
    onclick,
  });
}

async function render() {
  app.replaceChildren(el("p", { className: "muted pad", textContent: "Checking…" }));

  const status = await send("status");

  if (status?.code === "no_host" || status?.code === "timeout") {
    app.replaceChildren(
      notice(
        "bad",
        "TruePassword is not running",
        status.message,
        button("Try again", render, true),
      ),
    );
    return;
  }

  if (!status?.hasKey || status?.associated === false) {
    app.replaceChildren(
      notice(
        "warn",
        "Pair this browser",
        "TruePassword will ask you to approve this browser in its own window. That approval is what stops anything else on this Mac from reading your vault.",
        button("Pair", pair),
      ),
    );
    return;
  }

  const result = await send("logins");

  if (result?.type === "error") {
    app.replaceChildren(
      notice("bad", "Could not look that up", result.message, button("Try again", render, true)),
    );
    return;
  }

  const items = result?.items ?? [];
  const origin = result?.origin;

  const header = el("header", {}, [
    el("div", { className: "site", textContent: origin ?? "This page" }),
    el("div", { className: "count", textContent: `${items.length}` }),
  ]);

  if (items.length === 0) {
    app.replaceChildren(
      header,
      el("p", {
        className: "faint pad",
        textContent: status.unlocked
          ? "No saved logins for this site. Note that a login saved for one host does not cover its subdomains."
          : "Nothing to show. Unlock TruePassword, or there are no logins for this site.",
      }),
    );
    return;
  }

  const list = el(
    "div",
    { className: "list" },
    items.map((item) =>
      el("button", { className: "entry", onclick: () => fill(item.item_id) }, [
        el("span", { className: "t", textContent: item.title }),
        el("span", { className: "s", textContent: item.username ?? "No username" }),
      ]),
    ),
  );

  app.replaceChildren(header, list);
}

async function pair() {
  app.replaceChildren(
    notice("warn", "Waiting for approval", "Approve this browser in the TruePassword window, then come back."),
  );

  const response = await send("associate");

  if (response?.type === "associated") {
    await render();
    return;
  }

  app.replaceChildren(
    notice(
      response?.code === "approval_required" ? "warn" : "bad",
      response?.code === "approval_required" ? "Not approved yet" : "Pairing failed",
      response?.message ?? "Could not pair with TruePassword.",
      button("Check again", pair, true),
    ),
  );
}

async function fill(itemId) {
  app.replaceChildren(el("p", { className: "muted pad", textContent: "Filling…" }));
  const response = await send("fill", { itemId });

  if (response?.type === "filled") {
    window.close();
    return;
  }

  app.replaceChildren(
    notice(
      "bad",
      "Could not fill",
      response?.message ?? "Something went wrong.",
      button("Back", render, true),
    ),
  );
}

render();
