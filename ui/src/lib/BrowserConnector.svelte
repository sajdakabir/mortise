<script lang="ts">
  import { onMount } from "svelte";
  import { ipc } from "./ipc";
  import { errorMessage, type NativeHostStatus } from "./types";

  let browser = $state("Chrome / Dia");
  let host = $state<NativeHostStatus | null>(null);
  let extensionId = $state("");
  let busy = $state(false);
  let error = $state("");
  let message = $state("");
  const firefox = $derived(browser === "Firefox");

  async function refresh() {
    try {
      host = await ipc.nativeHostStatus();
      if (!extensionId && host.extension_id) extensionId = host.extension_id;
    } catch (e) { error = errorMessage(e); }
  }
  onMount(() => {
    void refresh();
    window.addEventListener("focus", refresh);
    return () => window.removeEventListener("focus", refresh);
  });

  async function connect() {
    if (busy) return;
    busy = true;
    error = "";
    message = "";
    try {
      const registered = await ipc.installNativeHost(firefox ? "mortise@mortise.app" : extensionId.trim());
      message = `Connector ready for ${registered.join(", ")}. Pair from the browser toolbar next.`;
      await refresh();
    } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }
</script>

<div class="connector">
  <label>Browser
    <select bind:value={browser} disabled={busy} onchange={() => { error = ""; message = ""; }}>
      <option>Chrome / Dia</option>
      <option>Firefox</option>
    </select>
  </label>
  {#if host && !host.proxy_present}
    <p class="error" role="status">The browser helper is missing. Reinstall Mortise, or build mortise-proxy for a development checkout.</p>
  {/if}
  <ol>
    {#if firefox}
      <li>Use <strong>Firefox 153 or later</strong>. Open <code>about:debugging#/runtime/this-firefox</code>, choose <strong>Load Temporary Add-on</strong>, then select <code>manifest.json</code> from the unpacked Firefox extension package.</li>
      <li>Click <strong>Connect Firefox</strong> below. No extension ID needs to be copied.</li>
    {:else}
      <li>Open <code>chrome://extensions</code> in Chrome or Dia. Enable <strong>Developer mode</strong>, choose <strong>Load unpacked</strong>, and select the unpacked Chromium extension folder.</li>
      <li>Copy the extension ID shown by your browser, then connect below.</li>
    {/if}
    <li>Open Mortise in the browser toolbar, click <strong>Pair</strong>, and approve the request in this app. Return to the popup and click <strong>Check again</strong>.</li>
  </ol>
  <div class="connect">
    {#if !firefox}
      <input aria-label="Chromium extension ID" placeholder="Extension ID: 32 letters, a–p" spellcheck="false" bind:value={extensionId} disabled={busy} />
    {/if}
    <button class="primary" disabled={busy || !host?.proxy_present || (!firefox && !extensionId.trim())} onclick={connect}>
      {busy ? "Connecting…" : firefox ? "Connect Firefox" : "Connect browser"}
    </button>
  </div>
  {#if firefox}<p class="faint">Preview: Firefox removes temporary add-ons when it closes. Load it again after restarting. A signed release will remove this step.</p>{/if}
  {#if message}<p role="status">{message}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

<style>
  .connector { margin-top: 14px; font-size: 12px; line-height: 1.6; }
  label { display: flex; gap: 12px; align-items: center; }
  select { max-width: 200px; }
  ol { padding-left: 20px; color: var(--text-dim); }
  li { margin: 8px 0; }
  strong { color: var(--text); }
  code { font-family: var(--mono); overflow-wrap: anywhere; }
  .connect { display: flex; gap: 8px; flex-wrap: wrap; }
  input { flex: 1; min-width: 180px; font-family: var(--mono); font-size: 12px; }
  button { flex-shrink: 0; }
  .error { color: var(--danger); }
</style>
