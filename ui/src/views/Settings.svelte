<script lang="ts">
  import { ipc, onBrowserPairingRequest } from "../lib/ipc";
  import {
    errorMessage, isCmdError,
    type PairedBrowser, type VaultStatus,
  } from "../lib/types";

  let { status, onStatus, onClose }:
    { status: VaultStatus; onStatus: (s: VaultStatus) => void; onClose: () => void } = $props();

  let error = $state("");
  let busy = $state(false);

  let browsers = $state<PairedBrowser[]>([]);
  /** Name of a browser waiting for approval, if any. */
  let pairingRequest = $state<string | null>(null);

  async function refreshBrowsers() {
    browsers = await ipc.listBrowsers();
  }

  $effect(() => {
    refreshBrowsers();
    const stop = onBrowserPairingRequest((name) => { pairingRequest = name; });
    return () => { stop.then((f) => f()); };
  });

  async function approvePairing() {
    busy = true;
    error = "";
    try {
      await ipc.approveBrowser();
      pairingRequest = null;
      await refreshBrowsers();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function rejectPairing() {
    await ipc.rejectBrowser();
    pairingRequest = null;
  }

  async function unpair(id: string) {
    busy = true;
    try {
      await ipc.unpairBrowser(id);
      await refreshBrowsers();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function toggleBiometric() {
    busy = true;
    error = "";
    try {
      onStatus(await ipc.setBiometric(!status.biometric_enabled));
    } catch (e) {
      if (!(isCmdError(e) && e.code === "cancelled")) error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function forgetKey() {
    busy = true;
    error = "";
    try {
      onStatus(await ipc.forgetAccountKey());
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function signOut() {
    busy = true;
    try {
      onStatus(await ipc.signOut());
      onClose();
    } finally {
      busy = false;
    }
  }
</script>

<div class="settings">
  <div class="head spread">
    <h2>Settings</h2>
    <button class="ghost" onclick={onClose}>Done</button>
  </div>

  <div class="body">
    {#if error}<div class="error">{error}</div>{/if}

    {#if pairingRequest}
      <section class="pairing">
        <h3>Pair with {pairingRequest}?</h3>
        <p class="faint">
          This browser will be able to ask for logins matching the page you are on,
          and only after you pick one. Approve it only if you just clicked Pair in
          that browser — nothing else on this Mac can reach your vault without this.
        </p>
        <div class="row">
          <button class="primary" disabled={busy} onclick={approvePairing}>Approve</button>
          <button disabled={busy} onclick={rejectPairing}>Not now</button>
        </div>
      </section>
    {/if}

    <section>
      <div class="spread">
        <div class="label">
          <h3>Browsers</h3>
          <p class="faint">
            {#if browsers.length === 0}
              No browsers paired. Install the extension and click Pair in it.
            {:else}
              Paired: {browsers.map((b) => b.name).join(", ")}. Unpairing means that
              browser has to be approved again.
            {/if}
          </p>
        </div>
        {#if browsers.length > 0}
          <button disabled={busy} onclick={() => unpair(browsers[0].id)}>
            Unpair {browsers.length > 1 ? browsers[0].name : ""}
          </button>
        {/if}
      </div>
    </section>

    <section>
      <div class="spread">
        <div class="label">
          <h3>Unlock with Touch ID</h3>
          <p class="faint">
            Lets anyone who can pass Touch ID on this Mac open your vault, without
            your master password. Convenient, and a real trade — it is off unless
            you turn it on.
          </p>
        </div>
        <button disabled={busy || !status.unlocked} onclick={toggleBiometric}>
          {status.biometric_enabled ? "Turn off" : "Turn on"}
        </button>
      </div>
    </section>

    <section>
      <div class="spread">
        <div class="label">
          <h3>Recovery key on this Mac</h3>
          <p class="faint">
            {#if status.account_key_remembered}
              Saved in the keychain, so unlocking needs only your master password.
              Forgetting it means typing the recovery key next time.
            {:else}
              Not saved. You will be asked for your recovery key each time you unlock.
            {/if}
          </p>
        </div>
        <button disabled={busy || !status.account_key_remembered} onclick={forgetKey}>Forget</button>
      </div>
    </section>

    <section class="last">
      <div class="spread">
        <div class="label">
          <h3>Sign out</h3>
          <p class="faint">
            Locks the vault and removes everything TruePassword keeps in this
            Mac's keychain. Your data stays on disk; you will need your master
            password and recovery key to get back in.
          </p>
        </div>
        <button class="danger" disabled={busy} onclick={signOut}>Sign out</button>
      </div>
    </section>
  </div>
</div>

<style>
  .settings { height: 100%; display: flex; flex-direction: column; }
  .head { padding: 18px 22px 14px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  h2 { font-size: 15px; font-weight: 600; margin: 0; }
  .body { padding: 6px 22px 40px; overflow-y: auto; flex: 1; }
  section { padding: 18px 0; border-bottom: 1px solid var(--border); }
  section.last { border-bottom: none; }
  .spread { gap: 24px; align-items: flex-start; }
  .label { min-width: 0; }
  h3 { font-size: 13px; font-weight: 560; margin: 0 0 4px; }
  .label p { margin: 0; font-size: 12px; line-height: 1.55; max-width: 44ch; }
  button { flex-shrink: 0; }
  .pairing {
    border: 1px solid color-mix(in srgb, var(--accent) 45%, transparent);
    background: color-mix(in srgb, var(--accent) 9%, transparent);
    border-radius: var(--radius-lg);
    padding: 14px 16px;
    margin-top: 14px;
  }
  .pairing h3 { margin-bottom: 6px; }
  .pairing p { margin: 0 0 12px; max-width: 48ch; }
  .row { display: flex; gap: 8px; }
</style>
