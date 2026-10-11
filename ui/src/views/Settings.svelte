<script lang="ts">
  import { ipc } from "../lib/ipc";
  import { open } from "@tauri-apps/plugin-dialog";
  import {
    errorMessage, isCmdError,
    type ImportReport, type PairedBrowser, type SyncStatus, type VaultStatus,
  } from "../lib/types";

  let { status, onStatus, onClose }:
    { status: VaultStatus; onStatus: (s: VaultStatus) => void; onClose: () => void } = $props();

  let error = $state("");
  let busy = $state(false);

  let browsers = $state<PairedBrowser[]>([]);
  let sync = $state<SyncStatus | null>(null);
  let relayInput = $state("");
  let syncMessage = $state("");
  /// Set once Touch ID has been refused for want of a signed build.
  ///
  /// Not a failure the user can act on: an unsigned binary cannot create an
  /// access-controlled keychain item at all, so this is a property of the
  /// build rather than something that went wrong. Showing it in the red error
  /// banner for the whole pane said "something broke" about a feature that
  /// was never going to be available, every time.
  let biometricUnavailable = $state(false);
  let importing = $state(false);
  let importReport = $state<ImportReport | null>(null);
  let importError = $state("");

  async function refreshBrowsers() {
    browsers = await ipc.listBrowsers();
  }

  async function refreshSync() {
    sync = await ipc.syncStatus();
    relayInput = sync.relay_url ?? "";
  }

  async function saveRelay() {
    busy = true;
    error = "";
    syncMessage = "";
    try {
      sync = await ipc.setRelay(relayInput.trim() || null);
      relayInput = sync.relay_url ?? "";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function registerVault() {
    busy = true;
    error = "";
    try {
      await ipc.claimVaultOnRelay();
      syncMessage = "Registered with the relay.";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function syncNow() {
    busy = true;
    error = "";
    syncMessage = "";
    try {
      const r = await ipc.syncNow();
      syncMessage = `Sent ${r.pushed}, received ${r.pulled}, applied ${r.applied}.`;
      if (r.rejected > 0) {
        syncMessage += ` ${r.rejected} refused — the relay served changes this device could not verify.`;
      }
      await refreshSync();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  // The pairing prompt itself lives in the app shell, not here: a browser can
  // ask at any moment and the approval has to be reachable from any screen.
  $effect(() => {
    refreshBrowsers();
    refreshSync();
  });

  /// The picker hands back a path, never the file's bytes. Rust opens and
  /// parses it, so the plaintext export never enters this webview.
  async function importCsv() {
    if (importing) return;
    importError = "";
    importReport = null;

    const picked = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "CSV export", extensions: ["csv", "txt"] }],
    });
    if (typeof picked !== "string") return;

    importing = true;
    try {
      importReport = await ipc.importCsv(picked);
      onStatus(await ipc.status());
    } catch (e) {
      importError = errorMessage(e);
    } finally {
      importing = false;
    }
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
      if (isCmdError(e) && e.code === "requires_signed_app") {
        biometricUnavailable = true;
      } else if (!(isCmdError(e) && e.code === "cancelled")) {
        error = errorMessage(e);
      }
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

    <section>
      <h3>Sync</h3>
      <p class="faint">
        A relay stores your encrypted changes so your devices can reach each
        other. It cannot read any of them — but it does learn which devices sync
        together, and when. Leave this empty to keep everything on this Mac.
      </p>
      <div class="relay">
        <input
          class="mono"
          bind:value={relayInput}
          placeholder="https://relay.example"
          spellcheck="false" />
        <button disabled={busy} onclick={saveRelay}>Save</button>
      </div>
      {#if sync?.relay_url}
        <div class="row synced">
          <button disabled={busy} onclick={syncNow}>Sync now</button>
          <button disabled={busy} onclick={registerVault}>Register vault</button>
          <span class="faint">
            {sync.pending} waiting to send
          </span>
        </div>
        {#if syncMessage}<p class="faint result">{syncMessage}</p>{/if}
      {/if}
    </section>


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
        <button
          disabled={busy || !status.unlocked || biometricUnavailable}
          onclick={toggleBiometric}>
          {status.biometric_enabled ? "Turn off" : "Turn on"}
        </button>
      </div>

      {#if biometricUnavailable}
        <p class="note">
          Unavailable in this development build. Touch ID needs a signed copy
          of TruePassword — macOS will not let an unsigned app create a
          keychain item that asks for your fingerprint.
        </p>
      {/if}
    </section>

    <section>
      <div class="spread">
        <div class="label">
          <h3>Import from another manager</h3>
          <p class="faint">
            A CSV export from 1Password, Bitwarden, Chrome, LastPass or Safari.
            Items already here are skipped, so running it twice is safe.
          </p>
        </div>
        <button disabled={busy || importing || !status.unlocked} onclick={importCsv}>
          {importing ? "Importing…" : "Choose file"}
        </button>
      </div>

      {#if !status.unlocked}
        <p class="faint note">Unlock the vault first.</p>
      {/if}

      {#if importError}
        <p class="note bad">{importError}</p>
      {/if}

      {#if importReport}
        <p class="note good">
          {importReport.source}: imported {importReport.imported}
          {importReport.imported === 1 ? "item" : "items"}{#if importReport.duplicates}, skipped
            {importReport.duplicates} already here{/if}{#if importReport.unsupported}, skipped
            {importReport.unsupported} of a kind not supported yet{/if}{#if importReport.failed},
            {importReport.failed} failed{/if}.
        </p>
        <!-- The export is plaintext credentials sitting in Downloads. Saying
             so is the whole reason this line exists; an import flow that
             stays quiet about it leaves every password on disk unencrypted. -->
        <p class="note warnline">
          Delete the CSV now — it holds every one of those passwords in plain text.
        </p>
      {/if}
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
  .note { font-size: 12px; margin: 10px 0 0; line-height: 1.5; }
  .note.bad { color: var(--danger); }
  .note.good { color: var(--ok); }
  .note.warnline { color: var(--warn); }
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
  .row { display: flex; gap: 8px; }
  .relay { display: flex; gap: 8px; margin-top: 10px; }
  .relay input { flex: 1; }
  .synced { margin-top: 10px; align-items: center; }
  .result { margin: 9px 0 0; font-size: 12px; }
  section h3 + .faint { max-width: 52ch; }
</style>
