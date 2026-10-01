<script lang="ts">
  import { ipc } from "../lib/ipc";
  import { errorMessage, isCmdError, type VaultStatus } from "../lib/types";

  let { status, onStatus, onClose }:
    { status: VaultStatus; onStatus: (s: VaultStatus) => void; onClose: () => void } = $props();

  let error = $state("");
  let busy = $state(false);

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
</style>
