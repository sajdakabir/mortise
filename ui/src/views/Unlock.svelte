<script lang="ts">
  import { ipc } from "../lib/ipc";
  import { errorMessage, isCmdError, type VaultStatus } from "../lib/types";

  let { status, onUnlocked }:
    { status: VaultStatus; onUnlocked: () => void } = $props();

  let password = $state("");
  let kit = $state("");
  let busy = $state(false);
  let error = $state("");

  // The recovery key is only needed on a Mac that has not saved it: a fresh
  // install, or after the user chose to forget it.
  const needsKit = $derived(!status.account_key_remembered);
  const canSubmit = $derived(!!password && (!needsKit || !!kit.trim()) && !busy);

  async function submit() {
    if (!canSubmit) return;
    busy = true;
    error = "";
    try {
      await ipc.unlock(password, needsKit ? kit : null);
      password = kit = "";
      onUnlocked();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function biometric() {
    busy = true;
    error = "";
    try {
      await ipc.unlockBiometric();
      onUnlocked();
    } catch (e) {
      // Dismissing the prompt is a shrug, not a failure. Showing a red banner
      // for it would be wrong.
      if (!(isCmdError(e) && e.code === "cancelled")) error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <div class="card">
    <h1>Unlock</h1>

    {#if error}<div class="error">{error}</div>{/if}

    {#if status.biometric_enabled}
      <button class="primary wide touchid" disabled={busy} onclick={biometric}>
        Unlock with Touch ID
      </button>
      <div class="or"><span>or</span></div>
    {/if}

    <div class="field">
      <label for="pw">Master password</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="pw" type="password" bind:value={password} autofocus autocomplete="current-password"
        onkeydown={(e) => e.key === "Enter" && !needsKit && submit()} />
    </div>

    {#if needsKit}
      <div class="field">
        <label for="kit">Recovery key</label>
        <input id="kit" class="mono" bind:value={kit} placeholder="TP1-…" spellcheck="false"
          onkeydown={(e) => e.key === "Enter" && submit()} />
        <p class="faint hint">
          Saved to this Mac's keychain after this, so you only type it once.
        </p>
      </div>
    {/if}

    <button class="primary wide" disabled={!canSubmit} onclick={submit}>
      {busy ? "Unlocking…" : "Unlock"}
    </button>
  </div>
</div>

<style>
  .wrap { height: 100%; display: grid; place-items: center; padding: 24px; }
  .card { width: 100%; max-width: 380px; }
  h1 { font-size: 19px; font-weight: 600; margin: 0 0 22px; }
  .wide { width: 100%; padding: 9px; }
  .touchid { margin-bottom: 4px; }
  .or {
    display: flex; align-items: center; gap: 10px;
    margin: 16px 0; color: var(--text-faint); font-size: 11px;
  }
  .or::before, .or::after { content: ""; flex: 1; height: 1px; background: var(--border); }
  .hint { font-size: 11px; margin: 6px 0 0; line-height: 1.5; }
</style>
