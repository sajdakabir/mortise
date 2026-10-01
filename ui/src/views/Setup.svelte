<script lang="ts">
  import { ipc } from "../lib/ipc";
  import { errorMessage } from "../lib/types";

  let { onDone }: { onDone: () => void } = $props();

  let password = $state("");
  let confirm = $state("");
  let busy = $state(false);
  let error = $state("");
  let kit = $state("");
  let acknowledged = $state(false);

  const tooShort = $derived(password.length > 0 && password.length < 8);
  const mismatch = $derived(confirm.length > 0 && password !== confirm);
  const canCreate = $derived(password.length >= 8 && password === confirm && !busy);

  async function create() {
    busy = true;
    error = "";
    try {
      kit = (await ipc.createVault(password)).recovery_kit;
      password = confirm = "";
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <div class="card">
    {#if !kit}
      <h1>Set up TruePassword</h1>
      <p class="dim intro">
        Everything stays on this Mac. Your master password is never stored and never
        leaves the device.
      </p>

      {#if error}<div class="error">{error}</div>{/if}

      <div class="field">
        <label for="pw">Master password</label>
        <input id="pw" type="password" bind:value={password} autocomplete="new-password" />
        {#if tooShort}<p class="hint warn">At least 8 characters.</p>{/if}
      </div>

      <div class="field">
        <label for="pw2">Confirm</label>
        <input id="pw2" type="password" bind:value={confirm} autocomplete="new-password"
          onkeydown={(e) => e.key === "Enter" && canCreate && create()} />
        {#if mismatch}<p class="hint warn">These do not match.</p>{/if}
      </div>

      <button class="primary wide" disabled={!canCreate} onclick={create}>
        {busy ? "Creating…" : "Create vault"}
      </button>
    {:else}
      <h1>Save your recovery key</h1>
      <p class="dim intro">
        You need this <strong>and</strong> your master password to unlock. It is shown
        once and cannot be retrieved later.
      </p>

      <div class="kit mono">{kit}</div>

      <div class="note">
        If you lose both this key and your password, your data is gone. There is no
        reset and no support path — that is the design, not an oversight.
      </div>

      <label class="ack">
        <input type="checkbox" bind:checked={acknowledged} />
        <span>I have written this down somewhere safe.</span>
      </label>

      <button class="primary wide" disabled={!acknowledged} onclick={onDone}>Continue</button>
    {/if}
  </div>
</div>

<style>
  .wrap { height: 100%; display: grid; place-items: center; padding: 24px; }
  .card { width: 100%; max-width: 420px; }
  h1 { font-size: 19px; font-weight: 600; margin: 0 0 8px; }
  .intro { margin: 0 0 22px; font-size: 12.5px; line-height: 1.6; }
  .wide { width: 100%; padding: 9px; }
  .hint { font-size: 11px; margin: 6px 0 0; }
  .warn { color: var(--warn); }
  .kit {
    background: var(--bg-input);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    padding: 14px;
    font-size: 13px;
    line-height: 1.9;
    word-break: break-all;
    user-select: all;
    margin-bottom: 14px;
  }
  .ack { display: flex; gap: 9px; align-items: flex-start; margin: 16px 0 18px; font-size: 12px; color: var(--text); }
  .ack input { width: auto; margin-top: 1px; }
</style>
