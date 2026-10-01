<script lang="ts">
  import { ipc } from "../lib/ipc";
  import { errorMessage } from "../lib/types";

  let { onUnlocked }: { onUnlocked: () => void } = $props();

  let password = $state("");
  let kit = $state("");
  let busy = $state(false);
  let error = $state("");

  async function submit() {
    if (!password || !kit || busy) return;
    busy = true;
    error = "";
    try {
      await ipc.unlock(password, kit);
      password = "";
      onUnlocked();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <div class="card">
    <h1>Unlock</h1>

    {#if error}<div class="error">{error}</div>{/if}

    <div class="field">
      <label for="pw">Master password</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="pw" type="password" bind:value={password} autofocus autocomplete="current-password" />
    </div>

    <div class="field">
      <label for="kit">Recovery key</label>
      <input id="kit" class="mono" bind:value={kit} placeholder="TP1-…" spellcheck="false"
        onkeydown={(e) => e.key === "Enter" && submit()} />
    </div>

    <button class="primary wide" disabled={!password || !kit || busy} onclick={submit}>
      {busy ? "Unlocking…" : "Unlock"}
    </button>

    <p class="footnote faint">
      Asking for the recovery key every time is temporary. It belongs in the macOS
      keychain behind Touch ID — that work is scheduled, and stashing it anywhere
      less safe in the meantime would be worse than the inconvenience.
    </p>
  </div>
</div>

<style>
  .wrap { height: 100%; display: grid; place-items: center; padding: 24px; }
  .card { width: 100%; max-width: 380px; }
  h1 { font-size: 19px; font-weight: 600; margin: 0 0 22px; }
  .wide { width: 100%; padding: 9px; }
  .footnote { font-size: 11px; line-height: 1.6; margin: 20px 0 0; }
</style>
