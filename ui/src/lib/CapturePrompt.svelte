<script lang="ts">
  /// "Save this login?" after the browser sees one submitted.
  ///
  /// Mounted by the app shell for the same reason the pairing prompt is: the
  /// browser can offer a login at any moment, and an approval that only
  /// exists on one screen is one the user will never be shown.
  ///
  /// The password is never sent here. The webview gets the origin and the
  /// username, and `save_capture` reads the secret from Rust-side state — so
  /// the thing being saved never enters the JS heap.
  import { ipc, onLoginCaptured } from "./ipc";
  import { errorMessage, type CaptureSummary } from "./types";

  let { onSaved }: { onSaved?: () => void } = $props();

  let capture = $state<CaptureSummary | null>(null);
  let title = $state("");
  let busy = $state(false);
  let error = $state("");

  /// `https://github.com` reads better as `github.com` in a name field.
  function hostOf(origin: string): string {
    return origin.replace(/^[a-z]+:\/\//, "").replace(/\/$/, "");
  }

  async function load() {
    try {
      const pending = await ipc.pendingCapture();
      if (pending) {
        capture = pending;
        title = hostOf(pending.origin);
      }
    } catch {
      capture = null;
    }
  }

  $effect(() => {
    let stop: (() => void) | undefined;
    onLoginCaptured(() => { load(); })
      .then((fn) => { stop = fn; })
      .catch(() => {});
    return () => stop?.();
  });

  // And one that arrived before anything was listening.
  $effect(() => { load(); });

  async function save() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      await ipc.saveCapture(title.trim() || null);
      capture = null;
      onSaved?.();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function discard() {
    if (busy) return;
    busy = true;
    try {
      await ipc.discardCapture();
      capture = null;
    } finally {
      busy = false;
    }
  }
</script>

{#if capture}
  <div class="backdrop">
    <div class="panel" role="dialog" aria-modal="true" aria-label="Save login" tabindex="-1">
      <h2>Save this login?</h2>
      <p class="faint">
        {hostOf(capture.origin)}{#if capture.username} · {capture.username}{/if}
      </p>

      <label for="captitle">Name</label>
      <input
        id="captitle"
        bind:value={title}
        onkeydown={(e) => { if (e.key === "Enter") save(); }} />

      {#if error}<p class="err">{error}</p>{/if}

      <div class="row">
        <button disabled={busy} onclick={discard}>Not now</button>
        <button class="primary" disabled={busy} onclick={save}>
          {busy ? "…" : "Save"}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: grid;
    place-items: center;
    padding: 32px 20px;
    /* Below the pairing prompt, above everything else. */
    z-index: 35;
  }
  .panel {
    width: 100%;
    max-width: 380px;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5);
    padding: 20px 22px 18px;
  }
  h2 { font-size: 15px; font-weight: 600; margin: 0 0 6px; }
  p { font-size: 12px; line-height: 1.5; margin: 0 0 16px; }
  label { display: block; font-size: 11px; color: var(--text-dim); margin-bottom: 5px; }
  .err { color: var(--danger); margin: 10px 0 0; }
  .row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
</style>
