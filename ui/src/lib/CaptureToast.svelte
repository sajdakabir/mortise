<script lang="ts">
  /// Saves a submitted login straight away and says so, with an undo.
  ///
  /// This used to be a dialog that asked first. Asking is the safer default in
  /// the abstract — the extension is semi-trusted, and a prompt means only a
  /// human ever commits to the vault — but in practice a modal after every
  /// sign-in is friction on the one flow that has to be effortless, and a
  /// prompt people learn to dismiss protects nobody.
  ///
  /// So it saves, and offers to take it back. The window of regret is the
  /// same; the cost when you *do* want it saved, which is almost always, is
  /// zero. A wrongly-saved item is recoverable, which is what makes this a
  /// reasonable trade rather than a shortcut.
  ///
  /// The password still never enters this webview: `save_capture` reads it
  /// from Rust-side state and only the item id comes back.
  import { ipc, onLoginCaptured } from "./ipc";
  import { errorMessage } from "./types";

  let { onChanged }: { onChanged?: () => void } = $props();

  let saved = $state<{ id: string; label: string } | null>(null);
  let error = $state("");
  let timer: ReturnType<typeof setTimeout> | undefined;

  function hostOf(origin: string): string {
    return origin.replace(/^[a-z]+:\/\//, "").replace(/\/$/, "");
  }

  function dismissLater() {
    clearTimeout(timer);
    // Long enough to notice and act on, short enough not to sit over the UI.
    timer = setTimeout(() => { saved = null; }, 8000);
  }

  async function saveNow() {
    const pending = await ipc.pendingCapture();
    if (!pending) return;
    try {
      const id = await ipc.saveCapture(null);
      saved = { id, label: hostOf(pending.origin) };
      error = "";
      onChanged?.();
      dismissLater();
    } catch (e) {
      // Locked vaults and the like. Worth showing: the user just typed a
      // password expecting it to be kept, and silence would be a lie.
      error = errorMessage(e);
      dismissLater();
    }
  }

  $effect(() => {
    let stop: (() => void) | undefined;
    onLoginCaptured(() => { saveNow(); })
      .then((fn) => { stop = fn; })
      .catch(() => {});
    return () => { stop?.(); clearTimeout(timer); };
  });

  // One that arrived before anything was listening.
  $effect(() => { saveNow(); });

  async function undo() {
    if (!saved) return;
    const { id } = saved;
    saved = null;
    clearTimeout(timer);
    try {
      await ipc.deleteItem(id);
      onChanged?.();
    } catch (e) {
      error = errorMessage(e);
      dismissLater();
    }
  }
</script>

{#if saved || error}
  <div class="toast" class:bad={Boolean(error)} role="status">
    {#if error}
      <span>{error}</span>
      <button class="link" onclick={() => (error = "")}>Dismiss</button>
    {:else if saved}
      <span>Saved <strong>{saved.label}</strong></span>
      <button class="link" onclick={undo}>Undo</button>
    {/if}
  </div>
{/if}

<style>
  .toast {
    position: fixed;
    left: 50%;
    bottom: 22px;
    transform: translateX(-50%);
    display: flex;
    align-items: center;
    gap: 14px;
    max-width: calc(100% - 40px);
    padding: 10px 14px;
    font-size: 12.5px;
    background: var(--bg-raised);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
    z-index: 30;
  }
  .toast.bad { border-color: var(--danger); color: var(--danger); }
  strong { font-weight: 600; }
  .link {
    border: 0;
    background: none;
    padding: 0;
    font-size: 12.5px;
    font-weight: 600;
    color: var(--text);
    cursor: pointer;
  }
  .link:hover { text-decoration: underline; }
</style>
