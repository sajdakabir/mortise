<script lang="ts">
  /// The approve-this-browser dialog.
  ///
  /// Mounted by the app shell rather than by any one screen. It used to live
  /// inside Settings, which meant the listener only existed while Settings was
  /// open: click Pair in the browser from anywhere else and the request landed
  /// in app state with nothing on screen able to accept it. The extension then
  /// waited forever for an approval the user was never offered.
  ///
  /// A pairing request is the app asking the human a question. It belongs over
  /// whatever they are looking at.
  import { ipc, onBrowserPairingRequest } from "./ipc";
  import { errorMessage } from "./types";

  let { onPaired }: { onPaired?: () => void } = $props();

  let name = $state<string | null>(null);
  let busy = $state(false);
  let error = $state("");

  /// Live requests.
  $effect(() => {
    let stop: (() => void) | undefined;
    onBrowserPairingRequest((requester) => { name = requester; })
      .then((fn) => { stop = fn; })
      .catch(() => {});
    return () => stop?.();
  });

  /// And one that arrived before anything was listening.
  $effect(() => {
    ipc.pendingBrowser().then((p) => { if (p && !name) name = p; }).catch(() => {});
  });

  async function approve() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      await ipc.approveBrowser();
      name = null;
      onPaired?.();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function reject() {
    if (busy) return;
    busy = true;
    try {
      await ipc.rejectBrowser();
      name = null;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if name}
  <!-- No backdrop dismissal and no Escape. Every other dialog in the app can
       be waved away; this one is a security decision, and "I clicked outside
       it" is not an answer to it. -->
  <div class="backdrop">
    <div class="panel" role="dialog" aria-modal="true" aria-label="Pair browser" tabindex="-1">
      <h2>Pair with {name}?</h2>
      <p>
        This browser will be able to ask for logins matching the page you are
        on, and only after you pick one each time.
      </p>
      <p class="faint">
        Approve this only if you just clicked Pair in that browser. Nothing
        else on this Mac can reach your vault without it.
      </p>
      {#if error}<p class="err">{error}</p>{/if}
      <div class="row">
        <button disabled={busy} onclick={reject}>Not now</button>
        <button class="primary" disabled={busy} onclick={approve}>
          {busy ? "…" : "Approve"}
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
    /* Above the item editor: a pairing request that opened while a form was
       up still has to be answerable. */
    z-index: 40;
  }
  .panel {
    width: 100%;
    max-width: 400px;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5);
    padding: 20px 22px 18px;
  }
  h2 { font-size: 15px; font-weight: 600; margin: 0 0 10px; }
  p { font-size: 12px; line-height: 1.55; margin: 0 0 10px; }
  .err { color: var(--danger); }
  .row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
</style>
