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
  import SecurityDialog from "./SecurityDialog.svelte";
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
  <SecurityDialog label="Pair browser">
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
  </SecurityDialog>
{/if}
