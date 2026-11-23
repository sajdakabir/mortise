<script lang="ts">
  /// Approve a `mortise run` asking for an environment's secrets.
  ///
  /// Mounted by the app shell, like the pairing prompt, so it can be
  /// answered from any screen. Shows one request at a time, oldest first;
  /// answering one brings up the next.
  ///
  /// What is shown, and how far to trust it:
  /// - directory and process chain: from the kernel, so trustworthy;
  /// - command: what the caller *says* it is about to run, labelled as such.
  import { ipc, onCliQueueChanged } from "./ipc";
  import SecurityDialog from "./SecurityDialog.svelte";
  import { errorMessage, type CliAnswer, type CliRequest } from "./types";

  let request = $state<CliRequest | null>(null);
  let busy = $state(false);
  let error = $state("");

  async function refresh() {
    try {
      request = await ipc.pendingCliRequest();
    } catch {
      request = null;
    }
  }

  $effect(() => {
    let stop: (() => void) | undefined;
    onCliQueueChanged(refresh).then((fn) => { stop = fn; }).catch(() => {});
    refresh();
    return () => stop?.();
  });

  async function answer(choice: CliAnswer) {
    if (!request || busy) return;
    busy = true;
    error = "";
    try {
      await ipc.answerCliRequest(request.id, choice);
    } catch (e) {
      // Usually "no longer waiting": the command timed out. Say so briefly,
      // then move on to whatever is next.
      error = errorMessage(e);
    } finally {
      busy = false;
      await refresh();
    }
  }

  let what = $derived(
    request?.keys
      ? `${request.keys.length} secret${request.keys.length === 1 ? "" : "s"} (${request.keys.join(", ")})`
      : "every secret",
  );
</script>

{#if request}
  <SecurityDialog label="Command-line access">
    {#if request.kind === "session"}
      <h2>Start an agent session for {request.project} / {request.environment}?</h2>
      <p>
        Until the agent exits, or for 8 hours, anything it runs with
        <code>mortise run</code> can read every secret in that environment
        without asking. Nothing outside the agent is covered, even in the same
        directory.
      </p>
    {:else}
      <h2>Let a command read {request.project} / {request.environment}?</h2>
      <p>It is asking for {what} from that environment.</p>
    {/if}
    <dl>
      <dt>Directory</dt>
      <dd><code>{request.directory}</code></dd>
      <dt>Started by</dt>
      <dd><code>{request.process_chain.join(" ← ")}</code></dd>
      <dt>{request.kind === "session" ? "Says the agent is" : "Says it will run"}</dt>
      <dd><code>{request.command || "—"}</code></dd>
    </dl>
    {#if request.kind === "session"}
      <p class="faint">Start this only if you just launched that agent with <code>mortise agent</code>.</p>
    {:else}
      <p class="faint">
        Allow this only if you just ran it yourself, or asked an agent to.
        “For 8 hours” covers anything run from that directory until then, or
        until you revoke it in Settings.
      </p>
    {/if}
    {#if error}<p class="err">{error}</p>{/if}
    <div class="row">
      <button disabled={busy} onclick={() => answer("deny")}>Deny</button>
      {#if request.kind === "session"}
        <button class="primary" disabled={busy} onclick={() => answer("for_eight_hours")}>Start session</button>
      {:else}
        <button disabled={busy} onclick={() => answer("for_eight_hours")}>Allow for 8 hours</button>
        <button class="primary" disabled={busy} onclick={() => answer("once")}>Allow once</button>
      {/if}
    </div>
  </SecurityDialog>
{/if}

<style>
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 12px;
    margin: 4px 0 14px;
    font-size: 12px;
  }
  dt { color: var(--text-faint); }
  dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
  code { font-size: 11.5px; }
</style>
