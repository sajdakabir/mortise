<script lang="ts">
  import { untrack } from "svelte";
  import { ipc } from "./ipc";
  import { errorMessage } from "./types";

  type Target = { id: string; name: string };
  type Pending = NonNullable<Awaited<ReturnType<typeof ipc.pendingProjectJoin>>>;
  type Session = {
    target: Target; link: string; pending: Pending | null;
    role: "viewer" | "member" | "admin";
    phase: "waiting" | "pending" | "granted" | "declined";
    error: string;
  };
  let { target = $bindable(null), join = $bindable(null), unlocked, hidden = false,
    onUnlock, onSettings, onChanged }: {
    target: Target | null; join: string | null; unlocked: boolean; hidden?: boolean;
    onUnlock: () => void; onSettings: () => void; onChanged: () => void;
  } = $props();

  // This component lives above the workspaces, so requests still arrive after
  // dismissing a dialog or switching tabs. Bearer links stay in memory only.
  let sessions = $state<Record<string, Session>>({});
  const active = $derived(target ? sessions[target.id] : undefined);
  let relay = $state<"checking" | "ready" | "missing">("checking");
  let busy = $state(false);
  let error = $state("");
  let copied = $state(false);
  let joinInput = $state("");
  let name = $state(localStorage.getItem("mortise.displayName") ?? "");
  let joinState = $state<{
    link: string;
    preview: Awaited<ReturnType<typeof ipc.inspectProjectInvite>> | null;
    phase: "review" | "waiting" | "joined";
    error: string;
  } | null>(null);

  $effect(() => {
    const id = target?.id;
    if (!id || !unlocked) return;
    let cancelled = false;
    relay = "checking";
    error = "";
    copied = false;
    ipc.syncStatus().then((s) => {
      if (!cancelled) relay = s.relay_url ? "ready" : "missing";
    }).catch((e) => { if (!cancelled) { relay = "missing"; error = errorMessage(e); } });
    return () => { cancelled = true; };
  });

  $effect(() => {
    const link = join;
    if (link === null) return;
    untrack(() => {
      target = null;
      if (joinState?.link === link && link) return;
      joinState = null;
      joinInput = link;
      error = "";
      if (link) void inspect(link);
    });
  });

  // One serial loop, only while unlocked. Cancellation discards late replies
  // after a lock/unmount; errors retry slowly without issuing overlapping calls.
  $effect(() => {
    if (!unlocked) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      let failed = false;
      for (const session of Object.values(sessions)) {
        if (cancelled) return;
        if (session.phase !== "waiting") continue;
        try {
          const pending = await ipc.pendingProjectJoin(session.link);
          if (cancelled || session.phase !== "waiting") return;
          session.error = "";
          if (pending) {
            session.pending = pending;
            session.phase = "pending";
            if (!target && join === null) target = session.target;
          }
        } catch (e) {
          if (cancelled) return;
          session.error = errorMessage(e);
          failed = true;
        }
      }
      const waiting = joinState;
      if (waiting?.phase === "waiting" && !cancelled) {
        try {
          const done = await ipc.completeProjectJoin(waiting.link);
          if (cancelled || joinState !== waiting) return;
          waiting.error = "";
          if (done) {
            waiting.phase = "joined";
            if (!target) join = waiting.link;
            onChanged();
          }
        } catch (e) {
          if (cancelled) return;
          waiting.error = errorMessage(e);
          failed = true;
        }
      }
      if (!cancelled) timer = setTimeout(poll, failed ? 15_000 : 3_000);
    };
    timer = setTimeout(poll, 1000);
    return () => { cancelled = true; clearTimeout(timer); };
  });

  async function createLink() {
    if (!target || !unlocked || busy || relay !== "ready") return;
    const selected = target;
    busy = true; error = "";
    try {
      // No profile form for the sender. Their certified identity is unchanged.
      const link = await ipc.createProjectInvite(selected.id, "Project owner");
      sessions[selected.id] = { target: selected, link, pending: null,
        role: "viewer", phase: "waiting", error: "" };
      onChanged();
    } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }

  async function copyLink() {
    if (!active || !unlocked) return;
    try { await navigator.clipboard.writeText(active.link); copied = true; }
    catch (e) { error = errorMessage(e); }
  }

  async function decide(allow: boolean) {
    if (!active?.pending || busy || !unlocked) return;
    const session = active;
    const request = session.pending!;
    busy = true; error = "";
    try {
      if (allow) await ipc.grantProjectJoin(session.link, session.role, request.request_token);
      else await ipc.declineProjectJoin(session.link);
      session.phase = allow ? "granted" : "declined";
      session.pending = null;
    } catch (e) {
      error = errorMessage(e);
      // A changed request must be fetched and displayed before another approval.
      if (allow) { session.pending = null; session.phase = "waiting"; }
    } finally { busy = false; }
  }

  async function inspect(link: string) {
    const state = { link: link.trim(), preview: null, phase: "review", error: "" } as NonNullable<typeof joinState>;
    joinState = state;
    try {
      const preview = await ipc.inspectProjectInvite(state.link);
      if (joinState?.link === state.link) joinState.preview = preview;
    } catch (e) { if (joinState?.link === state.link) joinState.error = errorMessage(e); }
  }

  async function requestAccess() {
    if (!joinState?.preview || !unlocked || !name.trim() || busy) return;
    const state = joinState;
    busy = true; error = "";
    try {
      await ipc.requestProjectAccess(state.link, name.trim());
      localStorage.setItem("mortise.displayName", name.trim());
      state.phase = "waiting";
    } catch (e) { state.error = errorMessage(e); }
    finally { busy = false; }
  }

  function close() { target = null; join = null; error = ""; }
  function keyboard(event: KeyboardEvent) {
    if (event.key === "Escape") { event.stopPropagation(); close(); }
    if (event.key !== "Tab") return;
    const panel = event.currentTarget as HTMLElement;
    const controls = Array.from(panel.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), summary"))
      .filter((element) => element.getClientRects().length > 0);
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
      event.preventDefault(); last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first?.focus();
    }
  }
  function focusPanel(node: HTMLElement) {
    const previous = document.activeElement as HTMLElement | null;
    node.focus();
    return { destroy() { if (previous?.isConnected) previous.focus(); } };
  }
</script>

{#if !hidden && (target || join !== null)}
  <div class="backdrop" role="presentation" onclick={close}></div>
  <div class="dialog" role="dialog" aria-modal="true" aria-label={target ? "Share project" : "Join project"}
    tabindex="-1" onkeydown={keyboard} use:focusPanel>
    <div class="heading"><strong>{target ? `Share ${target.name}` : "Join a project"}</strong>
      <button class="ghost tiny" onclick={close} aria-label="Close sharing">✕</button></div>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    {#if !unlocked}
      <p>Unlock Mortise to continue.</p>
      <div class="actions"><button class="primary" onclick={onUnlock}>Unlock</button></div>
    {:else if target}
      {#if active?.phase === "granted"}
        <p role="status">Access allowed. They can now finish joining.</p>
        <div class="actions"><button onclick={close}>Done</button></div>
      {:else if active?.phase === "declined"}
        <p role="status">Request declined. This link can no longer be used.</p>
        <div class="actions"><button onclick={close}>Done</button></div>
      {:else if active?.pending}
        <p><strong>{active.pending.name}</strong> wants access to this project.</p>
        <div class="field"><label for="share-role">Access</label>
          <select id="share-role" bind:value={active.role} disabled={busy}>
            <option value="viewer">Can view and copy</option>
            <option value="member">Can edit secrets</option>
            <option value="admin">Can manage access</option>
          </select></div>
        <details><summary>Verify their identity</summary>
          <p>Confirm this fingerprint with the person before allowing access. Names are self-chosen.</p>
          <code>{active.pending.fingerprint}</code>
        </details>
        <div class="actions"><button disabled={busy} onclick={() => decide(false)}>Decline</button>
          <button class="primary" disabled={busy} onclick={() => decide(true)}>{busy ? "Saving…" : "Allow access"}</button></div>
      {:else if active}
        <p>Send this link. You’ll be asked before anyone gets access.</p>
        <div class="link-row"><input aria-label="Invite link" readonly value={active.link} spellcheck="false" />
          <button class="primary" onclick={copyLink}>{copied ? "Copied" : "Copy link"}</button></div>
        <p class="caption" role="status">Waiting for a request · Keep Mortise open</p>
        {#if active.error}<p class="caption error">{active.error} Retrying automatically.</p>{/if}
      {:else}
        <p>Share a link. They request access. You decide.</p>
        <p class="caption">Includes all environments in this project.</p>
        <details><summary>Preview — use a test project</summary>
          <p>Shared projects are not visible in the project list yet. Creating a link moves this project to a separate vault. Test with dummy secrets until navigation is complete.</p>
        </details>
        {#if relay === "missing"}
          <p class="caption">Sharing needs a one-time connection setup.</p>
          <div class="actions"><button onclick={() => { close(); onSettings(); }}>Set up sharing</button></div>
        {:else}
          <div class="actions"><button class="primary" disabled={busy || relay !== "ready"} onclick={createLink}>
            {busy ? "Creating link…" : relay === "checking" ? "Checking…" : "Create link"}</button></div>
        {/if}
      {/if}
    {:else if joinState?.phase === "joined"}
      <p role="status">Access approved. The encrypted project has been downloaded.</p>
      <p class="caption">Preview: shared-project navigation is still being built.</p>
      <div class="actions"><button onclick={close}>Done</button></div>
    {:else if joinState?.phase === "waiting"}
      <p role="status">Request sent. Waiting for the owner to approve.</p>
      <p class="caption">Keep Mortise open. We’ll check automatically.</p>
      {#if joinState.error}<p class="error">{joinState.error} Retrying automatically.</p>{/if}
    {:else if joinState?.preview}
      <p>Request access to <strong>{joinState.preview.project_name}</strong>?</p>
      <div class="field"><label for="join-name">Your name</label>
        <input id="join-name" bind:value={name} maxlength="64" autocomplete="name" placeholder="So the owner knows who is asking" /></div>
      <details><summary>Verify the invitation</summary>
        <p>Invited by {joinState.preview.inviter_name}. Confirm this fingerprint and the full invitation with them.</p>
        <code>{joinState.preview.fingerprint}</code>
      </details>
      {#if joinState.error}<p class="error">{joinState.error}</p>{/if}
      <div class="actions"><button onclick={close}>Not now</button>
        <button class="primary" disabled={busy || !name.trim()} onclick={requestAccess}>{busy ? "Sending…" : "Request access"}</button></div>
    {:else}
      <p>Paste the invitation you received.</p>
      <input aria-label="Invite link" bind:value={joinInput} placeholder="mortise://join#…" spellcheck="false" />
      {#if joinState?.error}<p class="error" role="alert">{joinState.error}</p>{/if}
      <div class="actions"><button class="primary" disabled={!joinInput.trim()} onclick={() => inspect(joinInput)}>Continue</button></div>
    {/if}
  </div>
{/if}

<style>
  .backdrop { position: fixed; inset: 0; z-index: 40; background: rgb(0 0 0 / 55%); }
  .dialog { position: fixed; z-index: 41; top: 50%; left: 50%; transform: translate(-50%, -50%);
    width: min(440px, calc(100vw - 40px)); max-height: calc(100vh - 48px); overflow-y: auto;
    padding: 24px; background: var(--bg-raised); border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg); box-shadow: var(--shadow-3); }
  .heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; }
  .heading strong { overflow-wrap: anywhere; }
  p { font-size: 13px; line-height: 1.6; margin: 0 0 16px; }
  .caption, details { color: var(--text-dim); font-size: 12px; }
  details { margin: 16px 0; line-height: 1.6; }
  details p { font-size: 12px; margin: 10px 0; }
  summary { cursor: pointer; }
  code { display: block; overflow-wrap: anywhere; font-size: 12px; padding: 10px; background: var(--bg-input); border-radius: var(--radius); }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; }
  .link-row { display: flex; gap: 8px; margin-bottom: 12px; }
  .link-row input { min-width: 0; font: 12px var(--mono); }
  .link-row button { flex-shrink: 0; }
</style>
