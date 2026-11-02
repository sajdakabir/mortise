<script lang="ts">
  import { onMount } from "svelte";
  import { ipc } from "./ipc";
  import { errorMessage, type AccountStatus, type AccountDashboard, type AccountDevice,
    type AccountAction, type TeamMember, type TeamRequest, type TeamInvitePreview } from "./types";

  let { unlocked, onUnlock, incoming = null, onInviteHandled }: {
    unlocked: boolean; onUnlock: () => void; incoming?: string | null; onInviteHandled: () => void;
  } = $props();
  let status = $state<AccountStatus | null>(null);
  let data = $state<AccountDashboard | null>(null);
  let opened = $state(false);
  let dialog = $state<HTMLDialogElement>();
  let view = $state<"teams" | "devices" | "create" | "invite" | "join" | "confirm">("teams");
  let busy = $state(false);
  let error = $state("");
  let message = $state("");
  let deviceName = $state("My Mac");
  let teamName = $state("");
  let teamId = $state("");
  let members = $state<TeamMember[]>([]);
  let requests = $state<TeamRequest[]>([]);
  let email = $state("");
  let role = $state("member");
  let invite = $state<{ id: string; link: string; expires_at: number } | null>(null);
  let link = $state("");
  let preview = $state<TeamInvitePreview | null>(null);
  let requested = $state(false);
  let confirmation = $state<{ title: string; description: string; fingerprint?: string; action: AccountAction } | null>(null);
  let revision = 0;
  let refreshing = false;
  let seenIncoming: string | null = null;
  const current = $derived(data?.devices.find(d => d.id === data?.current_device_id));
  const trusted = $derived(current?.status === "trusted");
  const team = $derived(data?.teams.find(t => t.id === teamId));
  const manager = $derived(team?.role === "owner" || team?.role === "admin");

  onMount(() => { void ipc.accountStatus().then(s => status = s).catch(e => error = errorMessage(e)); });
  $effect(() => {
    if (incoming !== null && incoming !== seenIncoming) {
      seenIncoming = incoming;
      link = incoming; preview = null; requested = false; view = "join"; opened = true;
    }
  });
  $effect(() => { if (opened) dialog?.showModal(); else dialog?.close(); });
  $effect(() => {
    if (!unlocked) {
      revision++; data = null; invite = null; preview = null; confirmation = null;
      members = []; requests = []; error = ""; message = "";
    }
  });
  $effect(() => {
    if (!opened || !unlocked || !status?.signed_in) return;
    void refresh();
    const timer = setInterval(() => { if (!busy) void refresh(); }, 5000);
    return () => { clearInterval(timer); revision++; };
  });

  function close() { opened = false; revision++; invite = null; confirmation = null; error = ""; message = ""; onInviteHandled(); }
  function navigate(next: typeof view) { revision++; view = next; error = ""; message = ""; confirmation = null; }
  async function refresh() {
    if (refreshing || !unlocked) return;
    refreshing = true;
    const rev = revision;
    try {
      const next = await ipc.accountAction<AccountDashboard>({ kind: "dashboard" });
      if (rev !== revision || !unlocked) return;
      data = next;
      if (!next.teams.some(t => t.id === teamId)) teamId = next.teams[0]?.id ?? "";
      if (requested && preview && next.teams.some(t => t.id === preview?.team_id)) {
        message = `You joined ${preview.team_name}.`; requested = false; preview = null; link = "";
      }
      if (teamId && next.devices.find(d => d.id === next.current_device_id)?.status === "trusted") {
        const selected = teamId;
        const [people, waiting] = await Promise.all([
          ipc.accountAction<TeamMember[]>({ kind: "members", team: selected }),
          ["owner", "admin"].includes(next.teams.find(t => t.id === selected)?.role ?? "")
            ? ipc.accountAction<TeamRequest[]>({ kind: "requests", team: selected }) : Promise.resolve([]),
        ]);
        if (rev === revision && selected === teamId && unlocked) { members = people; requests = waiting; }
      } else { members = []; requests = []; }
    } catch (e) { if (rev === revision) { error = errorMessage(e); status = await ipc.accountStatus(); } }
    finally { refreshing = false; }
  }
  async function run(work: () => Promise<void>) {
    if (busy) return;
    busy = true; error = ""; message = "";
    try { await work(); } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }
  async function signIn() {
    await run(async () => {
      await ipc.accountSignIn(deviceName.trim() || "My Mac");
      status = await ipc.accountStatus(); await refresh();
    });
  }
  async function signOut() {
    await run(async () => {
      await ipc.accountSignOut(); revision++; status = await ipc.accountStatus(); data = null;
      invite = null; preview = null; requested = false; link = ""; members = []; requests = []; view = "teams";
    });
  }
  function approveDevice(device: AccountDevice) {
    confirmation = { title: `Trust ${device.name}?`, description: "Compare this fingerprint with the one shown on that Mac before approving.",
      fingerprint: device.fingerprint, action: { kind: "approve_device", id: device.id, certificate: device.certificate } };
    view = "confirm";
  }
  async function confirm() {
    const choice = confirmation;
    if (!choice) return;
    await run(async () => {
      await ipc.accountAction(choice.action); confirmation = null;
      view = choice.action.kind.includes("device") ? "devices" : "teams";
      await refresh(); message = "Updated.";
    });
  }
  async function createTeam() {
    await run(async () => {
      const created = await ipc.accountAction<{ id: string }>({ kind: "create_team", name: teamName.trim() });
      teamId = created.id; teamName = ""; view = "teams"; await refresh();
    });
  }
  async function createInvite() {
    const selected = teamId, rev = revision;
    await run(async () => {
      const result = await ipc.accountAction<{ id: string; link: string; expires_at: number }>({ kind: "invite", team: selected, email: email.trim() || null, role });
      if (rev === revision && unlocked && opened) invite = result;
    });
  }
  async function inspect() {
    const candidate = link.trim(), rev = revision;
    await run(async () => {
      const result = await ipc.accountAction<TeamInvitePreview>({ kind: "preview_invite", link: candidate });
      if (rev === revision && unlocked && candidate === link.trim()) { preview = result; requested = false; }
    });
  }
  async function requestJoin() {
    await run(async () => {
      await ipc.accountAction({ kind: "request_invite", link: link.trim() }); requested = true;
    });
  }
</script>

<section class="account-card">
  <div><h3>Account &amp; teams</h3><p class="faint">Sign in to manage your devices and team invitations. Your vault stays on this Mac.</p></div>
  {#if status?.configured}
    <button class="outline" onclick={() => { opened = true; view = "teams"; }}>{status.signed_in ? "Manage account" : "Sign in"}</button>
  {:else if status}
    <p class="small faint">Account service is not configured in this build. Local passwords and secrets work without it.</p>
  {:else}<p class="small faint">{error || "Checking account service…"}</p>{/if}
</section>

<dialog bind:this={dialog} aria-labelledby="account-title" oncancel={(e) => { e.preventDefault(); close(); }} onclick={(e) => { if (e.target === dialog) close(); }}>
  <div class="panel" role="presentation">
    <header><div><p class="eyebrow">MORTISE</p><h2 id="account-title">Account &amp; teams</h2></div><button class="ghost" aria-label="Close account" onclick={close}>Close</button></header>
    <div class="content">
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      {#if message}<p class="notice" role="status">{message}</p>{/if}
      {#if !status?.configured}
        <p>Account service is not configured in this build.</p>
      {:else if !unlocked}
        <p>Unlock this Mac’s vault to use its device identity.</p><button class="primary" onclick={onUnlock}>Unlock vault</button>
      {:else if !status.signed_in}
        <p class="faint">Continue in your browser to sign in or create an account.</p>
        <label>This device’s name<input bind:value={deviceName} maxlength="80" autocomplete="off" /></label>
        <button class="primary" disabled={busy || !deviceName.trim()} onclick={signIn}>{busy ? "Waiting for browser…" : "Continue in browser"}</button>
        <p class="small faint">Account sign-in does not unlock or upload your vault.</p>
      {:else}
        <div class="identity"><span>{data?.account.email ?? "Loading account…"}</span><button class="ghost" disabled={busy} onclick={signOut}>Sign out</button></div>
        {#if data && !trusted}
          <div class="notice"><strong>Approve this Mac from a trusted device</strong><p>Open Account &amp; teams → Devices on your other Mac and compare this fingerprint.</p><code class="fingerprint">{current?.fingerprint}</code><p class="small">Approval will appear here automatically. If all trusted devices are lost, recovery is not available yet.</p></div>
        {/if}
        <nav aria-label="Account sections"><button class:active={view === "teams"} onclick={() => navigate("teams")}>Teams</button><button class:active={view === "devices"} onclick={() => navigate("devices")}>Devices</button></nav>
        {#if view === "devices"}
          <p class="small faint">Trusted devices can manage your account. Removing one ends its account sessions; it does not erase its local vault.</p>
          {#each data?.devices ?? [] as device (device.id)}
            <div class="list-row"><div><strong>{device.name}</strong><p class="small faint">{device.status}{device.id === data?.current_device_id ? " · This Mac" : ""}</p></div>
              {#if trusted && device.status === "pending"}<button class="outline" disabled={busy} onclick={() => approveDevice(device)}>Review device</button>{/if}
              {#if trusted && device.status !== "revoked" && (device.status !== "trusted" || (data?.devices.filter(d => d.status === "trusted").length ?? 0) > 1)}
                <button class="ghost" disabled={busy} onclick={() => { confirmation = { title: `Remove ${device.name}?`, description: "This device will lose account access and cannot sign in again with the same device identity.", action: { kind: "revoke_device", id: device.id } }; view = "confirm"; }}>Remove</button>
              {/if}
            </div>
          {/each}
        {:else if view === "confirm" && confirmation}
          <h3>{confirmation.title}</h3><p class="faint">{confirmation.description}</p>
          {#if confirmation.fingerprint}<code class="fingerprint">{confirmation.fingerprint}</code>{/if}
          <div class="actions"><button class="outline" onclick={() => navigate(confirmation?.action.kind.includes("device") ? "devices" : "teams")}>Cancel</button><button class="primary" disabled={busy || !trusted} onclick={confirm}>Confirm</button></div>
        {:else if view === "create"}
          <h3>New team</h3><form onsubmit={(e) => { e.preventDefault(); void createTeam(); }}><label>Team name<input bind:value={teamName} maxlength="80" required /></label><button class="primary" disabled={busy || !trusted || !teamName.trim()}>Create team</button></form>
        {:else if view === "invite"}
          <h3>Invite to {team?.name}</h3>
          {#if invite}
            <label>Team invitation link<input readonly value={invite.link} onclick={(e) => e.currentTarget.select()} /></label>
            <p class="small faint">Single use · Expires {new Date(invite.expires_at * 1000).toLocaleDateString()}. You approve the person after they request to join.</p>
            <div class="actions"><button class="outline" disabled={busy} onclick={() => run(async () => { await ipc.accountAction({ kind: "revoke_invite", team: teamId, invitation: invite!.id }); invite = null; message = "Invitation revoked."; })}>Revoke link</button><button class="primary" onclick={() => run(async () => { await navigator.clipboard.writeText(invite!.link); message = "Link copied."; })}>Copy link</button></div>
          {:else}
            <form onsubmit={(e) => { e.preventDefault(); void createInvite(); }}><label>Invitee’s email <span class="faint">(optional)</span><input type="email" bind:value={email} autocomplete="off" placeholder="teammate@example.com" /></label><label>Team role<select bind:value={role}><option value="member">Member</option>{#if team?.role === "owner"}<option value="admin">Admin</option>{/if}</select></label><button class="primary" disabled={busy || !trusted || !manager}>Create invitation link</button></form>
          {/if}
        {:else if view === "join"}
          <h3>Join a team</h3>
          {#if preview}
            <div class="notice"><strong>{preview.team_name}</strong><p>Join as a {preview.role}. An owner or admin must approve your request.</p></div>
            {#if requested}<p role="status">Request sent. Waiting for approval.</p>{:else}<button class="primary" disabled={busy || !trusted} onclick={requestJoin}>Request to join</button>{/if}
            <button class="ghost" onclick={() => { preview = null; requested = false; }}>Use another link</button>
          {:else}
            <form onsubmit={(e) => { e.preventDefault(); void inspect(); }}><label>Team invitation link<input bind:value={link} autocomplete="off" spellcheck="false" maxlength="8192" /></label><button class="primary" disabled={busy || !link.trim() || !trusted}>Review invitation</button></form>
          {/if}
        {:else if view === "teams"}
          <div class="toolbar"><button class="outline" disabled={!trusted || busy} onclick={() => { navigate("create"); teamName = ""; }}>New team</button><button class="ghost" disabled={!trusted || busy} onclick={() => { navigate("join"); preview = null; requested = false; }}>Join with link</button></div>
          {#if data?.teams.length}
            <label>Team<select bind:value={teamId} onchange={() => { revision++; members = []; requests = []; void refresh(); }}>{#each data.teams as t}<option value={t.id}>{t.name}</option>{/each}</select></label>
            <div class="spread"><h3>People <span class="faint">· {members.length}</span></h3>{#if manager}<button class="outline" disabled={busy || !trusted} onclick={() => { navigate("invite"); invite = null; email = ""; role = "member"; }}>Invite people</button>{/if}</div>
            {#each requests as request (request.id)}
              <div class="list-row request"><div><strong>{request.email}</strong><p class="small faint">Wants to join as {request.role}</p></div><button class="ghost" disabled={busy} onclick={() => run(async () => { await ipc.accountAction({ kind: "decide", team: teamId, invitation: request.id, account_id: request.account_id, approve: false }); await refresh(); })}>Decline</button><button class="outline" disabled={busy || !trusted} onclick={() => { confirmation = { title: `Approve ${request.email}?`, description: `Add this account to ${team?.name} as ${request.role}.`, action: { kind: "decide", team: teamId, invitation: request.id, account_id: request.account_id, approve: true } }; view = "confirm"; }}>Review request</button></div>
            {/each}
            {#each members as member (member.account_id)}
              <div class="list-row"><div><strong>{member.name}</strong><p class="small faint">{member.email} · {member.role}</p></div>{#if manager && member.role !== "owner" && (team?.role === "owner" || member.role !== "admin")}<button class="ghost" disabled={busy || !trusted} onclick={() => { confirmation = { title: `Remove ${member.name}?`, description: "This removes team membership. Access to any separately shared encrypted projects must be revoked in those projects.", action: { kind: "remove_member", team: teamId, account: member.account_id } }; view = "confirm"; }}>Remove</button>{/if}</div>
            {/each}
          {:else if data}<p class="empty faint">Create your first team, or join one with an invitation link.</p>{/if}
          <p class="small faint boundary">Teams currently manage membership. Encrypted project access is granted separately.</p>
        {/if}
      {/if}
    </div>
  </div>
</dialog>

<style>
  .account-card { padding-bottom: var(--s5); margin-bottom: var(--s5); border-bottom: 1px solid var(--border); }
  .account-card p { max-width: 58ch; margin: 10px 0 16px; }
  dialog { padding: 0; border: 1px solid var(--border); border-radius: 16px; background: var(--bg-raised); color: var(--text); width: min(600px, calc(100vw - 32px)); max-height: calc(100dvh - 48px); box-shadow: 0 24px 80px #0006; }
  dialog::backdrop { background: #0008; }
  .panel { padding: 24px; }
  header, .identity, .toolbar, .actions, .list-row { display: flex; align-items: center; gap: 12px; }
  header, .identity { justify-content: space-between; }
  header { margin-bottom: 20px; }
  .eyebrow { font-size: 10px; letter-spacing: .14em; color: var(--text-dim); margin: 0 0 8px; }
  h2 { font-size: 20px; } h3 { font-size: 14px; } p { line-height: 1.55; }
  .content > p { margin-block: 16px; }
  .identity { font-size: 13px; padding-bottom: 12px; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
  nav { display: flex; gap: 4px; margin: 16px 0 20px; }
  nav button { background: transparent; color: var(--text-dim); }
  nav .active { background: var(--bg-active); color: var(--text); }
  label { display: block; font-size: 12px; margin: 16px 0; }
  input, select { display: block; width: 100%; margin-top: 8px; }
  .list-row { padding: 14px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
  .list-row > div { flex: 1; min-width: 0; overflow-wrap: anywhere; }
  .list-row p { margin: 4px 0 0; }
  .list-row button { flex-shrink: 0; }
  .notice { background: var(--bg-input); padding: 16px; border-radius: 10px; margin: 16px 0; font-size: 13px; }
  .fingerprint { display: block; overflow-wrap: anywhere; font-size: 12px; padding: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; user-select: text; }
  .actions { margin-top: 20px; justify-content: flex-end; }
  .empty { padding: 24px 0; } .boundary { margin: 20px 0 0; }
  @media (max-width: 520px) { .panel { padding: 16px; } .list-row { flex-wrap: wrap; } .list-row > div { flex-basis: 100%; } }
</style>
