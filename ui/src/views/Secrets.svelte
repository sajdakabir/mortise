<script lang="ts">
  /// The developer-secrets workspace.
  ///
  /// A separate surface from the password list rather than a filter on it,
  /// because the two are navigated differently: a password is found by
  /// searching for it, a secret is found by knowing which project and which
  /// environment it is in. One flat list cannot serve both without making the
  /// commoner case worse.
  import { ipc, isMock } from "../lib/ipc";
  import { open } from "@tauri-apps/plugin-dialog";
  import { errorMessage, type ProjectSummary, type EnvImportReport } from "../lib/types";

  import { tick, type Snippet } from "svelte";

  let {
    unlocked,
    switcher,
    foot,
    onUnlock,
  }: {
    unlocked: boolean;
    switcher: Snippet;
    foot: Snippet;
    /// Ask the shell for the unlock screen. Locking keeps project and key
    /// names readable — the META key outlives it — so this view stays up and
    /// has to offer the way back itself.
    onUnlock: () => void;
  } = $props();

  let projects = $state<ProjectSummary[]>([]);
  let project = $state<string | null>(null);
  let environment = $state<string | null>(null);
  let rows = $state<{ id: string; title: string }[]>([]);
  /// Values revealed in this session, by item id. Cleared whenever the
  /// environment changes: a value left on screen after you have navigated
  /// away is a value on screen for longer than anyone asked for.
  let shown = $state<Record<string, string>>({});
  let copiedId = $state<string | null>(null);

  /// The add-one-secret row.
  let adding = $state(false);
  let newKey = $state("");
  let newValue = $state("");
  let error = $state("");
  let busy = $state(false);

  /// The paste sheet. Held open while a report is showing, so the person can
  /// read what happened before deciding whether to paste again.
  let pasting = $state(false);
  let pasteText = $state("");
  let pasteProject = $state("");
  let pasteEnv = $state("");
  let report = $state<EnvImportReport | null>(null);
  let copied = $state(false);
  let copiedNote = $state("");
  /// Bumped after a write. The key list is keyed on the project and the
  /// environment, so a paste into the environment already on screen changes
  /// neither and the list would keep showing what was there before.
  let revision = $state(0);

  /// The create-project sheet.
  let creating = $state(false);
  let newName = $state("");
  let newDescription = $state("");
  let sharing = $state(false);
  let inviterName = $state("");
  let inviteLink = $state("");
  let inviteCopied = $state(false);
  let pendingJoin = $state<{ name: string; fingerprint: string } | null>(null);
  let grantRole = $state<"viewer" | "member" | "admin">("member");
  let grantComplete = $state(false);
  let joining = $state(false);
  let joinLink = $state("");
  let joinerName = $state("");
  let joinPreview = $state<{ project_name: string; inviter_name: string; fingerprint: string } | null>(null);
  let joinRequested = $state(false);
  let joinComplete = $state(false);

  /// Inline add-an-environment field, shown from the segmented control.
  let addingEnv = $state(false);
  let newEnv = $state("");
  let environmentInput = $state<HTMLInputElement | null>(null);
  let fileMenuOpen = $state(false);
  let fileActions = $state<HTMLDivElement | null>(null);
  let fileMenu = $state<HTMLDivElement | null>(null);
  let fileMenuButton = $state<HTMLButtonElement | null>(null);
  const componentId = $props.id();
  const menuId = `${componentId}-env-actions`;

  async function chooseEnvironment(event: Event) {
    const select = event.currentTarget as HTMLSelectElement;
    if (select.value === "new") {
      select.value = String(current?.environments.indexOf(environment ?? "") ?? -1);
      addingEnv = true;
      newEnv = "";
      await tick();
      environmentInput?.focus();
    } else {
      environment = current?.environments[Number(select.value)] ?? null;
      addingEnv = false;
    }
    fileMenuOpen = false;
  }

  async function toggleFileMenu() {
    fileMenuOpen = !fileMenuOpen;
    if (fileMenuOpen) {
      await tick();
      fileMenu?.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus();
    }
  }

  function closeFileMenu(restoreFocus = false) {
    fileMenuOpen = false;
    if (restoreFocus) fileMenuButton?.focus();
  }

  function fileMenuKeys(event: KeyboardEvent) {
    if (event.key === "Tab") { closeFileMenu(true); return; }
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const buttons = Array.from(fileMenu?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? []);
    if (!buttons.length) return;
    const currentIndex = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1
      : (currentIndex + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length;
    buttons[next]?.focus();
  }

  $effect(() => { if (!unlocked) fileMenuOpen = false; });

  const current = $derived(projects.find((p) => p.name === project) ?? null);

  async function load() {
    try {
      error = "";
      projects = await ipc.projects();
      if (project && !projects.some((p) => p.name === project)) project = null;
      if (!project && projects.length > 0) project = projects[0].name;
    } catch (e) {
      error = errorMessage(e);
    }
  }

  /// Keep the chosen environment inside the chosen project.
  $effect(() => {
    const envs = current?.environments ?? [];
    if (environment && !envs.includes(environment)) environment = null;
    if (!environment && envs.length > 0) environment = envs[0];
  });

  /// The keys in the current environment, by name only — values stay in Rust
  /// until something actually asks for one.
  $effect(() => {
    const p = project, e = environment;
    revision;
    if (!p || !e) { rows = []; return; }
    shown = {};
    ipc.search("")
      .then((all) =>
        (rows = all
          .filter((r) => r.kind === "env")
          .filter((r) => r.project === p && r.environment === e)
          .map((r) => ({ id: r.id, title: r.title }))
          .sort((a, b) => a.title.localeCompare(b.title))),
      )
      .catch((err) => (error = errorMessage(err)));
  });

  $effect(() => { load(); });

  /// Drop anything revealed the moment the vault locks. Keeping a decrypted
  /// value on screen past the lock would make the lock a lie.
  $effect(() => { if (!unlocked) shown = {}; });

  async function createProject() {
    if (busy) return;
    busy = true;
    try {
      error = "";
      const p = await ipc.createProject(newName, newDescription);
      creating = false;
      newName = "";
      newDescription = "";
      await load();
      project = p.name;
      environment = p.environments[0] ?? null;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function addEnvironment() {
    if (busy || !current) return;
    busy = true;
    try {
      error = "";
      const p = await ipc.addEnvironment(current.id, newEnv);
      addingEnv = false;
      const added = newEnv.trim();
      newEnv = "";
      await load();
      if (p.environments.includes(added)) environment = added;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function createInvite() {
    if (busy || !current || !inviterName.trim()) return;
    busy = true;
    try {
      error = "";
      inviteLink = await ipc.createProjectInvite(current.id, inviterName.trim());
      await load();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  async function copyInvite() {
    await navigator.clipboard.writeText(inviteLink);
    inviteCopied = true;
    setTimeout(() => (inviteCopied = false), 1800);
  }

  async function checkJoinRequest() {
    busy = true;
    try {
      error = "";
      pendingJoin = await ipc.pendingProjectJoin(inviteLink);
    } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }

  async function grantJoin() {
    if (!pendingJoin) return;
    busy = true;
    try {
      error = "";
      await ipc.grantProjectJoin(inviteLink, grantRole);
      grantComplete = true;
      pendingJoin = null;
    } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }

  async function inspectInvite() {
    try {
      error = "";
      joinPreview = await ipc.inspectProjectInvite(joinLink.trim());
    } catch (e) { error = errorMessage(e); }
  }

  async function requestAccess() {
    if (!joinerName.trim()) return;
    busy = true;
    try {
      await ipc.requestProjectAccess(joinLink.trim(), joinerName.trim());
      joinRequested = true;
    } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }

  async function checkJoinAccess() {
    busy = true;
    try {
      error = "";
      joinComplete = await ipc.completeProjectJoin(joinLink.trim());
    } catch (e) { error = errorMessage(e); }
    finally { busy = false; }
  }

  /// Reopen onto whatever was being written.
  ///
  /// The project and environment follow the current selection, since that is
  /// what was clicked to get here, but the text is left alone: it is the one
  /// thing in the sheet that took effort, and it is cleared when it has been
  /// saved rather than when the sheet is dismissed.
  function openPaste() {
    pasteProject = project ?? "";
    pasteEnv = environment ?? "";
    report = null;
    error = "";
    pasting = true;
  }

  async function paste() {
    if (busy) return;
    busy = true;
    try {
      error = "";
      report = await ipc.importEnv(pasteProject, pasteEnv, pasteText);
      pasteText = "";
      project = pasteProject;
      environment = pasteEnv;
      revision += 1;
      await load();
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  function onSheetKeydown(event: KeyboardEvent) {
    if (event.key === "Escape") pasting = false;
  }

  async function reveal(id: string) {
    try {
      error = "";
      const payload = await ipc.reveal(id);
      shown[id] = payload.kind === "EnvSecret" ? payload.value : "";
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function copyValue(id: string) {
    try {
      error = "";
      // Copied inside Rust: the value goes to the clipboard and is cleared on
      // a timer without ever passing through this window.
      await ipc.copySecret(id, "value");
      copiedId = id;
      setTimeout(() => { if (copiedId === id) copiedId = null; }, 1800);
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function addSecret() {
    if (busy || !project || !environment) return;
    busy = true;
    try {
      error = "";
      await ipc.importEnv(project, environment, `${newKey}=${newValue}`);
      newKey = "";
      newValue = "";
      adding = false;
      revision += 1;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }

  /// Read a `.env` from disk.
  ///
  /// The path goes to Rust and Rust opens it. Reading it here would pull a
  /// file of plaintext secrets through the webview for no benefit.
  async function uploadEnv() {
    if (!project || !environment) return;
    try {
      error = "";
      const picked = isMock
        ? "/tmp/mock.env"
        : await open({ multiple: false, filters: [{ name: "Env file", extensions: ["env", "txt", ""] }] });
      if (typeof picked !== "string") return;
      report = await ipc.importEnvFile(project, environment, picked);
      revision += 1;
      await load();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  /// Copy the whole environment.
  ///
  /// Rust reads, formats and writes the clipboard, and clears it on the same
  /// timer a single-secret copy uses. This window never sees the text — which
  /// it used to, and then wrote to the clipboard itself with nothing to clear
  /// it afterwards.
  async function copyEnv() {
    if (!project || !environment) return;
    try {
      error = "";
      const report = await ipc.copyEnv(project, environment);
      copiedNote = `${report.copied} copied · clears in ${report.clears_in_secs}s`;
      copied = true;
      setTimeout(() => (copied = false), report.clears_in_secs * 1000);
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<svelte:window
  onpointerdown={(event) => {
    if (fileMenuOpen && !fileActions?.contains(event.target as Node)) closeFileMenu();
  }}
  onkeydown={(event) => {
    if (fileMenuOpen && event.key === "Escape") {
      event.preventDefault();
      closeFileMenu(true);
    }
  }} />

<div class="secrets">
  <aside class="rail">
    <div class="railtop drag">
      <div class="no-drag">{@render switcher()}</div>
    </div>

    <div class="railhead spread">
      <span class="label">Projects</span>
      <button class="ghost tiny" disabled={!unlocked}
        onclick={() => { error = ""; creating = true; }}>
        + New</button>
    </div>
    <div class="projects">
    {#if projects.length === 0}
      <p class="faint empty">No projects yet.</p>
    {:else}
      {#each projects as p (p.name)}
        <button class="proj" class:active={p.name === project} onclick={() => (project = p.name)}>
          <span class="t">{p.name}</span>
          <span class="n faint">{p.secret_count}</span>
        </button>
      {/each}
    {/if}
    </div>

    <button class="ghost tiny" disabled={!unlocked}
      onclick={() => { joining = true; joinPreview = null; joinRequested = false; joinComplete = false; error = ""; }}>
      Join with invite</button>
    <div class="railfoot">{@render foot()}</div>
  </aside>

  <section class="body">
    {#if !unlocked}
      <!-- Said here rather than left to the first failed save: someone can
           paste forty lines into a sheet that was never going to write them,
           and finding out at the end is the worst moment to learn it. -->
      <div class="lockbar">
        <span>Vault is locked. Names are readable; adding or revealing is not.</span>
        <button class="ghost tiny" onclick={onUnlock}>Unlock</button>
      </div>
    {/if}
    {#if error && !creating && !pasting}<div class="error">{error}</div>{/if}

    {#if !current}
      <div class="nothing">
        <p class="faint">No projects yet. One per codebase, with its own environments.</p>
        <button class="primary" disabled={!unlocked}
          onclick={() => { error = ""; creating = true; }}>
          New project</button>
      </div>
    {:else}
      <header class="head">
        <div class="environment-controls">
          <div class="environment-select">
            <select aria-label="Environment" value={current.environments.indexOf(environment ?? "")}
              onchange={chooseEnvironment}>
              {#each current.environments as e, i (e)}
                <option value={i}>{e}</option>
              {/each}
              <option value="new" disabled={!unlocked}>+ Add environment…</option>
            </select>
            <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="m6 8 4 4 4-4" /></svg>
          </div>
          {#if addingEnv}
            <form class="environment-add" onsubmit={(event) => { event.preventDefault(); addEnvironment(); }}>
              <input class="envinput" bind:this={environmentInput} bind:value={newEnv}
                aria-label="New environment name" placeholder="e.g. preview" disabled={!unlocked || busy}
                onkeydown={(event) => { if (event.key === "Escape") { addingEnv = false; newEnv = ""; } }} />
              <button class="tiny" type="submit" disabled={!unlocked || busy || !newEnv.trim()}>Add</button>
              <button class="ghost tiny" type="button" onclick={() => { addingEnv = false; newEnv = ""; }}>Cancel</button>
            </form>
          {/if}
        </div>
        <div class="row">
          <button class="ghost tiny" disabled={!unlocked}
            onclick={() => { sharing = true; inviteLink = ""; inviteCopied = false; pendingJoin = null; grantComplete = false; error = ""; }}>
            Share</button>
          <button class="ghost tiny" disabled={!unlocked}
            onclick={() => { adding = true; newKey = ""; newValue = ""; }}>+ Secret</button>
          <div class="file-actions" bind:this={fileActions}>
            <button class="file-trigger tiny" bind:this={fileMenuButton} disabled={!unlocked}
              aria-label="Environment file actions" aria-haspopup="menu" aria-expanded={fileMenuOpen}
              aria-controls={menuId} onclick={toggleFileMenu}
              onkeydown={(event) => { if (event.key === "ArrowDown" && !fileMenuOpen) { event.preventDefault(); toggleFileMenu(); } }}>
              .env
              <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="m6 8 4 4 4-4" /></svg>
            </button>
            {#if fileMenuOpen}
              <div class="file-menu" id={menuId} bind:this={fileMenu} role="menu"
                aria-label="Environment file actions" tabindex="-1" onkeydown={fileMenuKeys}>
                <button role="menuitem" onclick={() => { closeFileMenu(); openPaste(); }}>Paste .env</button>
                <button role="menuitem" onclick={() => { closeFileMenu(true); uploadEnv(); }}>Upload .env file</button>
                <div class="menu-divider" role="separator"></div>
                <button role="menuitem" disabled={rows.length === 0}
                  onclick={() => { closeFileMenu(true); copyEnv(); }}>Copy as .env</button>
              </div>
            {/if}
          </div>
        </div>
      </header>
      {#if copied}<p class="copy-note" role="status">{copiedNote}</p>{/if}

      {#if rows.length === 0 && !adding}
        <!-- An empty environment is the one place someone is certain to be
             stuck, so it carries the three ways out rather than stating the
             obvious and leaving them to hunt the toolbar. -->
        <div class="blank">
          <p class="faint">Nothing in <strong>{environment}</strong> yet.</p>
          <div class="row">
            <button class="primary" disabled={!unlocked} onclick={openPaste}>Paste .env</button>
            <button disabled={!unlocked} onclick={uploadEnv}>Upload a file</button>
            <button disabled={!unlocked} onclick={() => { adding = true; newKey = ""; newValue = ""; }}>
              Add one secret</button>
          </div>
        </div>
      {:else}
        <ul class="keys mono">
          {#each rows as row (row.id)}
            <li>
              <span class="k">{row.title}</span>
              <!-- Keyed on presence rather than truthiness: a .env may hold
                   KEY= with nothing after it, and a revealed empty value has
                   to look different from one that is still hidden. -->
              <span class="v" class:faint={!(row.id in shown)}>
                {#if row.id in shown}
                  {shown[row.id] === "" ? "(empty)" : shown[row.id]}
                {:else}••••••••{/if}
              </span>
              <span class="acts">
                <button class="ghost icon-button" disabled={!unlocked}
                  title={row.id in shown ? "Hide value" : "Reveal value"}
                  aria-label={`${row.id in shown ? "Hide" : "Reveal"} ${row.title}`}
                  aria-pressed={row.id in shown}
                  onclick={() => { if (row.id in shown) { const n = { ...shown }; delete n[row.id]; shown = n; } else reveal(row.id); }}>
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                    {#if row.id in shown}
                      <path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.2A11 11 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 4M6.5 6.5A18 18 0 0 0 2 12s3.5 7 10 7a11 11 0 0 0 5.5-1.5" />
                    {:else}
                      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" />
                      <circle cx="12" cy="12" r="3" />
                    {/if}
                  </svg>
                </button>
                <button class="ghost icon-button" class:confirmed={copiedId === row.id}
                  disabled={!unlocked} onclick={() => copyValue(row.id)}
                  title={copiedId === row.id ? "Copied" : "Copy value"}
                  aria-label={copiedId === row.id ? `Copied ${row.title}` : `Copy ${row.title}`}>
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                    {#if copiedId === row.id}
                      <path d="m5 12 4 4L19 6" />
                    {:else}
                      <rect x="9" y="9" width="11" height="11" rx="2" />
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                    {/if}
                  </svg>
                </button>
              </span>
            </li>
          {/each}

          {#if adding}
            <li class="addrow">
              <!-- svelte-ignore a11y_autofocus -->
              <input class="k" autofocus bind:value={newKey} placeholder="KEY_NAME" spellcheck="false" />
              <input class="v" bind:value={newValue} placeholder="value" spellcheck="false"
                onkeydown={(e) => { if (e.key === "Enter" && newKey.trim()) addSecret(); }} />
              <span class="acts">
                <button class="ghost tiny" disabled={busy || !newKey.trim()} onclick={addSecret}>Save</button>
                <button class="ghost tiny" onclick={() => (adding = false)}>Cancel</button>
              </span>
            </li>
          {/if}
        </ul>
      {/if}
    {/if}
  </section>
</div>

{#if joining}
  <div class="scrim" role="presentation" onclick={() => (joining = false)}></div>
  <div class="sheet" role="dialog" aria-label="Join project" tabindex="-1">
    <div class="spread sheethead"><strong>Join a project</strong><button class="ghost tiny" onclick={() => (joining = false)}>Close</button></div>
    {#if error}<div class="error">{error}</div>{/if}
    {#if joinRequested}
      {#if joinComplete}
        <p>Access granted and the project history is synced to this device.</p>
      {:else}
        <p>Your request was sent. Access is not granted until the owner checks your fingerprint and approves it.</p>
        <div class="row end"><button disabled={busy} onclick={checkJoinAccess}>{busy ? "Checking…" : "Check access"}</button></div>
      {/if}
    {:else if joinPreview}
      <p>Join <strong>{joinPreview.project_name}</strong>, invited by {joinPreview.inviter_name}?</p>
      <p class="hint">Compare this identity fingerprint with the inviter before continuing:</p>
      <code>{joinPreview.fingerprint}</code>
      <div class="field"><label for="join-name">Your name</label><input id="join-name" bind:value={joinerName} /></div>
      <div class="row end"><button class="primary" disabled={busy || !joinerName.trim()} onclick={requestAccess}>Send request</button></div>
    {:else}
      <div class="field"><label for="join-link">Invite link</label><textarea id="join-link" bind:value={joinLink}></textarea></div>
      <div class="row end"><button class="primary" disabled={!joinLink.trim()} onclick={inspectInvite}>Check invite</button></div>
    {/if}
  </div>
{/if}

{#if sharing}
  <div class="scrim" role="presentation" onclick={() => (sharing = false)}></div>
  <div class="sheet" role="dialog" aria-label="Share project" tabindex="-1"
    onkeydown={(e) => { if (e.key === "Escape") sharing = false; }}>
    <div class="spread sheethead">
      <strong>Share {current?.name}</strong>
      <button class="ghost tiny" onclick={() => (sharing = false)}>Close</button>
    </div>
    {#if error}<div class="error">{error}</div>{/if}
    {#if inviteLink}
      <p class="hint">Send this single-use link to your teammate. Compare the fingerprint Mortise shows before granting access.</p>
      <div class="field">
        <label for="invite-link">Invite link</label>
        <textarea id="invite-link" readonly value={inviteLink}></textarea>
      </div>
      <div class="row end">
        <button class="primary" onclick={copyInvite}>{inviteCopied ? "Copied" : "Copy invite link"}</button>
      </div>
      {#if grantComplete}
        <p>Access granted. The teammate can now sync this project.</p>
      {:else if pendingJoin}
        <hr />
        <p><strong>{pendingJoin.name}</strong> is asking to join.</p>
        <p class="hint">Compare this identity fingerprint with them before granting access:</p>
        <code>{pendingJoin.fingerprint}</code>
        <div class="field"><label for="grant-role">Role</label>
          <select id="grant-role" bind:value={grantRole}>
            <option value="viewer">Viewer</option><option value="member">Member</option><option value="admin">Admin</option>
          </select>
        </div>
        <div class="row end"><button class="primary" disabled={busy} onclick={grantJoin}>{busy ? "Granting…" : "Grant access"}</button></div>
      {:else}
        <div class="row end"><button disabled={busy} onclick={checkJoinRequest}>{busy ? "Checking…" : "Check for request"}</button></div>
      {/if}
    {:else}
      <p class="hint">This moves the project into its own encrypted vault. Originals are removed only after the new vault is registered and synced.</p>
      <div class="field">
        <label for="inviter-name">Your name</label>
        <input id="inviter-name" bind:value={inviterName} placeholder="Sajda"
          onkeydown={(e) => { if (e.key === "Enter") createInvite(); }} />
      </div>
      <div class="row end">
        <button class="primary" disabled={busy || !inviterName.trim()} onclick={createInvite}>
          {busy ? "Preparing…" : "Create invite"}
        </button>
      </div>
    {/if}
  </div>
{/if}

{#if creating}
  <div class="scrim" role="presentation" onclick={() => (creating = false)}></div>
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="sheet" role="dialog" aria-label="New project" tabindex="-1"
    onkeydown={(e) => { if (e.key === "Escape") creating = false; }}>
    <div class="spread sheethead">
      <strong>New project</strong>
      <button class="ghost tiny" onclick={() => (creating = false)}>Cancel</button>
    </div>
    {#if error}<div class="error">{error}</div>{/if}
    <p class="hint">
      One per codebase. It starts with <code>dev</code>, <code>staging</code>
      and <code>prod</code>; you can add more.
    </p>

    <div class="field">
      <label for="np">Name</label>
      <!-- svelte-ignore a11y_autofocus -->
      <input id="np" autofocus bind:value={newName} placeholder="acme-api"
        onkeydown={(e) => { if (e.key === "Enter" && newName.trim()) createProject(); }} />
    </div>
    <div class="field">
      <label for="nd">Description <span class="faint">optional</span></label>
      <input id="nd" bind:value={newDescription} placeholder="The billing API" />
    </div>

    <div class="row end">
      <button class="primary" disabled={busy || !newName.trim()} onclick={createProject}>
        {busy ? "Creating…" : "Create project"}
      </button>
    </div>
  </div>
{/if}

{#if pasting}
  <!-- Closes on a click outside, and keeps what was typed. Dismissing a
       sheet and destroying its contents are two different things, and only
       the first is what a click out of the way asks for. -->
  <div class="scrim" role="presentation" onclick={() => (pasting = false)}></div>
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="sheet" role="dialog" aria-label="Paste a .env file"
    tabindex="-1" onkeydown={onSheetKeydown}>
    <div class="spread sheethead">
      <strong>Paste .env</strong>
      <button class="ghost tiny" onclick={() => (pasting = false)}>Close</button>
    </div>

    {#if error}<div class="error">{error}</div>{/if}

    <div class="row two">
      <div class="field">
        <label for="pp">Project</label>
        <input id="pp" bind:value={pasteProject} placeholder="acme-api" />
      </div>
      <div class="field">
        <label for="pe">Environment</label>
        <input id="pe" bind:value={pasteEnv} placeholder="prod" />
      </div>
    </div>

    <div class="field">
      <label for="pt">File</label>
      <textarea id="pt" bind:value={pasteText} spellcheck="false"
        placeholder={"DATABASE_URL=postgres://…\nSTRIPE_SECRET_KEY=…"}></textarea>
    </div>

    {#if report}
      <p class="report">
        {report.added} added · {report.updated} updated · {report.unchanged} unchanged{#if report.unreadable}
          · {report.unreadable} not a KEY=value{/if}{#if report.duplicates.length}
          · {report.duplicates.length} defined twice, last kept{/if}
      </p>
    {/if}

    <div class="row end">
      <button class="primary" disabled={busy || !pasteText.trim()} onclick={paste}>
        {busy ? "Saving…" : "Save"}
      </button>
    </div>
  </div>
{/if}

<style>
  .secrets { display: grid; grid-template-columns: 232px minmax(0, 1fr); height: 100%; min-height: 0; }
  /* One sidebar, not two: the switcher at the top, the projects it lists in
     the middle, and the lock at the bottom where it is in the other
     workspace too. */
  .rail {
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column; min-height: 0;
    padding: 0 var(--s2) 0;
  }
  /* Matches the password sidebar's top strip, which is what makes the window
     draggable where there is no title bar. */
  .railtop { padding: 38px var(--s1) 0; }
  .railfoot { margin-top: auto; }
  .railhead { padding: var(--s4) var(--s2) var(--s2); }
  .projects { overflow-y: auto; min-height: 0; }
  .proj {
    display: flex; align-items: center; justify-content: space-between; gap: var(--s2);
    width: 100%; text-align: left; background: transparent; border: 1px solid transparent;
    padding: 6px var(--s2); border-radius: var(--radius); color: var(--text-dim);
  }
  .proj:hover { background: var(--bg-hover); }
  .proj.active { background: var(--bg-active); color: var(--text); border-color: var(--border); }
  .proj .t { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .proj .n { font-variant-numeric: tabular-nums; font-size: 11px; }

  /* The body is a column, not a scroll box. Scrolling the whole thing took
     the environment selector and the file actions off screen as soon as a project
     had more than a dozen secrets — exactly when you most want to switch
     environment or paste a new file. Only the key list scrolls. */
  .body {
    padding: var(--s4);
    min-width: 0;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }
  .head {
    display: flex; align-items: center; justify-content: space-between;
    gap: var(--s3); flex-wrap: wrap; margin-bottom: var(--s4);
    flex-shrink: 0;
  }

  .environment-controls, .environment-add { display: flex; align-items: center; gap: var(--s2); flex-wrap: wrap; }
  .environment-select { position: relative; max-width: 220px; }
  .environment-select select {
    appearance: none; width: auto; min-width: 132px; max-width: 220px;
    padding: 7px 32px 7px 12px; font-size: 12.5px; cursor: pointer;
    text-overflow: ellipsis; background: var(--bg-raised);
  }
  .environment-select svg { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); pointer-events: none; color: var(--text-dim); }
  .file-actions { position: relative; }
  .file-trigger { display: inline-flex; align-items: center; gap: var(--s2); min-height: 32px; }
  .file-menu {
    position: absolute; top: calc(100% + 6px); right: 0; z-index: 10;
    min-width: 184px; padding: 4px; background: var(--bg-raised);
    border: 1px solid var(--border-strong); border-radius: var(--radius);
    box-shadow: var(--shadow-3);
  }
  .file-menu button {
    display: block; width: 100%; text-align: left; font-size: 12.5px;
    padding: 8px 10px; background: transparent; border-color: transparent;
  }
  .file-menu button:hover:not(:disabled), .file-menu button:focus-visible { background: var(--bg-hover); }
  .menu-divider { height: 1px; background: var(--border); margin: 4px 6px; }
  .copy-note { margin: 0 0 var(--s2); color: var(--text-dim); font-size: 12px; flex-shrink: 0; }

  .keys {
    list-style: none; margin: 0; padding: 0;
    flex: 1; min-height: 0; overflow-y: auto;
    /* Room for the last row's actions to clear the window edge. */
    padding-bottom: var(--s2);
  }
  .keys li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr) auto;
    align-items: center; gap: var(--s3);
    padding: 7px var(--s2); border-bottom: 1px solid var(--border); font-size: 12.5px;
  }
  .keys .k { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .keys .v { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .acts { display: flex; align-items: center; gap: var(--s1); }
  .icon-button {
    display: inline-grid; place-items: center; flex: 0 0 32px;
    width: 32px; height: 32px; padding: 0; border-radius: var(--radius);
    color: var(--text-faint);
  }
  .keys li:hover .icon-button, .icon-button:focus-visible,
  .icon-button.confirmed { color: var(--text); }
  .addrow input {
    font: 400 12.5px/1 var(--mono);
    padding: 4px 6px;
  }

  .blank { display: grid; place-items: center; gap: var(--s4); padding: var(--s6) 0; text-align: center; }

  .empty { padding: var(--s3) var(--s2); font-size: 12.5px; }
  .nothing { display: grid; place-items: center; gap: var(--s3); padding: var(--s6) 0; text-align: center; }

  .scrim { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); }
  .sheet {
    position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%);
    width: min(520px, calc(100vw - 48px));
    background: var(--bg-raised); border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg); box-shadow: var(--shadow-3); padding: var(--s4);
  }
  .sheethead { margin-bottom: var(--s4); }
  .row { display: flex; gap: var(--s2); align-items: center; }
  .row.two { display: grid; grid-template-columns: 1fr 1fr; gap: var(--s3); }
  .row.end { justify-content: flex-end; margin-top: var(--s3); }
  .sheet textarea { min-height: 170px; font: 400 12px/1.6 var(--mono); }
  .lockbar {
    flex-shrink: 0;
    display: flex; align-items: center; justify-content: space-between; gap: var(--s3);
    margin-bottom: var(--s4); padding: 8px var(--s3);
    background: color-mix(in srgb, var(--warn) 10%, transparent);
    border: 1px solid color-mix(in srgb, var(--warn) 35%, transparent);
    border-radius: var(--radius); font-size: 12px; color: var(--text-dim);
  }
  .report { font-size: 12px; color: var(--text-dim); margin: 0 0 var(--s2); }
  .hint { font-size: 12.5px; color: var(--text-dim); margin: 0 0 var(--s4); line-height: 1.6; }
  .envinput {
    width: 140px; padding: 6px 10px; font-size: 12px;
  }
</style>
