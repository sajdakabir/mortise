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

  import type { Snippet } from "svelte";

  let {
    unlocked,
    switcher,
    foot,
  }: { unlocked: boolean; switcher: Snippet; foot: Snippet } = $props();

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
  /// Bumped after a write. The key list is keyed on the project and the
  /// environment, so a paste into the environment already on screen changes
  /// neither and the list would keep showing what was there before.
  let revision = $state(0);

  /// The create-project sheet.
  let creating = $state(false);
  let newName = $state("");
  let newDescription = $state("");

  /// Inline add-an-environment field, shown from the segmented control.
  let addingEnv = $state(false);
  let newEnv = $state("");

  const current = $derived(projects.find((p) => p.name === project) ?? null);

  async function load() {
    if (!unlocked) { projects = []; return; }
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

  $effect(() => { if (unlocked) load(); });

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

  function openPaste() {
    pasteProject = project ?? "";
    pasteEnv = environment ?? "";
    pasteText = "";
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

  async function copyEnv() {
    if (!project || !environment) return;
    try {
      error = "";
      const text = await ipc.exportEnv(project, environment);
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<div class="secrets">
  <aside class="rail">
    <div class="railtop drag">
      <div class="no-drag">{@render switcher()}</div>
    </div>

    <div class="railhead spread">
      <span class="label">Projects</span>
      <button class="ghost tiny" disabled={!unlocked}
        onclick={() => { newName = ""; newDescription = ""; error = ""; creating = true; }}>
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

    <div class="railfoot">{@render foot()}</div>
  </aside>

  <section class="body">
    {#if error && !creating && !pasting}<div class="error">{error}</div>{/if}

    {#if !current}
      <div class="nothing">
        <p class="faint">No projects yet. One per codebase, with its own environments.</p>
        <button class="primary" disabled={!unlocked}
          onclick={() => { newName = ""; newDescription = ""; error = ""; creating = true; }}>
          New project</button>
      </div>
    {:else}
      <header class="head">
        <div class="envs" role="tablist">
          {#each current.environments as e (e)}
            <button role="tab" aria-selected={e === environment}
              class="env" class:active={e === environment}
              onclick={() => (environment = e)}>{e}</button>
          {/each}
          {#if addingEnv}
            <input class="envinput" bind:value={newEnv} placeholder="preview"
              onkeydown={(e) => {
                if (e.key === "Enter") addEnvironment();
                if (e.key === "Escape") { addingEnv = false; newEnv = ""; }
              }} />
          {:else}
            <button class="env add" title="Add an environment"
              onclick={() => { addingEnv = true; newEnv = ""; }}>+</button>
          {/if}
        </div>
        <div class="row">
          <button class="ghost tiny"
            onclick={() => { adding = true; newKey = ""; newValue = ""; }}>+ Secret</button>
          <button class="ghost tiny" onclick={openPaste}>Paste .env</button>
          <button class="ghost tiny" onclick={uploadEnv}>Upload</button>
          <button class="ghost tiny" onclick={copyEnv} disabled={rows.length === 0}>
            {copied ? "Copied" : "Copy as .env"}
          </button>
        </div>
      </header>

      {#if rows.length === 0 && !adding}
        <!-- An empty environment is the one place someone is certain to be
             stuck, so it carries the three ways out rather than stating the
             obvious and leaving them to hunt the toolbar. -->
        <div class="blank">
          <p class="faint">Nothing in <strong>{environment}</strong> yet.</p>
          <div class="row">
            <button class="primary" onclick={openPaste}>Paste .env</button>
            <button onclick={uploadEnv}>Upload a file</button>
            <button onclick={() => { adding = true; newKey = ""; newValue = ""; }}>
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
                <button class="ghost tiny"
                  onclick={() => { if (row.id in shown) { const n = { ...shown }; delete n[row.id]; shown = n; } else reveal(row.id); }}>
                  {row.id in shown ? "Hide" : "Reveal"}
                </button>
                <button class="ghost tiny" onclick={() => copyValue(row.id)}>
                  {copiedId === row.id ? "Copied" : "Copy"}
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

{#if creating}
  <div class="scrim" role="presentation"></div>
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
  <!-- Closing on a click outside would throw away a file someone has just
       pasted, which is the one thing this sheet holds. It closes from the
       button or Escape, both of which are deliberate. -->
  <div class="scrim" role="presentation"></div>
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

  .body { padding: var(--s4); overflow-y: auto; min-width: 0; }
  .head { display: flex; align-items: center; justify-content: space-between; gap: var(--s3); flex-wrap: wrap; margin-bottom: var(--s4); }

  /* A segmented control: the environments are a small fixed set and exactly
     one is in view, which is the one case where this beats a list. */
  .envs { display: inline-flex; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .env {
    border: 0; border-left: 1px solid var(--border); border-radius: 0;
    background: transparent; color: var(--text-dim); padding: 5px 13px; font-size: 12px;
  }
  .env:first-child { border-left: 0; }
  .env.active { background: var(--bg-active); color: var(--text); }

  .keys { list-style: none; margin: 0; padding: 0; }
  .keys li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr) auto;
    align-items: center; gap: var(--s3);
    padding: 7px var(--s2); border-bottom: 1px solid var(--border); font-size: 12.5px;
  }
  .keys .k { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .keys .v { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  /* The row actions appear on hover or focus. Two buttons on every row at
     rest turns a list of names into a wall of controls. */
  .acts { display: flex; gap: var(--s1); opacity: 0; transition: opacity var(--fast); }
  .keys li:hover .acts, .acts:focus-within { opacity: 1; }
  .addrow input {
    font: 400 12.5px/1 var(--mono);
    padding: 4px 6px;
  }
  .addrow .acts { opacity: 1; }

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
  .report { font-size: 12px; color: var(--text-dim); margin: 0 0 var(--s2); }
  .hint { font-size: 12.5px; color: var(--text-dim); margin: 0 0 var(--s4); line-height: 1.6; }
  .env.add { padding: 5px 10px; color: var(--text-faint); }
  .env.add:hover { color: var(--text); }
  .envinput {
    width: 96px; border: 0; border-left: 1px solid var(--border); border-radius: 0;
    background: transparent; padding: 4px 10px; font-size: 12px;
  }
  .envinput:focus { outline: none; box-shadow: none; }
</style>
