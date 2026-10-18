<script lang="ts">
  /// The developer-secrets workspace.
  ///
  /// A separate surface from the password list rather than a filter on it,
  /// because the two are navigated differently: a password is found by
  /// searching for it, a secret is found by knowing which project and which
  /// environment it is in. One flat list cannot serve both without making the
  /// commoner case worse.
  import { ipc } from "../lib/ipc";
  import { errorMessage, type ProjectSummary, type EnvImportReport } from "../lib/types";

  let { unlocked }: { unlocked: boolean } = $props();

  let projects = $state<ProjectSummary[]>([]);
  let project = $state<string | null>(null);
  let environment = $state<string | null>(null);
  let rows = $state<{ title: string }[]>([]);
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
    ipc.search("")
      .then((all) =>
        (rows = all
          .filter((r) => r.kind === "env")
          .filter((r) => r.project === p && r.environment === e)
          .map((r) => ({ title: r.title }))
          .sort((a, b) => a.title.localeCompare(b.title))),
      )
      .catch((err) => (error = errorMessage(err)));
  });

  $effect(() => { if (unlocked) load(); });

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
    <div class="railhead spread">
      <span class="label">Projects</span>
      <button class="ghost tiny" disabled={!unlocked} onclick={openPaste}>+ New</button>
    </div>
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
  </aside>

  <section class="body">
    {#if error}<div class="error">{error}</div>{/if}

    {#if !current}
      <div class="nothing">
        <p class="faint">Paste a <code>.env</code> to start a project.</p>
        <button class="primary" disabled={!unlocked} onclick={openPaste}>Paste .env</button>
      </div>
    {:else}
      <header class="head">
        <div class="envs" role="tablist">
          {#each current.environments as e (e)}
            <button role="tab" aria-selected={e === environment}
              class="env" class:active={e === environment}
              onclick={() => (environment = e)}>{e}</button>
          {/each}
        </div>
        <div class="row">
          <button class="ghost tiny" onclick={openPaste}>Paste .env</button>
          <button class="ghost tiny" onclick={copyEnv} disabled={rows.length === 0}>
            {copied ? "Copied" : "Copy as .env"}
          </button>
        </div>
      </header>

      {#if rows.length === 0}
        <p class="faint empty">Nothing in this environment.</p>
      {:else}
        <ul class="keys mono">
          {#each rows as row (row.title)}
            <li><span class="k">{row.title}</span><span class="v faint">••••••••</span></li>
          {/each}
        </ul>
      {/if}
    {/if}
  </section>
</div>

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
  .secrets { display: grid; grid-template-columns: 190px minmax(0, 1fr); height: 100%; min-height: 0; }
  .rail { border-right: 1px solid var(--border); overflow-y: auto; padding: 0 var(--s2) var(--s2); }
  .railhead { padding: var(--s3) var(--s2) var(--s2); }
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
    display: flex; align-items: center; justify-content: space-between; gap: var(--s4);
    padding: 8px var(--s2); border-bottom: 1px solid var(--border); font-size: 12.5px;
  }
  .keys .k { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

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
</style>
