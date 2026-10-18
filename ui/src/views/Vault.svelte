<script lang="ts">
  import ItemDetail from "../lib/ItemDetail.svelte";
  import Settings from "./Settings.svelte";
  import ItemEditor from "../lib/ItemEditor.svelte";
  import GettingStarted from "../lib/GettingStarted.svelte";
  import Avatar from "../lib/Avatar.svelte";
  import { ipc } from "../lib/ipc";
  import { errorMessage, KIND_LABEL, type ItemRow, type VaultStatus } from "../lib/types";
  import Secrets from "./Secrets.svelte";

  let { status = $bindable(), dataRevision = 0, onStatus, onUnlock }: {
    status: VaultStatus;
    /// Bumped by the shell when an item was written from outside this view.
    dataRevision?: number;
    onStatus: (s: VaultStatus) => void;
    /// Ask the shell to show the unlock screen. Locking drops the keys that
    /// decrypt secrets but keeps search working, so this view stays up — which
    /// means it has to offer the way back itself.
    onUnlock: () => void;
  } = $props();

  /// Which product is in view.
  ///
  /// Two workspaces rather than one list with a filter, because they are
  /// navigated differently: a password is found by searching for it, a secret
  /// by knowing its project and environment. Remembered, because whichever
  /// someone opened last is almost always the one they want next.
  let mode = $state<"passwords" | "secrets">(
    (localStorage.getItem("mortise.mode") as "passwords" | "secrets") ?? "passwords",
  );
  $effect(() => { localStorage.setItem("mortise.mode", mode); });

  /// The workspace menu.
  ///
  /// A menu rather than a row of tabs: tabs spend horizontal space in
  /// proportion to how many there are, and this list is going to grow. A
  /// trigger that names the current workspace costs the same whether there
  /// are two behind it or six.
  let menuOpen = $state(false);
  let projectCount = $state(0);

  $effect(() => {
    // Named so the count beside Secrets is the number of projects, not of
    // secrets: it is the thing the rail lists.
    dataRevision;
    if (!status.searchable) { projectCount = 0; return; }
    ipc.projects().then((p) => (projectCount = p.length)).catch(() => (projectCount = 0));
  });

  const WORKSPACES = [
    { id: "passwords" as const, label: "Passwords" },
    { id: "secrets" as const, label: "Secrets" },
  ];
  const workspaceLabel = $derived(
    WORKSPACES.find((w) => w.id === mode)?.label ?? "Passwords",
  );

  function chooseWorkspace(next: "passwords" | "secrets") {
    mode = next;
    menuOpen = false;
  }

  let query = $state("");
  let rows = $state<ItemRow[]>([]);
  let selectedId = $state<string | null>(null);
  let editing = $state<"none" | "new" | "existing" | "settings">("none");
  let error = $state("");
  /// Bumped when Settings closes, because approving a browser pairing happens
  /// in there and the getting-started panel has no other way to learn about it.
  let settingsRevision = $state(0);
  let searchEl = $state<HTMLInputElement | null>(null);
  let listEl = $state<HTMLElement | null>(null);

  const selected = $derived(rows.find((r) => r.id === selectedId) ?? null);
  const index = $derived(rows.findIndex((r) => r.id === selectedId));

  async function refresh() {
    try {
      rows = (await ipc.search(query)).filter((r) => r.kind !== "env");
      if (selectedId && !rows.some((r) => r.id === selectedId)) selectedId = null;
      error = "";
    } catch (e) {
      error = errorMessage(e);
      rows = [];
    }
  }

  $effect(() => {
    void query;
    void dataRevision;
    refresh();
  });

  /// Arrow keys move through the list, Enter opens, ⌘F or / focuses search.
  ///
  /// A list reachable only with the mouse is most of what separates this from
  /// the tools people reach for without thinking. Typing is left alone: these
  /// only fire when the keystroke is not already going into a field, except
  /// ⌘F, ⌘N and Escape, which should work from anywhere.
  function onKeydown(event: KeyboardEvent) {
    // Dialogs own the keyboard while they are up, and every shortcut below
    // acts on the password list, which is not on screen in the other mode.
    if (menuOpen && event.key === "Escape") {
      menuOpen = false;
      return;
    }
    if (editing !== "none" || mode !== "passwords") return;

    const target = event.target as HTMLElement | null;
    const typing =
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target?.isContentEditable === true;
    const mod = event.metaKey || event.ctrlKey;

    if (mod && event.key === "f") {
      event.preventDefault();
      searchEl?.focus();
      searchEl?.select();
      return;
    }
    if (mod && event.key === "n") {
      event.preventDefault();
      if (status.unlocked) { editing = "new"; selectedId = null; }
      return;
    }
    if (mod) return;

    if (event.key === "Escape") {
      if (query) { query = ""; return; }
      searchEl?.blur();
      return;
    }
    if (!typing && event.key === "/") {
      event.preventDefault();
      searchEl?.focus();
      return;
    }

    // Arrows work from the search field too, so you can type and then move
    // into the results without reaching for the mouse.
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (typing && target !== searchEl) return;
      if (rows.length === 0) return;
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = index < 0 ? (step > 0 ? 0 : rows.length - 1) : index + step;
      selectedId = rows[Math.max(0, Math.min(rows.length - 1, next))].id;
      scrollSelectedIntoView();
      return;
    }

    if (event.key === "Enter" && target === searchEl && rows.length > 0) {
      event.preventDefault();
      selectedId = rows[index < 0 ? 0 : index].id;
      searchEl?.blur();
    }
  }

  function scrollSelectedIntoView() {
    // After the selection has rendered, not before.
    requestAnimationFrame(() => {
      listEl
        ?.querySelector<HTMLElement>(".item.active")
        ?.scrollIntoView({ block: "nearest" });
    });
  }

  async function lock() {
    onStatus(await ipc.lock());
    selectedId = null;
    editing = "none";
  }

  async function onSaved(id: string) {
    editing = "none";
    await refresh();
    selectedId = id;
    onStatus(await ipc.status());
  }

  async function onDeleted() {
    selectedId = null;
    await refresh();
    onStatus(await ipc.status());
  }
</script>

<svelte:window onkeydown={onKeydown} />

{#snippet switcherUi()}
      <div class="no-drag switcher">
        <button class="trigger" aria-haspopup="menu" aria-expanded={menuOpen}
          onclick={() => (menuOpen = !menuOpen)}>
          <span class="t">{workspaceLabel}</span>
          <span class="chev" aria-hidden="true">⌄</span>
        </button>

        {#if menuOpen}
          <!-- A transparent catcher rather than a window listener: it closes
               on the click that opens something else, in one place, and it
               cannot fight the trigger's own toggle. -->
          <div class="catch" role="presentation" onclick={() => (menuOpen = false)}></div>
          <div class="menu" role="menu" aria-label="Workspace">
            <p class="menulabel label">Products</p>
            {#each WORKSPACES as w (w.id)}
              <button role="menuitem" class="menuitem" class:on={w.id === mode}
                onclick={() => chooseWorkspace(w.id)}>
                <span class="tick" aria-hidden="true">{w.id === mode ? "✓" : ""}</span>
                <span class="t">{w.label}</span>
                <span class="n faint">{w.id === "passwords" ? rows.length : projectCount}</span>
              </button>
            {/each}
          </div>
        {/if}
      </div>
{/snippet}

{#snippet footUi()}
    <div class="foot">
      <div class="spread">
        {#if status.unlocked}
          <button class="ghost tiny" onclick={lock}>Lock</button>
        {:else}
          <button class="ghost tiny unlock" onclick={onUnlock}>Unlock</button>
        {/if}
        <button
          class="ghost icon"
          title="Settings"
          aria-label="Settings"
          onclick={() => (editing = "settings")}>
          <!-- Teeth are shallow and chunky on a solid body. Deep teeth turn
               spiky at 16px and read as a sun or a star; the body has to stay
               dominant for the silhouette to say gear. Generated geometry, so
               the spacing is even. -->
          <svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true">
            <path
              fill="currentColor"
              fill-rule="evenodd"
              d="M7.62 2.89 L7.46 0.85 L12.54 0.85 L12.38 2.89 A7.5 7.5 0 0 1 13.35 3.29 L13.35 3.29 L14.68 1.73 L18.27 5.32 L16.71 6.65 A7.5 7.5 0 0 1 17.11 7.62 L17.11 7.62 L19.15 7.46 L19.15 12.54 L17.11 12.38 A7.5 7.5 0 0 1 16.71 13.35 L16.71 13.35 L18.27 14.68 L14.68 18.27 L13.35 16.71 A7.5 7.5 0 0 1 12.38 17.11 L12.38 17.11 L12.54 19.15 L7.46 19.15 L7.62 17.11 A7.5 7.5 0 0 1 6.65 16.71 L6.65 16.71 L5.32 18.27 L1.73 14.68 L3.29 13.35 A7.5 7.5 0 0 1 2.89 12.38 L2.89 12.38 L0.85 12.54 L0.85 7.46 L2.89 7.62 A7.5 7.5 0 0 1 3.29 6.65 L3.29 6.65 L1.73 5.32 L5.32 1.73 L6.65 3.29 A7.5 7.5 0 0 1 7.62 2.89 Z M10.0 6.7 A3.3 3.3 0 1 0 10.0 13.3 A3.3 3.3 0 1 0 10.0 6.7 Z" />
          </svg>
        </button>
      </div>
    </div>
{/snippet}

<!-- The secrets workspace brings its own sidebar: its projects rail is the
     only list it has, so the password list's sidebar sat beside it as a
     second column with nothing in it. The switcher and the footer are
     snippets, so one definition serves both layouts. -->
{#if mode === "secrets" && editing !== "settings" && status.exists}
  <Secrets unlocked={status.unlocked} {onUnlock} switcher={switcherUi} foot={footUi} />
{:else}
<div class="shell">
  <aside>
    <div class="topbar drag">
      {@render switcherUi()}
      {#if mode === "passwords"}
      <div class="no-drag searchwrap">
        <input
          class="search"
          placeholder="Search"
          bind:this={searchEl}
          bind:value={query}
          spellcheck="false"
          autocomplete="off" />
        {#if !query}<kbd class="hint">/</kbd>{/if}
      </div>
      {/if}
    </div>

    {#if mode === "passwords"}
    <div class="listhead spread">
      <span class="faint count">
        {rows.length}{query ? " found" : status.item_count === 1 ? " item" : " items"}
      </span>
      <button class="ghost tiny" disabled={!status.unlocked} title="New item  ⌘N"
        onclick={() => { editing = "new"; selectedId = null; }}>+ New</button>
    </div>

    <div class="list" bind:this={listEl}>
      {#if error}
        <p class="empty">{error}</p>
      {:else if rows.length === 0}
        <div class="nothing">
          <p class="faint">{query ? `No match for “${query}”` : "No items yet."}</p>
          {#if !query && status.unlocked}
            <button class="ghost tiny" onclick={() => (editing = "new")}>Add your first</button>
          {/if}
        </div>
      {:else}
        {#each rows as row (row.id)}
          <button class="item" class:active={row.id === selectedId}
            onclick={() => { selectedId = row.id; editing = "none"; }}>
            <Avatar title={row.title} kind={row.kind} size={28} />
            <span class="text">
              <span class="t">{row.title}</span>
              <span class="s faint">{row.username ?? KIND_LABEL[row.kind]}</span>
            </span>
          </button>
        {/each}
      {/if}
    </div>
    {/if}
    {@render footUi()}
  </aside>

  <main>
    {#if editing === "settings"}
      <Settings
        {status}
        onStatus={(s) => (status = s)}
        onClose={() => { editing = "none"; settingsRevision += 1; }} />
    {:else if !status.unlocked}
      <div class="placeholder">
        <p class="locked-title">Vault is locked</p>
        <p class="faint small">
          You can still search and see names. Unlock to reveal, copy or change
          anything.
        </p>
        <button class="primary unlockbtn" onclick={onUnlock}>Unlock</button>
      </div>
    {:else if selected}
      <ItemDetail item={selected} onEdit={() => (editing = "existing")} onDeleted={onDeleted} />
    {:else}
      <GettingStarted
        {status}
        revision={settingsRevision}
        onAddItem={() => { editing = "new"; selectedId = null; }} />
    {/if}
  </main>
</div>
{/if}

<!-- Outside the shell so the dialog overlays the whole window rather than
     only the right-hand pane, and the list stays visible behind it. -->
{#if editing === "new" || editing === "existing"}
  {#key editing === "existing" ? selected?.id : "new"}
    <ItemEditor
      existing={editing === "existing" ? selected : null}
      onSaved={onSaved}
      onCancel={() => (editing = "none")} />
  {/key}
{/if}

<style>
  .shell { height: 100%; display: grid; grid-template-columns: 272px 1fr; }

  aside {
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    /* Sunken rather than raised: the list is the ground the detail pane sits
       in front of, and lifting both flattened the two together. */
    background: var(--bg-sunken);
    min-width: 0;
  }

  /* The window has a transparent title bar, so the traffic lights float over
     the top-left of this sidebar. Clearing them with left padding squeezed the
     search into the leftover width; reserving the height instead puts it on
     its own row at full width, which is what every other macOS sidebar does.
     The strip above it stays draggable, so the lights still have a grab area. */
  .topbar { padding: 38px var(--s2) var(--s2); flex-shrink: 0; }
  .searchwrap { width: 100%; position: relative; }
  .search {
    font-size: 12.5px;
    padding: 6px 28px;
    border-radius: var(--radius);
    background: var(--bg-input);
  }
  /* Magnifier drawn in CSS rather than shipped as an icon file or an inline
     SVG — it is two shapes, and the asset would cost more than it saves. */
  .searchwrap::before {
    content: "";
    position: absolute;
    left: 10px;
    top: 50%;
    width: 7px;
    height: 7px;
    margin-top: -5px;
    border: 1.5px solid var(--text-faint);
    border-radius: 50%;
    pointer-events: none;
  }
  .searchwrap::after {
    content: "";
    position: absolute;
    left: 17px;
    top: 50%;
    width: 4px;
    height: 1.5px;
    margin-top: 2px;
    background: var(--text-faint);
    transform: rotate(45deg);
    transform-origin: left center;
    pointer-events: none;
  }
  .hint {
    position: absolute;
    right: 7px;
    top: 50%;
    transform: translateY(-50%);
    pointer-events: none;
  }

  .listhead { padding: var(--s2) var(--s3) var(--s1); flex-shrink: 0; }
  .count { font-size: 11px; font-variant-numeric: tabular-nums; }
  .tiny { font-size: 11px; padding: 3px 8px; }

  /* The workspace switcher. Sits above search because it changes what search
     would even be searching, and a control that reframes everything under it
     belongs first. */
  .switcher { position: relative; margin-bottom: var(--s2); }
  .trigger {
    display: flex; align-items: center; justify-content: space-between; gap: var(--s2);
    width: 100%; padding: 6px 10px; font-size: 12.5px;
    background: transparent; border: 1px solid var(--border); color: var(--text);
    border-radius: var(--radius);
  }
  .trigger:hover { background: var(--bg-hover); }
  .trigger .chev { color: var(--text-faint); font-size: 12px; line-height: 1; }

  /* Covers the window beneath the menu so the next click anywhere dismisses
     it, without a global listener racing the trigger's own toggle. */
  .catch { position: fixed; inset: 0; z-index: 10; }

  .menu {
    position: absolute; z-index: 11; top: calc(100% + 4px); left: 0;
    min-width: 212px;
    background: var(--bg-raised); border: 1px solid var(--border-strong);
    border-radius: var(--radius); box-shadow: var(--shadow-2); padding: var(--s1);
  }
  .menulabel { display: block; padding: 6px 9px 4px; }
  .menuitem {
    display: grid; grid-template-columns: 16px 1fr auto; align-items: center; gap: var(--s2);
    width: 100%; text-align: left; padding: 6px 9px; font-size: 12.5px;
    background: transparent; border: 0; border-radius: var(--radius-sm); color: var(--text-dim);
  }
  .menuitem:hover { background: var(--bg-hover); color: var(--text); }
  .menuitem.on { color: var(--text); }
  .menuitem .tick { color: var(--text); font-size: 11px; }
  .menuitem .n { font-variant-numeric: tabular-nums; font-size: 11px; }

  .list { flex: 1; overflow-y: auto; padding: 0 var(--s2) var(--s2); }
  .item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
    padding: 6px var(--s2);
    border-radius: var(--radius);
  }
  .item + .item { margin-top: 1px; }
  .item:hover { background: var(--bg-hover); }
  .item.active { background: var(--bg-active); border-color: var(--border); }
  .item.active .s { color: var(--text-dim); }

  /* min-width:0 is what lets the ellipsis work inside a flex row. */
  .text { min-width: 0; display: flex; flex-direction: column; gap: 1px; }
  .t,
  .s { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
  .t { font-size: 13px; font-weight: 500; letter-spacing: -0.005em; }
  .s { font-size: 11px; }

  .empty { padding: var(--s5) var(--s3); font-size: 12px; }
  .nothing {
    padding: var(--s6) var(--s3);
    text-align: center;
    display: grid;
    gap: 10px;
    justify-items: center;
  }
  .nothing p { margin: 0; font-size: 12px; }

  .foot { padding: var(--s2) var(--s3); border-top: 1px solid var(--border); flex-shrink: 0; }
  .unlock { color: var(--warn); }
  .unlock:hover:not(:disabled) { color: var(--warn); }
  .unlockbtn { margin-top: var(--s3); padding: 7px var(--s5); }

  /* Square so the gear sits centred rather than in a text-shaped box. */
  .icon {
    display: grid;
    place-items: center;
    width: 26px;
    height: 24px;
    padding: 0;
    color: var(--text-dim);
  }
  .icon:hover { color: var(--text); }

  main { min-width: 0; overflow: hidden; background: var(--bg); }
  .placeholder { height: 100%; display: grid; place-content: center; text-align: center; gap: 6px; }
  .placeholder p { margin: 0; }
  .locked-title { font-size: 14px; font-weight: 560; }
  .small { font-size: 12px; max-width: 280px; line-height: 1.6; }
</style>
