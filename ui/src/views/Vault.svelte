<script lang="ts">
  import ItemDetail from "../lib/ItemDetail.svelte";
  import Settings from "./Settings.svelte";
  import ItemEditor from "../lib/ItemEditor.svelte";
  import { ipc } from "../lib/ipc";
  import { errorMessage, KIND_LABEL, type ItemRow, type VaultStatus } from "../lib/types";

  let { status = $bindable(), onStatus, onUnlock }: {
    status: VaultStatus;
    onStatus: (s: VaultStatus) => void;
    /// Ask the shell to show the unlock screen. Locking drops the keys that
    /// decrypt secrets but keeps search working, so this view stays up — which
    /// means it has to offer the way back itself.
    onUnlock: () => void;
  } = $props();

  let query = $state("");
  let rows = $state<ItemRow[]>([]);
  let selectedId = $state<string | null>(null);
  let editing = $state<"none" | "new" | "existing" | "settings">("none");
  let error = $state("");

  const selected = $derived(rows.find((r) => r.id === selectedId) ?? null);

  async function refresh() {
    try {
      rows = await ipc.search(query);
      if (selectedId && !rows.some((r) => r.id === selectedId)) selectedId = null;
      error = "";
    } catch (e) {
      error = errorMessage(e);
      rows = [];
    }
  }

  $effect(() => {
    void query;
    refresh();
  });

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

<div class="shell">
  <aside>
    <div class="topbar drag">
      <div class="no-drag searchwrap">
        <input class="search" placeholder="Search" bind:value={query} spellcheck="false" />
      </div>
    </div>

    <div class="listhead spread">
      <span class="faint count">
        {rows.length}{query ? " found" : status.item_count === 1 ? " item" : " items"}
      </span>
      <button class="ghost tiny" disabled={!status.unlocked}
        onclick={() => { editing = "new"; selectedId = null; }}>+ New</button>
    </div>

    <div class="list">
      {#if error}
        <p class="empty">{error}</p>
      {:else if rows.length === 0}
        <p class="empty faint">{query ? "Nothing matches." : "No items yet."}</p>
      {:else}
        {#each rows as row (row.id)}
          <button class="item" class:active={row.id === selectedId}
            onclick={() => { selectedId = row.id; editing = "none"; }}>
            <span class="t">{row.title}</span>
            <span class="s faint">{row.username ?? KIND_LABEL[row.kind]}</span>
          </button>
        {/each}
      {/if}
    </div>

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
  </aside>

  <main>
    {#if editing === "settings"}
      <Settings {status} onStatus={(s) => (status = s)} onClose={() => (editing = "none")} />
    {:else if editing !== "none"}
      {#key editing === "existing" ? selected?.id : "new"}
        <ItemEditor
          existing={editing === "existing" ? selected : null}
          onSaved={onSaved}
          onCancel={() => (editing = "none")} />
      {/key}
    {:else if !status.unlocked}
      <div class="placeholder">
        <p>Vault is locked</p>
        <p class="faint small">
          You can still search and see names. Unlock to reveal, copy or change
          anything.
        </p>
        <button class="primary unlockbtn" onclick={onUnlock}>Unlock</button>
      </div>
    {:else if selected}
      <ItemDetail item={selected} onEdit={() => (editing = "existing")} onDeleted={onDeleted} />
    {:else}
      <div class="placeholder">
        <p class="faint">Select an item.</p>
      </div>
    {/if}
  </main>
</div>

<style>
  .shell { height: 100%; display: grid; grid-template-columns: 268px 1fr; }
  aside {
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    background: var(--bg-raised);
    min-width: 0;
  }
  /* Leaves room for the macOS traffic lights under a transparent title bar. */
  /* The window has a transparent title bar, so the traffic lights float over
     the top-left of this sidebar. Clearing them with left padding squeezed the
     search into the leftover width; reserving the height instead puts it on
     its own row at full width, which is what every other macOS sidebar does.
     The strip above it stays draggable, so the lights still have a grab area. */
  .topbar { padding: 38px 10px 8px; flex-shrink: 0; }
  .searchwrap { width: 100%; }
  .search {
    font-size: 12.5px;
    padding: 6px 10px 6px 28px;
    border-radius: 7px;
    background: var(--bg-input);
  }
  .searchwrap { position: relative; }
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
  .listhead { padding: 8px 12px 6px; flex-shrink: 0; }
  .count { font-size: 11px; }
  .tiny { font-size: 11px; padding: 2px 8px; }
  .list { flex: 1; overflow-y: auto; padding: 0 6px 8px; }
  .item {
    display: flex; flex-direction: column; gap: 1px;
    width: 100%; text-align: left;
    background: transparent; border: none;
    padding: 7px 10px; border-radius: var(--radius);
  }
  .item:hover { background: var(--bg-input); }
  .item.active { background: var(--accent-dim); }
  .item.active .t, .item.active .s { color: var(--text); }
  .t { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
  .s { font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
  .empty { padding: 20px 12px; font-size: 12px; }
  .foot { padding: 9px 12px; border-top: 1px solid var(--border); flex-shrink: 0; }
  .unlock { color: var(--warn); }
  .unlock:hover:not(:disabled) { color: var(--warn); border-color: var(--warn); }
  .unlockbtn { margin-top: 12px; padding: 6px 20px; }
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
  main { min-width: 0; overflow: hidden; }
  .placeholder { height: 100%; display: grid; place-content: center; text-align: center; gap: 6px; }
  .placeholder p { margin: 0; }
  .small { font-size: 12px; max-width: 260px; line-height: 1.6; }
</style>
