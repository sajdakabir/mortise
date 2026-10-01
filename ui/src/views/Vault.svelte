<script lang="ts">
  import ItemDetail from "../lib/ItemDetail.svelte";
  import ItemEditor from "../lib/ItemEditor.svelte";
  import { ipc } from "../lib/ipc";
  import { errorMessage, KIND_LABEL, type ItemRow, type VaultStatus } from "../lib/types";

  let { status, onStatus }:
    { status: VaultStatus; onStatus: (s: VaultStatus) => void } = $props();

  let query = $state("");
  let rows = $state<ItemRow[]>([]);
  let selectedId = $state<string | null>(null);
  let editing = $state<"none" | "new" | "existing">("none");
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
      {#if status.unlocked}
        <button class="ghost tiny" onclick={lock}>Lock</button>
      {:else}
        <span class="locked">Locked — search only</span>
      {/if}
    </div>
  </aside>

  <main>
    {#if editing !== "none"}
      {#key editing === "existing" ? selected?.id : "new"}
        <ItemEditor
          existing={editing === "existing" ? selected : null}
          onSaved={onSaved}
          onCancel={() => (editing = "none")} />
      {/key}
    {:else if !status.unlocked}
      <div class="placeholder">
        <p>Vault is locked.</p>
        <p class="faint small">
          Search and titles still work. Unlock to see or change anything secret.
        </p>
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
  .topbar { padding: 10px 12px 8px; padding-left: 78px; flex-shrink: 0; }
  .searchwrap { width: 100%; }
  .search { font-size: 12px; padding: 5px 9px; }
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
  .locked { font-size: 11px; color: var(--warn); }
  main { min-width: 0; overflow: hidden; }
  .placeholder { height: 100%; display: grid; place-content: center; text-align: center; gap: 6px; }
  .placeholder p { margin: 0; }
  .small { font-size: 12px; max-width: 260px; line-height: 1.6; }
</style>
