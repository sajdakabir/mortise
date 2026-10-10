<script lang="ts">
  import { ipc } from "./ipc";
  import { errorMessage, KIND_LABEL, type ItemPayload, type ItemRow } from "./types";

  let { item, onEdit, onDeleted }:
    { item: ItemRow; onEdit: () => void; onDeleted: () => void } = $props();

  let payload = $state<ItemPayload | null>(null);
  let shown = $state(false);
  let error = $state("");
  let copied = $state("");
  let confirmingDelete = $state(false);

  // Drop any revealed secret the moment the selection changes. Without this,
  // clicking through the list would leave every password it touched sitting in
  // the webview's heap.
  $effect(() => {
    void item.id;
    payload = null;
    shown = false;
    error = "";
    confirmingDelete = false;
  });

  async function reveal() {
    try {
      payload = await ipc.reveal(item.id);
      shown = true;
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function copy(field: string, label: string) {
    try {
      const seconds = await ipc.copySecret(item.id, field);
      copied = `${label} copied — clears in ${seconds}s`;
      setTimeout(() => (copied = ""), 2600);
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function remove() {
    try {
      await ipc.deleteItem(item.id);
      onDeleted();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  const when = $derived(new Date(item.updated_at_ms).toLocaleString());
</script>

<div class="detail">
  <div class="head">
    <div class="spread">
      <div class="titles">
        <span class="kind faint">{KIND_LABEL[item.kind]}</span>
        <h2>{item.title}</h2>
      </div>
      <div class="row no-drag">
        <button class="ghost" onclick={onEdit}>Edit</button>
        {#if confirmingDelete}
          <button class="danger" onclick={remove}>Really delete</button>
          <button class="ghost" onclick={() => (confirmingDelete = false)}>Keep</button>
        {:else}
          <button class="danger" onclick={() => (confirmingDelete = true)}>Delete</button>
        {/if}
      </div>
    </div>
  </div>

  <div class="body">
    {#if error}<div class="error">{error}</div>{/if}
    {#if copied}<div class="toast">{copied}</div>{/if}

    {#if item.username}
      <div class="row-field">
        <span class="k">Username</span>
        <span class="v">{item.username}</span>
      </div>
    {/if}

    {#if item.kind === "login" || item.kind === "apikey" || item.kind === "env"}
      <div class="row-field">
        <span class="k">{item.kind === "login" ? "Password" : item.kind === "apikey" ? "Key" : "Value"}</span>
        <span class="v mono secret">
          {#if shown && payload}
            {payload.kind === "Login" ? payload.password
              : payload.kind === "ApiKey" ? payload.key
              : payload.kind === "EnvSecret" ? payload.value : ""}
          {:else}
            ••••••••••••••••
          {/if}
        </span>
        <div class="row acts">
          <button class="ghost tiny" onclick={() => (shown ? ((shown = false), (payload = null)) : reveal())}>
            {shown ? "Hide" : "Show"}
          </button>
          <button class="ghost tiny" onclick={() =>
            copy(item.kind === "login" ? "password" : item.kind === "apikey" ? "key" : "value",
                 item.kind === "login" ? "Password" : item.kind === "apikey" ? "Key" : "Value")}>
            Copy
          </button>
        </div>
      </div>
    {/if}

    {#if item.urls.length}
      <div class="row-field">
        <span class="k">Websites</span>
        <span class="v">{#each item.urls as u (u)}<div>{u}</div>{/each}</span>
      </div>
    {/if}

    {#if item.folder}
      <div class="row-field"><span class="k">Folder</span><span class="v">{item.folder}</span></div>
    {/if}

    {#if item.tags.length}
      <div class="row-field">
        <span class="k">Tags</span>
        <span class="v tags">{#each item.tags as t (t)}<span class="tag">{t}</span>{/each}</span>
      </div>
    {/if}

    <div class="row-field"><span class="k">Updated</span><span class="v faint">{when}</span></div>

    <p class="faint footnote">
      Copying never sends the secret to this window — the backend reads it, writes
      the clipboard, and clears it on a timer.
    </p>
  </div>
</div>

<style>
  .detail { height: 100%; display: flex; flex-direction: column; }
  .head { padding: 18px 22px 14px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .titles { min-width: 0; }
  .kind { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.08em; }
  h2 { font-size: 17px; font-weight: 600; margin: 2px 0 0; overflow-wrap: anywhere; }
  .body { padding: 18px 22px 40px; overflow-y: auto; flex: 1; }
  .row-field {
    display: grid;
    grid-template-columns: 104px 1fr auto;
    gap: 12px;
    align-items: baseline;
    padding: 9px 0;
    border-bottom: 1px solid var(--border);
  }
  .k { font-size: 11px; color: var(--text-dim); }
  .v { overflow-wrap: anywhere; }
  .secret { letter-spacing: 0.04em; }
  .acts { align-self: center; }
  .tiny { font-size: 11px; padding: 2px 8px; }
  .tags { display: flex; flex-wrap: wrap; gap: 5px; }
  .tag { background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px; padding: 1px 7px; font-size: 11px; }
  .toast {
    background: color-mix(in srgb, var(--ok) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--ok) 38%, transparent);
    color: var(--ok);
    padding: 7px 11px; border-radius: var(--radius); font-size: 12px; margin-bottom: 14px;
  }
  .footnote { font-size: 11px; line-height: 1.6; margin: 24px 0 0; }
</style>
