<script lang="ts">
  import { ipc } from "./ipc";
  import Avatar from "./Avatar.svelte";
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

  /// The username is metadata, not a secret: it is already on screen and in
  /// this webview's heap. Routing it through `copy_secret` would be asking
  /// the backend to hand back something it never hid, and that command only
  /// knows about secret fields anyway.
  async function copyUsername() {
    if (!item.username) return;
    try {
      await navigator.clipboard.writeText(item.username);
      copied = "Username copied";
      setTimeout(() => (copied = ""), 2000);
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

  /// "3 minutes ago" beats a timestamp for the question people actually ask,
  /// which is whether this is current. The exact time stays in the tooltip.
  const when = $derived.by(() => {
    const mins = Math.round((Date.now() - item.updated_at_ms) / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins} minute${mins === 1 ? "" : "s"} ago`;
    const hours = Math.round(mins / 60);
    if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
    const days = Math.round(hours / 24);
    if (days < 31) return `${days} day${days === 1 ? "" : "s"} ago`;
    return new Date(item.updated_at_ms).toLocaleDateString();
  });
  const exact = $derived(new Date(item.updated_at_ms).toLocaleString());

  const secretLabel = $derived(
    item.kind === "login" ? "Password" : item.kind === "apikey" ? "Key" : "Value",
  );
  const secretField = $derived(
    item.kind === "login" ? "password" : item.kind === "apikey" ? "key" : "value",
  );
  const hasSecret = $derived(
    item.kind === "login" || item.kind === "apikey" || item.kind === "env",
  );
  const secretText = $derived(
    !shown || !payload
      ? ""
      : payload.kind === "Login"
        ? payload.password
        : payload.kind === "ApiKey"
          ? payload.key
          : payload.kind === "EnvSecret"
            ? payload.value
            : "",
  );
</script>

<div class="detail">
  <header class="head">
    <div class="ident">
      <Avatar title={item.title} kind={item.kind} size={40} />
      <div class="titles">
        <h2>{item.title}</h2>
        <span class="kind faint">{KIND_LABEL[item.kind]}</span>
      </div>
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
  </header>

  <div class="body">
    {#if error}<div class="error">{error}</div>{/if}

    <div class="card">
      {#if item.username}
        <div class="field-row">
          <span class="k">Username</span>
          <span class="v">{item.username}</span>
          <button class="ghost tiny" onclick={copyUsername}>Copy</button>
        </div>
      {/if}

      {#if hasSecret}
        <div class="field-row">
          <span class="k">{secretLabel}</span>
          <span class="v mono secret" class:masked={!shown}>
            {shown && payload ? secretText : "••••••••••••••••"}
          </span>
          <div class="row">
            <button class="ghost tiny"
              onclick={() => (shown ? ((shown = false), (payload = null)) : reveal())}>
              {shown ? "Hide" : "Show"}
            </button>
            <button class="ghost tiny" onclick={() => copy(secretField, secretLabel)}>Copy</button>
          </div>
        </div>
      {/if}

      {#if item.urls.length}
        <div class="field-row">
          <span class="k">Websites</span>
          <span class="v urls">
            {#each item.urls as u (u)}<span class="url">{u}</span>{/each}
          </span>
        </div>
      {/if}

      {#if item.folder}
        <div class="field-row">
          <span class="k">Folder</span><span class="v">{item.folder}</span>
        </div>
      {/if}

      {#if item.tags.length}
        <div class="field-row">
          <span class="k">Tags</span>
          <span class="v tags">{#each item.tags as t (t)}<span class="tag">{t}</span>{/each}</span>
        </div>
      {/if}

      <div class="field-row">
        <span class="k">Updated</span>
        <span class="v faint" title={exact}>{when}</span>
      </div>
    </div>

    <p class="faint footnote">
      Copying never sends the secret to this window — the backend reads it,
      writes the clipboard, and clears it on a timer.
    </p>
  </div>

  {#if copied}
    <div class="toast" role="status">{copied}</div>
  {/if}
</div>

<style>
  .detail { height: 100%; display: flex; flex-direction: column; position: relative; }

  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--s4);
    padding: var(--s5) var(--s5) var(--s4);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .ident { display: flex; align-items: center; gap: var(--s3); min-width: 0; }
  .titles { min-width: 0; display: flex; flex-direction: column; gap: 1px; }
  h2 {
    font-size: 18px;
    font-weight: 600;
    letter-spacing: -0.015em;
    margin: 0;
    overflow-wrap: anywhere;
  }
  .kind { font-size: 11px; }

  .body { padding: var(--s5); overflow-y: auto; flex: 1; }

  /* The fields sit on a card rather than loose on the pane. Loose rows with
     hairlines between them read as a spreadsheet; a bounded group reads as
     one record, which is what it is. */
  .card {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-raised);
    box-shadow: var(--shadow-1);
    overflow: hidden;
    /* Narrow enough that Copy stays near the value it copies. Full-bleed put
       the button four hundred pixels from the thing it acts on, which reads
       as two unrelated columns rather than one row. */
    max-width: 520px;
  }
  .field-row {
    display: grid;
    grid-template-columns: 96px 1fr auto;
    gap: var(--s3);
    align-items: center;
    padding: 11px var(--s4);
    min-height: 44px;
  }
  .field-row + .field-row { border-top: 1px solid var(--border); }
  .k { font-size: 11.5px; color: var(--text-dim); }
  .v { overflow-wrap: anywhere; font-size: 13px; }
  /* Dots want to be loose and even; a real secret wants to be readable. */
  .secret.masked { letter-spacing: 0.12em; color: var(--text-dim); }
  .tiny { font-size: 11px; padding: 3px 8px; }

  .urls { display: flex; flex-direction: column; gap: 2px; }
  .url { overflow-wrap: anywhere; }
  .tags { display: flex; flex-wrap: wrap; gap: 5px; }
  .tag {
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 1px 7px;
    font-size: 11px;
  }

  /* Pinned to the pane rather than pushing the fields down, so copying does
     not make the thing you just copied jump. */
  .toast {
    position: absolute;
    left: 50%;
    bottom: var(--s5);
    transform: translateX(-50%);
    white-space: nowrap;
    background: var(--bg-raised);
    border: 1px solid color-mix(in srgb, var(--ok) 45%, var(--border));
    color: var(--ok);
    padding: 8px var(--s3);
    border-radius: var(--radius);
    font-size: 12px;
    box-shadow: var(--shadow-2);
  }

  .footnote { font-size: 11px; line-height: 1.6; margin: var(--s4) 0 0; max-width: 62ch; }
</style>
