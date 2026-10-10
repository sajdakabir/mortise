<script lang="ts">
  import { ipc } from "./ipc";
  import Generator from "./Generator.svelte";
  import {
    emptyPayload, errorMessage, KIND_LABEL,
    type ItemKind, type ItemPayload, type ItemRow,
  } from "./types";

  let { existing, onSaved, onCancel }:
    { existing: ItemRow | null; onSaved: (id: string) => void; onCancel: () => void } = $props();

  // Intentional one-time snapshot: this is a form seeded from a prop, not a
  // live mirror of it. The parent keys the component on item id, so switching
  // items remounts rather than mutating a half-edited form under the user.
  // svelte-ignore state_referenced_locally
  const seed = {
    kind: (existing?.kind ?? "login") as ItemKind,
    title: existing?.title ?? "",
    username: existing?.username ?? "",
    urls: (existing?.urls ?? []).join("\n"),
    folder: existing?.folder ?? "",
    tags: (existing?.tags ?? []).join(", "),
    isEdit: existing !== null,
  };

  let kind = $state<ItemKind>(seed.kind);
  let title = $state(seed.title);
  let username = $state(seed.username);
  let urls = $state(seed.urls);
  let folder = $state(seed.folder);
  let tags = $state(seed.tags);
  let payload = $state<ItemPayload>(emptyPayload(seed.kind));

  let loading = $state(seed.isEdit);
  let busy = $state(false);
  let error = $state("");
  let showGenerator = $state(false);

  // Editing an existing item needs its secrets, so reveal once on open.
  $effect(() => {
    if (!existing) return;
    ipc.reveal(existing.id)
      .then((p) => { payload = p; })
      .catch((e) => { error = errorMessage(e); })
      .finally(() => { loading = false; });
  });

  function changeKind(next: ItemKind) {
    kind = next;
    payload = emptyPayload(next);
  }

  async function save() {
    if (!title.trim() || busy) return;
    busy = true;
    error = "";
    try {
      const id = await ipc.saveItem(existing?.id ?? null, {
        title: title.trim(),
        urls: urls.split("\n").map((u) => u.trim()).filter(Boolean),
        username: username.trim() || null,
        folder: folder.trim() || null,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      }, payload);
      onSaved(id);
    } catch (e) {
      error = errorMessage(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="editor">
  <div class="head spread">
    <h2>{existing ? "Edit item" : "New item"}</h2>
    <div class="row">
      <button class="ghost" onclick={onCancel}>Cancel</button>
      <button class="primary" disabled={!title.trim() || busy || loading} onclick={save}>
        {busy ? "Saving…" : "Save"}
      </button>
    </div>
  </div>

  <div class="body">
    {#if error}<div class="error">{error}</div>{/if}
    {#if loading}
      <p class="dim">Decrypting…</p>
    {:else}
      {#if !existing}
        <div class="field">
          <label for="kind">Type</label>
          <select id="kind" value={kind} onchange={(e) => changeKind(e.currentTarget.value as ItemKind)}>
            {#each Object.entries(KIND_LABEL) as [k, label] (k)}
              {#if k !== "passkey"}<option value={k}>{label}</option>{/if}
            {/each}
          </select>
        </div>
      {/if}

      <div class="field">
        <label for="title">Name</label>
        <input id="title" bind:value={title} />
      </div>

      {#if payload.kind === "Login"}
        <div class="field">
          <label for="user">Username</label>
          <input id="user" bind:value={username} spellcheck="false" />
        </div>
        <div class="field">
          <div class="spread lbl">
            <label for="pw">Password</label>
            <button class="ghost tiny" onclick={() => (showGenerator = !showGenerator)}>
              {showGenerator ? "Hide generator" : "Generate"}
            </button>
          </div>
          <input id="pw" class="mono" bind:value={payload.password} spellcheck="false" />
        </div>
        {#if showGenerator}
          <div class="genbox">
            <Generator onUse={(pw) => {
              if (payload.kind === "Login") payload.password = pw;
              showGenerator = false;
            }} />
          </div>
        {/if}
        <div class="field">
          <label for="totp">TOTP seed (optional)</label>
          <input id="totp" class="mono" value={payload.totp_seed ?? ""} spellcheck="false"
            oninput={(e) => { if (payload.kind === "Login") payload.totp_seed = e.currentTarget.value || null; }} />
        </div>
        <div class="field">
          <label for="notes">Notes</label>
          <textarea id="notes" value={payload.notes ?? ""}
            oninput={(e) => { if (payload.kind === "Login") payload.notes = e.currentTarget.value || null; }}></textarea>
        </div>
      {:else if payload.kind === "SecureNote"}
        <div class="field">
          <label for="body">Note</label>
          <textarea id="body" rows="10" bind:value={payload.body}></textarea>
        </div>
      {:else if payload.kind === "ApiKey"}
        <div class="field">
          <label for="key">Key</label>
          <input id="key" class="mono" bind:value={payload.key} spellcheck="false" />
        </div>
        <div class="field">
          <label for="knotes">Notes</label>
          <textarea id="knotes" value={payload.notes ?? ""}
            oninput={(e) => { if (payload.kind === "ApiKey") payload.notes = e.currentTarget.value || null; }}></textarea>
        </div>
      {:else if payload.kind === "EnvSecret"}
        <div class="field">
          <label for="val">Value</label>
          <input id="val" class="mono" bind:value={payload.value} spellcheck="false" />
          <p class="faint hint">Can reference another secret as <code>${"{NAME}"}</code>.</p>
        </div>
      {:else if payload.kind === "Card"}
        <div class="field">
          <label for="num">Card number</label>
          <input id="num" class="mono" bind:value={payload.number} spellcheck="false" />
        </div>
        <div class="two">
          <div class="field">
            <label for="exp">Expiry</label>
            <input id="exp" class="mono" placeholder="MM/YY" bind:value={payload.expiry} />
          </div>
          <div class="field">
            <label for="cvv">Security code</label>
            <input id="cvv" class="mono" bind:value={payload.cvv} />
          </div>
        </div>
        <div class="field">
          <label for="holder">Name on card</label>
          <input id="holder" bind:value={payload.holder} />
        </div>
      {/if}

      <div class="field">
        <label for="urls">Websites, one per line</label>
        <textarea id="urls" bind:value={urls} spellcheck="false" rows="2"></textarea>
      </div>
      <div class="two">
        <div class="field">
          <label for="folder">Folder</label>
          <input id="folder" bind:value={folder} />
        </div>
        <div class="field">
          <label for="tags">Tags, comma separated</label>
          <input id="tags" bind:value={tags} />
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .editor { height: 100%; display: flex; flex-direction: column; }
  .head { padding: 18px 22px 14px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  h2 { font-size: 15px; font-weight: 600; margin: 0; }
  .body { padding: 18px 22px 40px; overflow-y: auto; flex: 1; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .lbl { margin-bottom: 5px; }
  .lbl label { margin: 0; }
  .tiny { font-size: 11px; padding: 2px 7px; }
  .genbox {
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 14px;
    margin-bottom: 16px;
    background: var(--bg-raised);
  }
  .hint { font-size: 11px; margin: 6px 0 0; }
  code { font-family: var(--mono); font-size: 11px; }
</style>
