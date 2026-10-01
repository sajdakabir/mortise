<script lang="ts">
  import { ipc } from "./ipc";

  let { onUse }: { onUse: (pw: string) => void } = $props();

  let length = $state(20);
  let lower = $state(true);
  let upper = $state(true);
  let digits = $state(true);
  let symbols = $state(true);
  let value = $state("");
  let entropy = $state(0);

  const anyClass = $derived(lower || upper || digits || symbols);

  async function regenerate() {
    if (!anyClass) return;
    value = await ipc.generatePassword(length, lower, upper, digits, symbols);
    entropy = await ipc.passwordEntropy(length, lower, upper, digits, symbols);
  }

  // Regenerate whenever the spec changes.
  $effect(() => {
    void length; void lower; void upper; void digits; void symbols;
    regenerate();
  });

  const strength = $derived(entropy >= 100 ? "strong" : entropy >= 70 ? "ok" : "weak");
</script>

<div class="gen">
  <div class="out mono">{value || "—"}</div>

  <div class="meter">
    <div class="bar {strength}" style="width:{Math.min(100, entropy / 1.4)}%"></div>
  </div>
  <p class="faint bits">{Math.round(entropy)} bits of entropy</p>

  <div class="field">
    <label for="len">Length — {length}</label>
    <input id="len" type="range" min="8" max="64" bind:value={length} />
  </div>

  <div class="classes">
    <label><input type="checkbox" bind:checked={lower} /> a–z</label>
    <label><input type="checkbox" bind:checked={upper} /> A–Z</label>
    <label><input type="checkbox" bind:checked={digits} /> 0–9</label>
    <label><input type="checkbox" bind:checked={symbols} /> !@#</label>
  </div>

  {#if !anyClass}<p class="hint">Pick at least one kind of character.</p>{/if}

  <div class="row actions">
    <button onclick={regenerate} disabled={!anyClass}>Regenerate</button>
    <button class="primary" onclick={() => onUse(value)} disabled={!value}>Use this</button>
  </div>

  <p class="faint footnote">
    Generated in Rust with rejection sampling, so every character is uniform. The
    bit count is only honest because of that.
  </p>
</div>

<style>
  .gen { padding: 2px; }
  .out {
    background: var(--bg-input);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    padding: 12px;
    font-size: 14px;
    word-break: break-all;
    user-select: all;
    min-height: 44px;
  }
  .meter { height: 3px; background: var(--border); border-radius: 2px; margin: 10px 0 5px; overflow: hidden; }
  .bar { height: 100%; transition: width 0.15s; }
  .bar.weak { background: var(--danger); }
  .bar.ok { background: var(--warn); }
  .bar.strong { background: var(--ok); }
  .bits { font-size: 11px; margin: 0 0 16px; }
  .classes { display: flex; gap: 14px; margin-bottom: 14px; }
  .classes label { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text); margin: 0; }
  .classes input { width: auto; }
  input[type="range"] { padding: 0; accent-color: var(--accent); }
  .actions { justify-content: flex-end; margin-top: 4px; }
  .hint { color: var(--warn); font-size: 11px; margin: 0 0 10px; }
  .footnote { font-size: 10.5px; line-height: 1.6; margin: 14px 0 0; }
</style>
