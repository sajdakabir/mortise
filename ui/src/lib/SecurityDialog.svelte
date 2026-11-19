<script lang="ts">
  /// The frame for a question the app must put to the human before anything
  /// else happens: pairing a browser, letting a command read secrets.
  ///
  /// No backdrop dismissal and no Escape. Every other dialog in the app can
  /// be waved away; these are security decisions, and "I clicked outside it"
  /// is not an answer to them.
  import type { Snippet } from "svelte";

  let { label, children }: { label: string; children: Snippet } = $props();
</script>

<div class="backdrop">
  <div class="panel" role="dialog" aria-modal="true" aria-label={label} tabindex="-1">
    {@render children()}
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: grid;
    place-items: center;
    padding: 32px 20px;
    /* Above the item editor: a request that opened while a form was up still
       has to be answerable. */
    z-index: 40;
  }
  .panel {
    width: 100%;
    max-width: 420px;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5);
    padding: 20px 22px 18px;
  }
  .panel :global(h2) { font-size: 15px; font-weight: 600; margin: 0 0 10px; }
  .panel :global(p) { font-size: 12px; line-height: 1.55; margin: 0 0 10px; }
  .panel :global(.err) { color: var(--danger); }
  .panel :global(.row) { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
</style>
