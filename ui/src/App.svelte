<script lang="ts">
  import Setup from "./views/Setup.svelte";
  import Unlock from "./views/Unlock.svelte";
  import Vault from "./views/Vault.svelte";
  import { ipc, isMock, onVaultLocked } from "./lib/ipc";
  import type { VaultStatus } from "./lib/types";

  let status = $state<VaultStatus | null>(null);

  async function refreshStatus() {
    status = await ipc.status();
  }

  $effect(() => {
    refreshStatus();
    const stop = onVaultLocked(() => refreshStatus());
    return () => { stop.then((f) => f()); };
  });

  // Any interaction defers auto-lock. Throttled hard: this fires on every
  // keystroke otherwise, and it is only a timestamp write.
  let lastTouch = 0;
  function activity() {
    const now = Date.now();
    if (now - lastTouch > 15_000) {
      lastTouch = now;
      ipc.touch();
    }
  }
</script>

<svelte:window onkeydown={activity} onpointerdown={activity} />

{#if isMock}
  <div class="mockbar">Preview — mock data, nothing is encrypted</div>
{/if}

<div class="root" class:offset={isMock}>
  {#if !status}
    <div class="boot"></div>
  {:else if !status.exists}
    <Setup onDone={refreshStatus} />
  {:else if !status.searchable}
    <Unlock {status} onUnlocked={refreshStatus} />
  {:else}
    <Vault {status} onStatus={(s) => (status = s)} />
  {/if}
</div>

<style>
  .root { height: 100%; }
  .root.offset { height: calc(100% - 24px); }
  .boot { height: 100%; }
  .mockbar {
    height: 24px;
    display: grid;
    place-items: center;
    background: var(--warn);
    color: #1a1d24;
    font-size: 11px;
    font-weight: 560;
    letter-spacing: 0.02em;
  }
</style>
