<script lang="ts">
  /// Shown in the empty main pane while setup is incomplete.
  ///
  /// A fresh vault used to say "Select an item." into a void, which told a new
  /// user nothing — least of all that autofill needs a browser extension, and
  /// that without it this is an encrypted list you copy out of by hand.
  ///
  /// It is a panel rather than a wizard on purpose. Blocking the vault behind
  /// a multi-step setup to use a password manager is the kind of weight this
  /// product is meant not to have. Each step ticks itself from real state, so
  /// it is a status display rather than a checklist you mark off yourself, and
  /// it stops rendering once there is nothing left to do.
  import { ipc } from "./ipc";
  import { errorMessage, type NativeHostStatus, type PairedBrowser, type VaultStatus } from "./types";

  let { status, revision = 0, onAddItem }: {
    status: VaultStatus;
    /// Bumped by the parent when something that might have paired a browser
    /// happened — closing Settings, mainly. The keychain read behind
    /// `listBrowsers` is too expensive to poll, so the parent says when.
    revision?: number;
    onAddItem: () => void;
  } = $props();

  let browsers = $state<PairedBrowser[]>([]);
  let host = $state<NativeHostStatus | null>(null);
  let expanded = $state(false);
  let extensionId = $state("");
  let connecting = $state(false);
  let connectError = $state("");

  async function refresh() {
    try {
      browsers = await ipc.listBrowsers();
    } catch {
      // A failed read means "none paired" for display purposes. There is
      // nothing useful to say to the user here and an error banner on the
      // welcome screen would be a terrible first impression.
      browsers = [];
    }
    try {
      host = await ipc.nativeHostStatus();
      if (host.extension_id && !extensionId) extensionId = host.extension_id;
    } catch {
      host = null;
    }
  }

  $effect(() => {
    void revision;
    refresh();
  });

  /// Coming back from the browser is the moment a pairing most often becomes
  /// true, and it costs nothing to check then.
  $effect(() => {
    const onFocus = () => refresh();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  });

  const hasItem = $derived(status.item_count > 0);
  const hasBrowser = $derived(browsers.length > 0);
  const registered = $derived(host?.registered ?? []);
  const done = $derived(hasItem && hasBrowser);

  async function connect() {
    if (!extensionId.trim() || connecting) return;
    connecting = true;
    connectError = "";
    try {
      await ipc.installNativeHost(extensionId.trim());
      await refresh();
    } catch (e) {
      connectError = errorMessage(e);
    } finally {
      connecting = false;
    }
  }
</script>

{#if !done}
  <div class="wrap">
    <div class="card">
      <h2>Get set up</h2>
      <p class="sub faint">Two things and you are done.</p>

      <div class="step" class:complete={hasItem}>
        <span class="tick" aria-hidden="true">
          {#if hasItem}
            <svg viewBox="0 0 16 16" width="15" height="15">
              <path fill="none" stroke="currentColor" stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round" d="M3.5 8.5 L6.5 11.5 L12.5 4.5" />
            </svg>
          {/if}
        </span>
        <div class="body">
          <h3>Save your first login</h3>
          {#if hasItem}
            <p class="faint">
              {status.item_count}
              {status.item_count === 1 ? "item saved" : "items saved"}.
            </p>
          {:else}
            <p class="faint">
              A site, your username, and a password. The generator will make a
              strong one for you.
            </p>
            <button class="primary small" onclick={onAddItem}>Add a login</button>
          {/if}
        </div>
      </div>

      <div class="step" class:complete={hasBrowser}>
        <span class="tick" aria-hidden="true">
          {#if hasBrowser}
            <svg viewBox="0 0 16 16" width="15" height="15">
              <path fill="none" stroke="currentColor" stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round" d="M3.5 8.5 L6.5 11.5 L12.5 4.5" />
            </svg>
          {/if}
        </span>
        <div class="body">
          <h3>Connect your browser</h3>
          {#if hasBrowser}
            <p class="faint">
              Paired with {browsers.map((b) => b.name).join(", ")}. Press
              <kbd>⌘</kbd><kbd>⇧</kbd><kbd>L</kbd> on a login page to fill it.
            </p>
          {:else}
            <p class="faint">
              Without the extension nothing fills automatically — you can still
              copy passwords out of here by hand, but that is not the point of
              the app.
            </p>
            <button class="ghost small" onclick={() => (expanded = !expanded)}>
              {expanded ? "Hide steps" : "Show me how"}
            </button>

            {#if expanded}
              {#if host && !host.proxy_present}
                <!-- The one thing the app genuinely cannot do for itself in a
                     dev checkout: the helper has to be compiled first. -->
                <p class="warn">
                  The helper binary is missing. Build it with
                  <code>cargo build -p mortise-proxy</code>, then reopen this.
                </p>
              {/if}

              <!-- Until the extension is in the Chrome Web Store this is a
                   load-unpacked flow, so it is written as one. The ID step
                   exists because an unpacked extension's ID is derived from
                   its folder path and so differs on every machine; a published
                   one has a fixed ID and this field can disappear. -->
              <ol class="steps">
                <li>
                  Open <code>chrome://extensions</code>, turn on
                  <strong>Developer mode</strong>, click
                  <strong>Load unpacked</strong> and pick the
                  <code>extension</code> folder of this repo.
                </li>
                <li>
                  Paste the extension ID that Chrome shows under its name:
                  <div class="connect">
                    <input
                      class="mono"
                      placeholder="32 letters, a–p"
                      spellcheck="false"
                      bind:value={extensionId}
                      onkeydown={(e) => { if (e.key === "Enter") connect(); }} />
                    <button class="primary tiny" disabled={!extensionId.trim() || connecting}
                      onclick={connect}>
                      {connecting ? "…" : "Connect"}
                    </button>
                  </div>
                  {#if connectError}
                    <p class="warn">{connectError}</p>
                  {:else if registered.length > 0}
                    <p class="good">Registered with {registered.join(", ")}.</p>
                  {/if}
                </li>
                <li>
                  Restart the browser, click the TruePassword icon in the
                  toolbar and press <strong>Pair</strong>. Approve it here and
                  this step ticks itself.
                </li>
              </ol>
            {/if}
          {/if}
        </div>
      </div>
    </div>
  </div>
{:else}
  <div class="wrap">
    <p class="faint">Select an item.</p>
  </div>
{/if}

<style>
  .wrap {
    height: 100%;
    display: grid;
    place-items: center;
    padding: 32px 24px;
    overflow-y: auto;
  }
  .card {
    width: 100%;
    max-width: 440px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-raised);
    box-shadow: var(--shadow-1);
    padding: var(--s5);
  }
  h2 { font-size: 16px; font-weight: 600; margin: 0; }
  .sub { font-size: 12.5px; margin: 4px 0 22px; }

  .step { display: flex; gap: 12px; padding: 14px 0; border-top: 1px solid var(--border); }
  .step h3 { font-size: 13px; font-weight: 600; margin: 0 0 4px; }
  .step p { font-size: 12px; margin: 0; line-height: 1.5; }
  .body { min-width: 0; flex: 1; }

  /* An empty ring until the step is genuinely satisfied. Nothing here is ever
     ticked by the user, so a checkbox affordance would be a lie. */
  .tick {
    flex-shrink: 0;
    width: 19px;
    height: 19px;
    margin-top: 1px;
    border-radius: 50%;
    border: 1.5px solid var(--border-strong);
    display: grid;
    place-items: center;
    color: var(--accent-ink);
  }
  .complete .tick { background: var(--ok); border-color: var(--ok); color: #15171d; }

  .small { font-size: 12px; padding: 5px 11px; margin-top: 10px; }

  .steps { margin: 12px 0 0; padding-left: 18px; font-size: 12px; line-height: 1.65; }
  .steps li { margin-bottom: 10px; color: var(--text-dim); }
  .steps strong { color: var(--text); font-weight: 600; }
  code {
    font-family: var(--mono);
    font-size: 11px;
    background: var(--bg-input);
    padding: 1px 5px;
    border-radius: 4px;
  }

  .connect { display: flex; gap: 8px; margin-top: 6px; }
  .connect input { font-size: 11.5px; padding: 5px 8px; }
  .tiny { font-size: 11px; padding: 2px 9px; flex-shrink: 0; }

  .warn { color: var(--warn); margin-top: 6px !important; }
  .good { color: var(--ok); margin-top: 6px !important; }

  kbd {
    font-family: var(--font);
    font-size: 10.5px;
    border: 1px solid var(--border-strong);
    border-radius: 4px;
    padding: 0 4px;
    margin: 0 1px;
  }
</style>
