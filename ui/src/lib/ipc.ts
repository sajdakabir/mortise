/**
 * The only place that talks to the backend.
 *
 * Everything is funnelled through here so the IPC surface stays as visible in
 * the frontend as it is in `commands.rs`. If a component imports `invoke`
 * directly, that is a bug.
 *
 * When the page is loaded outside Tauri — `npm run dev` in a plain browser —
 * these fall back to an in-memory mock so the UI can be developed and reviewed
 * without launching the app. The mock holds fake data only; it never pretends
 * to encrypt anything.
 */
import type {
  ImportReport, ItemPayload, ItemRow, MetaInput, NativeHostStatus,
  PairedBrowser, SyncReport, SyncStatus, VaultStatus,
} from "./types";

const IN_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!IN_TAURI) return mock<T>(cmd, args ?? {});
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export const ipc = {
  status: () => call<VaultStatus>("status"),
  createVault: (masterPassword: string) =>
    call<{ recovery_kit: string }>("create_vault", { masterPassword }),
  unlock: (masterPassword: string, recoveryKit: string | null) =>
    call<VaultStatus>("unlock", { masterPassword, recoveryKit }),
  unlockBiometric: () => call<VaultStatus>("unlock_biometric"),
  setBiometric: (enabled: boolean) => call<VaultStatus>("set_biometric", { enabled }),
  forgetAccountKey: () => call<VaultStatus>("forget_account_key"),
  lock: () => call<VaultStatus>("lock"),
  signOut: () => call<VaultStatus>("sign_out"),
  search: (query: string) => call<ItemRow[]>("search", { query }),
  reveal: (id: string) => call<ItemPayload>("reveal", { id }),
  saveItem: (id: string | null, meta: MetaInput, payload: ItemPayload) =>
    call<string>("save_item", { id, meta, payload }),
  deleteItem: (id: string) => call<void>("delete_item", { id }),
  importCsv: (path: string) => call<ImportReport>("import_csv", { path }),
  copySecret: (id: string, field: string) => call<number>("copy_secret", { id, field }),
  generatePassword: (length: number, lower: boolean, upper: boolean, digits: boolean, symbols: boolean) =>
    call<string>("generate_password", { length, lower, upper, digits, symbols }),
  passwordEntropy: (length: number, lower: boolean, upper: boolean, digits: boolean, symbols: boolean) =>
    call<number>("password_entropy", { length, lower, upper, digits, symbols }),
  touch: () => call<void>("touch"),
  approveBrowser: () => call<string>("approve_browser"),
  rejectBrowser: () => call<void>("reject_browser"),
  pendingBrowser: () => call<string | null>("pending_browser"),
  listBrowsers: () => call<PairedBrowser[]>("list_browsers"),
  unpairBrowser: (id: string) => call<void>("unpair_browser", { id }),
  nativeHostStatus: () => call<NativeHostStatus>("native_host_status"),
  installNativeHost: (extensionId: string) =>
    call<string[]>("install_native_host", { extensionId }),
  uninstallNativeHost: () => call<void>("uninstall_native_host"),
  syncStatus: () => call<SyncStatus>("sync_status"),
  setRelay: (url: string | null) => call<SyncStatus>("set_relay", { url }),
  syncNow: () => call<SyncReport>("sync_now"),
  claimVaultOnRelay: () => call<void>("claim_vault_on_relay"),
};

/** Fires when a browser asks to pair. The payload is the browser's name. */
export async function onBrowserPairingRequest(
  handler: (name: string) => void,
): Promise<() => void> {
  if (!IN_TAURI) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<string>("browser-association-requested", (e) => handler(e.payload));
}

/** Fires when the backend auto-locks, so the UI can drop anything revealed. */
export async function onVaultLocked(handler: () => void): Promise<() => void> {
  if (!IN_TAURI) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  const unlisten = await listen("vault-locked", handler);
  return unlisten;
}

export const isMock = !IN_TAURI;

// --- browser-only mock ---------------------------------------------------

const MOCK_ROWS: ItemRow[] = [
  { id: "a".repeat(32), kind: "login", title: "GitHub", username: "octocat", urls: ["https://github.com"], folder: "Work", tags: ["dev"], updated_at_ms: Date.now() - 3_600_000 },
  { id: "b".repeat(32), kind: "login", title: "Fastmail", username: "me@fastmail.com", urls: ["https://app.fastmail.com"], folder: "Personal", tags: [], updated_at_ms: Date.now() - 86_400_000 },
  { id: "c".repeat(32), kind: "apikey", title: "Anthropic API", username: null, urls: ["https://console.anthropic.com"], folder: "Work", tags: ["ai"], updated_at_ms: Date.now() - 172_800_000 },
  { id: "d".repeat(32), kind: "note", title: "Recovery codes", username: null, urls: [], folder: "Personal", tags: [], updated_at_ms: Date.now() - 604_800_000 },
  { id: "e".repeat(32), kind: "card", title: "Monzo debit", username: null, urls: [], folder: "Personal", tags: [], updated_at_ms: Date.now() - 1_209_600_000 },
];

const mockState = {
  exists: true, unlocked: true, searchable: true,
  accountKeyRemembered: true, biometricEnabled: false,
  rows: [...MOCK_ROWS],
  browsers: [] as PairedBrowser[],
  nativeHost: null as string | null,
  relayUrl: null as string | null,
};

async function mock<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  const as = <R,>(v: R) => v as unknown as T;
  const status = (): VaultStatus => ({
    exists: mockState.exists,
    unlocked: mockState.unlocked,
    searchable: mockState.searchable,
    item_count: mockState.rows.length,
    account_key_remembered: mockState.accountKeyRemembered,
    biometric_enabled: mockState.biometricEnabled,
  });

  switch (cmd) {
    case "status":
      return as(status());
    case "create_vault":
      mockState.exists = mockState.unlocked = mockState.searchable = true;
      return as({ recovery_kit: "TP1-AAISE-M2EKV-THPCE-ZVK54-ZXPO7-4ASGR-LHRGV-43376-3S5JQ-5SUGI-IIJCY" });
    case "unlock":
      mockState.unlocked = mockState.searchable = true;
      return as(status());
    case "lock":
      mockState.unlocked = false;
      return as(status());
    case "sign_out":
      mockState.unlocked = mockState.searchable = false;
      mockState.accountKeyRemembered = mockState.biometricEnabled = false;
      return as(status());
    case "unlock_biometric":
      mockState.unlocked = mockState.searchable = true;
      return as(status());
    case "set_biometric":
      mockState.biometricEnabled = Boolean(args.enabled);
      return as(status());
    case "forget_account_key":
      mockState.accountKeyRemembered = false;
      return as(status());
    case "import_csv":
      return as({
        source: "Chrome", imported: 12, duplicates: 2,
        empty: 1, unsupported: 0, failed: 0,
      });
    case "pending_browser":
      return as(null);
    case "list_browsers":
      return as(mockState.browsers);
    case "native_host_status":
      return as({
        browsers: ["Google Chrome"],
        registered: mockState.nativeHost ? ["Google Chrome"] : [],
        extension_id: mockState.nativeHost,
        proxy_present: true,
      });
    case "install_native_host":
      mockState.nativeHost = String(args.extensionId ?? "");
      return as(["Google Chrome"]);
    case "uninstall_native_host":
      mockState.nativeHost = null;
      return as(undefined);
    case "approve_browser":
      mockState.browsers = [...mockState.browsers, { id: "mock1", name: "Google Chrome", key: "" }];
      return as("mock1");
    case "unpair_browser":
      mockState.browsers = mockState.browsers.filter((b) => b.id !== args.id);
      return as(undefined);
    case "reject_browser":
      return as(undefined);
    case "sync_status":
      return as({ relay_url: mockState.relayUrl, pending: 0, cursor: 0 });
    case "set_relay":
      mockState.relayUrl = (args.url as string | null) || null;
      return as({ relay_url: mockState.relayUrl, pending: 0, cursor: 0 });
    case "sync_now":
      return as({ pushed: 2, pulled: 1, applied: 1, rejected: 0 });
    case "claim_vault_on_relay":
      return as(undefined);
    case "search": {
      const q = String(args.query ?? "").trim().toLowerCase();
      const hits = q
        ? mockState.rows.filter((r) =>
            [r.title, r.username ?? "", r.folder ?? "", ...r.urls, ...r.tags]
              .join(" ")
              .toLowerCase()
              .includes(q),
          )
        : mockState.rows;
      return as(hits);
    }
    case "reveal":
      return as({ kind: "Login", password: "correct-horse-battery-staple", totp_seed: null, notes: null });
    case "save_item":
      return as(String(args.id ?? "f".repeat(32)));
    case "delete_item":
      mockState.rows = mockState.rows.filter((r) => r.id !== args.id);
      return as(undefined);
    case "copy_secret":
      return as(30);
    case "generate_password": {
      const n = Number(args.length ?? 20);
      const set = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*";
      const bytes = crypto.getRandomValues(new Uint32Array(n));
      return as(Array.from(bytes, (b) => set[b % set.length]).join(""));
    }
    case "password_entropy":
      return as(Math.log2(70) * Number(args.length ?? 20));
    default:
      return as(undefined);
  }
}
