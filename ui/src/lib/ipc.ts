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
  CaptureSummary, ImportReport, ItemPayload, ItemRow, MetaInput,
  NativeHostStatus, PairedBrowser, SyncReport, SyncStatus, VaultStatus,
  ProjectSummary,
  EnvImportReport,
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
  pendingCapture: () => call<CaptureSummary | null>("pending_capture"),
  saveCapture: (title: string | null) => call<string>("save_capture", { title }),
  discardCapture: () => call<void>("discard_capture"),
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
  projects: () => call<ProjectSummary[]>("projects"),
  createProject: (name: string, description: string) =>
    call<ProjectSummary>("create_project", { name, description }),
  addEnvironment: (projectId: string, environment: string) =>
    call<ProjectSummary>("add_environment", { projectId, environment }),
  deleteProject: (projectId: string) => call<void>("delete_project", { projectId }),
  importEnv: (project: string, environment: string, text: string) =>
    call<EnvImportReport>("import_env", { project, environment, text }),
  importEnvFile: (project: string, environment: string, path: string) =>
    call<EnvImportReport>("import_env_file", { project, environment, path }),
  exportEnv: (project: string, environment: string) =>
    call<string>("export_env", { project, environment }),
};

/** Fires when a browser asks to pair. The payload is the browser's name. */
export async function onBrowserPairingRequest(
  handler: (name: string) => void,
): Promise<() => void> {
  if (!IN_TAURI) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<string>("browser-association-requested", (e) => handler(e.payload));
}

/** Fires when the browser offers a login to save. The payload is the origin. */
export async function onLoginCaptured(
  handler: (origin: string) => void,
): Promise<() => void> {
  if (!IN_TAURI) return () => {};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<string>("login-capture-requested", (e) => handler(e.payload));
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

const row = (
  id: string,
  kind: ItemRow["kind"],
  title: string,
  extra: Partial<ItemRow> = {},
): ItemRow => ({
  id: id.repeat(32).slice(0, 32),
  kind,
  title,
  username: null,
  urls: [],
  folder: null,
  project: null,
  environment: null,
  tags: [],
  updated_at_ms: Date.now() - 3_600_000,
  ...extra,
});

const MOCK_ROWS: ItemRow[] = [
  row("a", "login", "GitHub", { username: "octocat", urls: ["https://github.com"], folder: "Work", tags: ["dev"] }),
  row("b", "login", "Fastmail", { username: "me@fastmail.com", urls: ["https://app.fastmail.com"], folder: "Personal" }),
  row("c", "apikey", "Anthropic API", { urls: ["https://console.anthropic.com"], folder: "Work", tags: ["ai"] }),
  row("d", "note", "Recovery codes", { folder: "Personal" }),
  row("e", "card", "Monzo debit", { folder: "Personal" }),
  // Enough of a developer-secrets shape to exercise the Secrets workspace:
  // two projects, one with two environments.
  row("f", "env", "DATABASE_URL", { project: "acme-api", environment: "prod" }),
  row("g", "env", "STRIPE_SECRET_KEY", { project: "acme-api", environment: "prod" }),
  row("h", "env", "JWT_SECRET", { project: "acme-api", environment: "prod" }),
  row("i", "env", "DATABASE_URL", { project: "acme-api", environment: "dev" }),
  row("j", "env", "REDIS_URL", { project: "acme-api", environment: "dev" }),
  row("m", "env", "EMPTY_ON_PURPOSE", { project: "acme-api", environment: "dev" }),
  row("k", "env", "SESSION_SECRET", { project: "acme-web", environment: "prod" }),
];

const mockState = {
  exists: true, unlocked: true, searchable: true,
  accountKeyRemembered: true, biometricEnabled: false,
  rows: [...MOCK_ROWS],
  browsers: [] as PairedBrowser[],
  nativeHost: null as string | null,
  relayUrl: null as string | null,
  projects: [
    { id: "p1", name: "acme-api", description: "The API", environments: ["dev", "staging", "prod"] },
    { id: "p2", name: "acme-web", description: "", environments: ["prod"] },
  ],
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
    case "pending_capture":
      return as(null);
    case "discard_capture":
      return as(undefined);
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
    case "reveal": {
      const r = mockState.rows.find((x) => x.id === args.id);
      // One row deliberately holds an empty value: a .env may legitimately
      // contain KEY=, and revealing that must look different from not having
      // revealed it at all.
      if (r?.kind === "env")
        return as({ kind: "EnvSecret", value: r.title === "EMPTY_ON_PURPOSE" ? "" : `value-of-${r.title}` });
      if (r?.kind === "apikey") return as({ kind: "ApiKey", key: "placeholder-key", notes: null });
      if (r?.kind === "note") return as({ kind: "SecureNote", body: "a note" });
      return as({ kind: "Login", password: "correct-horse-battery-staple", totp_seed: null, notes: null });
    }
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
    case "projects":
      return as(
        mockState.projects.map((p) => ({
          ...p,
          secret_count: mockState.rows.filter((r) => r.project === p.name).length,
        })),
      );
    case "create_project": {
      const name = String(args.name).trim();
      if (!name) throw { code: "invalid", message: "a project needs a name" };
      if (mockState.projects.some((p) => p.name.toLowerCase() === name.toLowerCase()))
        throw { code: "invalid", message: "a project with that name already exists" };
      const p = { id: `p${mockState.projects.length + 1}`, name,
        description: String(args.description ?? ""), environments: ["dev", "staging", "prod"] };
      mockState.projects.push(p);
      return as({ ...p, secret_count: 0 });
    }
    case "add_environment": {
      const p = mockState.projects.find((x) => x.id === args.projectId);
      if (!p) throw { code: "invalid", message: "no such project" };
      const e = String(args.environment).trim();
      if (p.environments.some((x) => x.toLowerCase() === e.toLowerCase()))
        throw { code: "invalid", message: "that environment already exists" };
      p.environments.push(e);
      return as({ ...p, secret_count: mockState.rows.filter((r) => r.project === p.name).length });
    }
    case "delete_project": {
      const i = mockState.projects.findIndex((x) => x.id === args.projectId);
      if (i < 0) throw { code: "invalid", message: "no such project" };
      if (mockState.rows.some((r) => r.project === mockState.projects[i].name))
        throw { code: "invalid", message: "that project still has secrets in it" };
      mockState.projects.splice(i, 1);
      return as(undefined);
    }
    case "import_env_file":
      return as({ added: 2, updated: 0, unchanged: 0, skipped: 1, unreadable: 0, duplicates: [] });
    case "import_env": {
      const project = String(args.project), environment = String(args.environment);
      let added = 0, updated = 0;
      for (const line of String(args.text).split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const eq = t.indexOf("=");
        if (eq < 1) continue;
        const key = t.slice(0, eq).trim();
        const existing = mockState.rows.find(
          (r) => r.kind === "env" && r.project === project && r.environment === environment && r.title === key,
        );
        if (existing) { updated += 1; continue; }
        mockState.rows.push(row(String(mockState.rows.length), "env", key, { project, environment }));
        added += 1;
      }
      return as({ added, updated, unchanged: 0, skipped: 0, unreadable: 0, duplicates: [] });
    }
    case "export_env":
      return as(
        mockState.rows
          .filter((r) => r.kind === "env" && r.project === args.project && r.environment === args.environment)
          .map((r) => `${r.title}=mock-value`)
          .sort()
          .join("\n") + "\n",
      );
    default:
      return as(undefined);
  }
}
