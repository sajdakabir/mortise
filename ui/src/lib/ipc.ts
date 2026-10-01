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
import type { ItemPayload, ItemRow, MetaInput, VaultStatus } from "./types";

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
  unlock: (masterPassword: string, recoveryKit: string) =>
    call<VaultStatus>("unlock", { masterPassword, recoveryKit }),
  lock: () => call<VaultStatus>("lock"),
  signOut: () => call<VaultStatus>("sign_out"),
  search: (query: string) => call<ItemRow[]>("search", { query }),
  reveal: (id: string) => call<ItemPayload>("reveal", { id }),
  saveItem: (id: string | null, meta: MetaInput, payload: ItemPayload) =>
    call<string>("save_item", { id, meta, payload }),
  deleteItem: (id: string) => call<void>("delete_item", { id }),
  copySecret: (id: string, field: string) => call<number>("copy_secret", { id, field }),
  generatePassword: (length: number, lower: boolean, upper: boolean, digits: boolean, symbols: boolean) =>
    call<string>("generate_password", { length, lower, upper, digits, symbols }),
  passwordEntropy: (length: number, lower: boolean, upper: boolean, digits: boolean, symbols: boolean) =>
    call<number>("password_entropy", { length, lower, upper, digits, symbols }),
  touch: () => call<void>("touch"),
};

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

const mockState = { exists: true, unlocked: true, searchable: true, rows: [...MOCK_ROWS] };

async function mock<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  const as = <R,>(v: R) => v as unknown as T;
  const status = (): VaultStatus => ({
    exists: mockState.exists,
    unlocked: mockState.unlocked,
    searchable: mockState.searchable,
    item_count: mockState.rows.length,
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
      return as(status());
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
