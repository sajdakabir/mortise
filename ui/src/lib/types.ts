export type ItemKind = "login" | "note" | "card" | "apikey" | "passkey" | "env";

export interface ItemRow {
  id: string;
  kind: ItemKind;
  title: string;
  username: string | null;
  urls: string[];
  folder: string | null;
  tags: string[];
  updated_at_ms: number;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  /** Search works after one unlock, and survives locking. Not the same as `unlocked`. */
  searchable: boolean;
  item_count: number;
  /** Account key is in the keychain, so unlocking needs only a password. */
  account_key_remembered: boolean;
  /** Touch ID unlock is set up. */
  biometric_enabled: boolean;
}

export interface MetaInput {
  title: string;
  urls: string[];
  username: string | null;
  folder: string | null;
  tags: string[];
}

/** Mirrors the Rust `ItemPayload` enum, which serializes with a `kind` tag. */
export type ItemPayload =
  | { kind: "Login"; password: string; totp_seed: string | null; notes: string | null }
  | { kind: "SecureNote"; body: string }
  | { kind: "Card"; number: string; expiry: string; cvv: string; holder: string }
  | { kind: "ApiKey"; key: string; notes: string | null }
  | { kind: "Passkey"; rp_id: string; credential_id: number[]; private_key: number[]; user_handle: number[] }
  | { kind: "EnvSecret"; value: string };

export interface CmdError {
  code:
    | "no_vault"
    | "locked"
    | "wrong_credentials"
    | "not_found"
    | "bad_request"
    | "schema_too_new"
    | "cancelled"
    | "auth_failed"
    | "requires_signed_app"
    | "biometrics_unavailable"
    | "internal";
  message: string;
}

export function isCmdError(e: unknown): e is CmdError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  return isCmdError(e) ? e.message : "Something went wrong.";
}

export const KIND_LABEL: Record<ItemKind, string> = {
  login: "Login",
  note: "Note",
  card: "Card",
  apikey: "API key",
  passkey: "Passkey",
  env: "Secret",
};

export function emptyPayload(kind: ItemKind): ItemPayload {
  switch (kind) {
    case "login":
      return { kind: "Login", password: "", totp_seed: null, notes: null };
    case "note":
      return { kind: "SecureNote", body: "" };
    case "card":
      return { kind: "Card", number: "", expiry: "", cvv: "", holder: "" };
    case "apikey":
      return { kind: "ApiKey", key: "", notes: null };
    case "env":
      return { kind: "EnvSecret", value: "" };
    case "passkey":
      return { kind: "Passkey", rp_id: "", credential_id: [], private_key: [], user_handle: [] };
  }
}

/** A paired browser. */
/** Whether browsers know where to find the native helper. */
export interface NativeHostStatus {
  /** Chromium-family browsers installed on this Mac. */
  browsers: string[];
  /** Those the helper is currently registered with. */
  registered: string[];
  /** The extension id currently authorised, if any. */
  extension_id: string | null;
  /** Whether the helper binary is actually present beside the app. */
  proxy_present: boolean;
}

export interface PairedBrowser {
  id: string;
  name: string;
  /** Proof key. Present in the backend type; never rendered. */
  key: string;
}

/** Sync configuration and backlog. */
export interface SyncStatus {
  relay_url: string | null;
  pending: number;
  cursor: number;
}

/** What one sync round did. */
export interface SyncReport {
  pushed: number;
  pulled: number;
  applied: number;
  rejected: number;
}
