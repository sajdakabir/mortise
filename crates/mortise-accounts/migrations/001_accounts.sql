-- Account metadata only. Vault items, env values, and private keys never belong here.
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
 email TEXT NOT NULL, name TEXT NOT NULL, created_at BIGINT NOT NULL, UNIQUE(issuer,subject));
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 certificate TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','trusted','revoked')),
 created_at BIGINT NOT NULL, approved_by TEXT REFERENCES devices(id));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 device_id TEXT NOT NULL REFERENCES devices(id), expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS logins(id TEXT PRIMARY KEY, nonce TEXT NOT NULL, certificate TEXT NOT NULL,
 device_id TEXT NOT NULL, device_name TEXT NOT NULL, expires_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(device_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY(device_id,nonce));
CREATE TABLE IF NOT EXISTS teams(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS memberships(team_id TEXT NOT NULL REFERENCES teams(id), account_id TEXT NOT NULL REFERENCES accounts(id),
 role TEXT NOT NULL CHECK(role IN ('owner','admin','member')), PRIMARY KEY(team_id,account_id));
CREATE TABLE IF NOT EXISTS invitations(id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 team_id TEXT NOT NULL REFERENCES teams(id), created_by TEXT NOT NULL REFERENCES accounts(id), email TEXT,
 role TEXT NOT NULL CHECK(role IN ('admin','member')), expires_at BIGINT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('issued','requested','accepted','declined','revoked')),
 requester TEXT REFERENCES accounts(id));
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE INDEX logins_device ON logins(device_id);
CREATE INDEX nonces_expiry ON nonces(expires_at);
CREATE INDEX devices_account ON devices(account_id);
CREATE INDEX memberships_account ON memberships(account_id);
