use crate::database::{Database, Transaction, params};
use crate::{Error, Result, protocol::*};
use rusqlite::{Connection, OptionalExtension};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Store(Arc<Database>);
#[derive(Clone)]
pub struct Actor {
    pub account_id: String,
    pub device_id: String,
}
/// Only construct from cryptographically verified OIDC claims.
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub name: String,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
 email TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(issuer,subject));
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 certificate TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','trusted','revoked')),
 created_at INTEGER NOT NULL, approved_by TEXT REFERENCES devices(id));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 device_id TEXT NOT NULL REFERENCES devices(id), expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS logins(id TEXT PRIMARY KEY, nonce TEXT NOT NULL, certificate TEXT NOT NULL,
 device_id TEXT NOT NULL, device_name TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(device_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY(device_id,nonce));
CREATE TABLE IF NOT EXISTS teams(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS memberships(team_id TEXT NOT NULL REFERENCES teams(id), account_id TEXT NOT NULL REFERENCES accounts(id),
 role TEXT NOT NULL CHECK(role IN ('owner','admin','member')), PRIMARY KEY(team_id,account_id));
CREATE TABLE IF NOT EXISTS invitations(id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 team_id TEXT NOT NULL REFERENCES teams(id), created_by TEXT NOT NULL REFERENCES accounts(id), email TEXT,
 role TEXT NOT NULL CHECK(role IN ('admin','member')), expires_at INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('issued','requested','accepted','declined','revoked')),
 requester TEXT REFERENCES accounts(id));
PRAGMA user_version=1;
PRAGMA application_id=1296122691;
";

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(Error::Storage),
            }
        }
        Self::initialize(Connection::open(path)?)
    }
    pub fn memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?)
    }
    fn initialize(conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")?;
        let app: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tables: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0),
        )?;
        if (app != 1296122691 && tables != 0) || version > 1 {
            return Err(Error::Invalid("Not a supported accounts database."));
        }
        conn.execute_batch(SCHEMA)?;
        Ok(Self(Arc::new(Database::Sqlite(Mutex::new(conn)))))
    }
    fn tx<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        self.0.tx(f)
    }

    /// Connect to an already migrated, TLS-verified account Postgres database.
    #[cfg(feature = "postgres")]
    pub fn postgres(url: &str) -> Result<Self> {
        Ok(Self(Arc::new(Database::postgres(url)?)))
    }
    /// Apply account-only migrations through a direct Postgres connection.
    #[cfg(feature = "postgres")]
    pub fn migrate_postgres(url: &str) -> Result<()> {
        crate::database::migrate(url)
    }

    pub fn start_login(
        &self,
        input: &LoginStart,
        proof: &Proof,
        body: &[u8],
        now: i64,
    ) -> Result<LoginChallenge> {
        valid_name(&input.device_name)?;
        let cert = certificate(&input.certificate)?;
        proof.verify(&cert, "POST", "/v1/auth/start", "", body, now)?;
        self.tx(|tx| {
            tx.execute("DELETE FROM logins WHERE expires_at<=?1", params![now])?;
            let total: i64 =
                tx.query_row("SELECT count(*) FROM logins", params![], |r| r.get(0))?;
            let own: i64 = tx.query_row(
                "SELECT count(*) FROM logins WHERE device_id=?1",
                params![&proof.device_id],
                |r| r.get(0),
            )?;
            if total >= 1024 || own >= 5 {
                return Err(Error::Conflict(
                    "Too many sign-in attempts. Try again later.",
                ));
            }
            consume_nonce(tx, proof, now)?;
            let id = random()?;
            let nonce = random()?;
            let expires_at = now + LOGIN_LIFETIME;
            tx.execute(
                "INSERT INTO logins VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    id,
                    nonce,
                    input.certificate,
                    proof.device_id,
                    input.device_name,
                    expires_at
                ],
            )?;
            Ok(LoginChallenge {
                id,
                nonce,
                expires_at,
            })
        })
    }
    pub fn login_nonce(&self, id: &str, proof: &Proof, body: &[u8], now: i64) -> Result<String> {
        self.tx(|tx| {
            let (nonce, cert): (String, String) = tx
                .query_row(
                    "SELECT nonce,certificate FROM logins WHERE id=?1 AND expires_at>?2",
                    params![id, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(Error::Unauthorized)?;
            proof.verify(
                &certificate(&cert)?,
                "POST",
                "/v1/auth/finish",
                "",
                body,
                now,
            )?;
            Ok(nonce)
        })
    }
    pub fn finish_login(
        &self,
        id: &str,
        identity: &Identity,
        proof: &Proof,
        body: &[u8],
        now: i64,
    ) -> Result<Session> {
        valid_name(&identity.name)?;
        let email = normalize_email(&identity.email)?;
        if identity.subject.is_empty() || identity.subject.len() > 255 {
            return Err(Error::Unauthorized);
        }
        self.tx(|tx| {
            let (cert, name): (String, String) = tx
                .query_row(
                    "SELECT certificate,device_name FROM logins WHERE id=?1 AND expires_at>?2",
                    params![id, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(Error::Unauthorized)?;
            proof.verify(
                &certificate(&cert)?,
                "POST",
                "/v1/auth/finish",
                "",
                body,
                now,
            )?;
            consume_nonce(tx, proof, now)?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT id FROM accounts WHERE issuer=?1 AND subject=?2",
                    params![identity.issuer, identity.subject],
                    |r| r.get(0),
                )
                .optional()?;
            let fresh = existing.is_none();
            let account_id = match existing {
                Some(id) => id,
                None => random()?,
            };
            if fresh {
                tx.execute(
                    "INSERT INTO accounts VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        account_id,
                        identity.issuer,
                        identity.subject,
                        email,
                        identity.name,
                        now
                    ],
                )?;
            } else {
                tx.execute(
                    "UPDATE accounts SET email=?1,name=?2 WHERE id=?3",
                    params![email, identity.name, account_id],
                )?;
            }
            let registered: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT account_id,certificate,status FROM devices WHERE id=?1",
                    params![&proof.device_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((owner, old_cert, status)) = registered {
                // Certificates may be reissued with a new timestamp. The full
                // public device and identity must still match the enrolled ones.
                let old = certificate(&old_cert)?;
                let incoming = certificate(&cert)?;
                if owner != account_id
                    || old.device() != incoming.device()
                    || old.identity() != incoming.identity()
                    || status == "revoked"
                {
                    return Err(Error::Forbidden);
                }
            } else {
                tx.execute(
                    "INSERT INTO devices VALUES(?1,?2,?3,?4,?5,?6,NULL)",
                    params![
                        proof.device_id,
                        account_id,
                        cert,
                        name,
                        if fresh { "trusted" } else { "pending" },
                        now
                    ],
                )?;
            }
            let token = random()?;
            let expires_at = now + SESSION_LIFETIME;
            tx.execute("DELETE FROM sessions WHERE expires_at<=?1", params![now])?;
            tx.execute(
                "INSERT INTO sessions VALUES(?1,?2,?3,?4)",
                params![digest(&token), account_id, proof.device_id, expires_at],
            )?;
            tx.execute("DELETE FROM logins WHERE id=?1", params![id])?;
            Ok(Session {
                token,
                expires_at,
                account: Account {
                    id: account_id,
                    email,
                    name: identity.name.clone(),
                },
            })
        })
    }
    pub fn authenticate(
        &self,
        token: &str,
        proof: &Proof,
        method: &str,
        path: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Actor> {
        if token.len() != 64 {
            return Err(Error::Unauthorized);
        }
        self.tx(|tx| {
            let (account_id, cert): (String,String) = tx.query_row("SELECT s.account_id,d.certificate FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.token_hash=?1 AND s.device_id=?2 AND s.expires_at>?3 AND d.status!='revoked'", params![digest(token),proof.device_id,now], |r| Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(Error::Unauthorized)?;
            proof.verify(&certificate(&cert)?, method, path, token, body, now)?;
            consume_nonce(tx, proof, now)?;
            Ok(Actor { account_id, device_id: proof.device_id.clone() })
        })
    }
    pub fn logout(&self, token: &str) -> Result<()> {
        self.tx(|tx| {
            tx.execute(
                "DELETE FROM sessions WHERE token_hash=?1",
                params![digest(token)],
            )?;
            Ok(())
        })
    }
    pub fn dashboard(&self, actor: &Actor) -> Result<Dashboard> {
        self.tx(|tx| {
            let account = tx.query_row("SELECT id,email,name FROM accounts WHERE id=?1", params![&actor.account_id], |r| Ok(Account {id:r.get(0)?,email:r.get(1)?,name:r.get(2)?}))?;
            let mut query = tx.prepare("SELECT id,name,certificate,status,created_at FROM devices WHERE account_id=?1 ORDER BY created_at,id")?;
            let devices = query.query_map(params![&actor.account_id], |r| Ok(DeviceInfo {id:r.get(0)?,name:r.get(1)?,certificate:r.get(2)?,status:r.get(3)?,created_at:r.get(4)?,fingerprint:String::new()}))?.collect::<std::result::Result<Vec<_>,_>>()?.into_iter().map(|mut d| { d.fingerprint = digest(&d.certificate); d }).collect();
            let mut query = tx.prepare("SELECT t.id,t.name,m.role FROM teams t JOIN memberships m ON m.team_id=t.id WHERE m.account_id=?1 ORDER BY t.name")?;
            let teams = query.query_map(params![&actor.account_id], |r| Ok(Team{id:r.get(0)?,name:r.get(1)?,role:r.get(2)?}))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(Dashboard {account,current_device_id:actor.device_id.clone(),devices,teams})
        })
    }
    pub fn approve_device(&self, actor: &Actor, id: &str, expected: &str) -> Result<()> {
        self.tx(|tx| {
            trusted(tx, actor)?;
            if id == actor.device_id { return Err(Error::Forbidden); }
            let changed = tx.execute("UPDATE devices SET status='trusted',approved_by=?1 WHERE id=?2 AND account_id=?3 AND status='pending' AND certificate=?4", params![actor.device_id,id,actor.account_id,expected])?;
            if changed != 1 { return Err(Error::Conflict("Device request changed. Refresh and review it again.")); }
            Ok(())
        })
    }
    pub fn revoke_device(&self, actor: &Actor, id: &str) -> Result<()> {
        self.tx(|tx| {
            trusted(tx, actor)?;
            let remaining: i64 = tx.query_row("SELECT count(*) FROM devices WHERE account_id=?1 AND status='trusted' AND id!=?2", params![actor.account_id,id], |r| r.get(0))?;
            if remaining == 0 { return Err(Error::Conflict("Keep at least one trusted device.")); }
            let changed = tx.execute("UPDATE devices SET status='revoked' WHERE id=?1 AND account_id=?2 AND status!='revoked'", params![id,actor.account_id])?;
            if changed != 1 { return Err(Error::Forbidden); }
            tx.execute("DELETE FROM sessions WHERE device_id=?1", params![id])?;
            Ok(())
        })
    }
    pub fn create_team(&self, actor: &Actor, name: &str, now: i64) -> Result<Team> {
        valid_name(name)?;
        self.tx(|tx| {
            trusted(tx, actor)?;
            let id = random()?;
            tx.execute(
                "INSERT INTO teams VALUES(?1,?2,?3)",
                params![id, name.trim(), now],
            )?;
            tx.execute(
                "INSERT INTO memberships VALUES(?1,?2,'owner')",
                params![id, actor.account_id],
            )?;
            Ok(Team {
                id,
                name: name.trim().to_string(),
                role: "owner".into(),
            })
        })
    }
    pub fn members(&self, actor: &Actor, team: &str) -> Result<Vec<Member>> {
        self.tx(|tx| { trusted(tx,actor)?; role(tx,actor,team)?;
            let mut query=tx.prepare("SELECT a.id,a.email,a.name,m.role FROM memberships m JOIN accounts a ON a.id=m.account_id WHERE m.team_id=?1 ORDER BY a.name")?;
            Ok(query.query_map(params![team],|r|Ok(Member{account_id:r.get(0)?,email:r.get(1)?,name:r.get(2)?,role:r.get(3)?}))?.collect::<std::result::Result<Vec<_>,_>>()?)
        })
    }
    pub fn remove_member(&self, actor: &Actor, team: &str, member: &str) -> Result<()> {
        self.tx(|tx| {
            trusted(tx, actor)?;
            let mine = manager(tx, actor, team)?;
            let theirs: String = tx
                .query_row(
                    "SELECT role FROM memberships WHERE team_id=?1 AND account_id=?2",
                    params![team, member],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Error::Forbidden)?;
            if theirs == "owner" || (theirs == "admin" && mine != "owner") {
                return Err(Error::Forbidden);
            }
            tx.execute(
                "DELETE FROM memberships WHERE team_id=?1 AND account_id=?2",
                params![team, member],
            )?;
            Ok(())
        })
    }
    pub fn invite(
        &self,
        actor: &Actor,
        team: &str,
        input: &NewInvite,
        now: i64,
    ) -> Result<Invitation> {
        let email = input.email.as_deref().map(normalize_email).transpose()?;
        if !matches!(input.role.as_str(), "member" | "admin") {
            return Err(Error::Invalid("Choose member or admin."));
        }
        self.tx(|tx| {
            trusted(tx, actor)?;
            let mine = manager(tx, actor, team)?;
            if input.role == "admin" && mine != "owner" {
                return Err(Error::Forbidden);
            }
            let id = random()?;
            let token = random()?;
            let expires_at = now + INVITE_LIFETIME;
            tx.execute(
                "INSERT INTO invitations VALUES(?1,?2,?3,?4,?5,?6,?7,'issued',NULL)",
                params![
                    id,
                    digest(&token),
                    team,
                    actor.account_id,
                    email,
                    input.role,
                    expires_at
                ],
            )?;
            Ok(Invitation {
                id,
                token,
                expires_at,
            })
        })
    }
    pub fn preview(&self, actor: &Actor, token: &str, now: i64) -> Result<InvitePreview> {
        self.tx(|tx| {
            let (team,role,status,expires,email,team_id): (String,String,String,i64,Option<String>,String)=tx.query_row("SELECT t.name,i.role,i.status,i.expires_at,i.email,t.id FROM invitations i JOIN teams t ON t.id=i.team_id WHERE i.token_hash=?1 AND i.expires_at>?2 AND i.status IN ('issued','requested')",params![digest(token),now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?.ok_or(Error::Invalid("Invitation is unavailable or expired."))?;
            recipient(tx,actor,email.as_deref())?;
            Ok(InvitePreview{team_id,team_name:team,role,status,expires_at:expires})
        })
    }
    pub fn request_invite(&self, actor: &Actor, token: &str, now: i64) -> Result<()> {
        self.tx(|tx| { trusted(tx,actor)?;
            let (id,team,email,status,requester):(String,String,Option<String>,String,Option<String>)=tx.query_row("SELECT id,team_id,email,status,requester FROM invitations WHERE token_hash=?1 AND expires_at>?2",params![digest(token),now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(Error::Invalid("Invitation is unavailable or expired."))?;
            recipient(tx,actor,email.as_deref())?;
            if role(tx,actor,&team).is_ok(){return Err(Error::Conflict("You already belong to this team."));}
            if status=="requested" && requester.as_deref()==Some(&actor.account_id){return Ok(());}
            if status!="issued"{return Err(Error::Conflict("This invitation is no longer available."));}
            tx.execute("UPDATE invitations SET status='requested',requester=?1 WHERE id=?2",params![actor.account_id,id])?;
            Ok(())
        })
    }
    pub fn requests(&self, actor: &Actor, team: &str, now: i64) -> Result<Vec<JoinRequest>> {
        self.tx(|tx|{trusted(tx,actor)?;manager(tx,actor,team)?;
            let mut query=tx.prepare("SELECT i.id,a.id,a.email,a.name,i.role FROM invitations i JOIN accounts a ON a.id=i.requester WHERE i.team_id=?1 AND i.status='requested' AND i.expires_at>?2 ORDER BY a.name")?;
            Ok(query.query_map(params![team,now],|r|Ok(JoinRequest{id:r.get(0)?,account_id:r.get(1)?,email:r.get(2)?,name:r.get(3)?,role:r.get(4)?}))?.collect::<std::result::Result<Vec<_>,_>>()?)
        })
    }
    pub fn decide(
        &self,
        actor: &Actor,
        team: &str,
        id: &str,
        input: &DecideInvite,
        now: i64,
    ) -> Result<()> {
        self.tx(|tx|{trusted(tx,actor)?;let mine=manager(tx,actor,team)?;
            let granted: String=tx.query_row("SELECT role FROM invitations WHERE id=?1 AND team_id=?2 AND requester=?3 AND status='requested' AND expires_at>?4",params![id,team,input.account_id,now],|r|r.get(0)).optional()?.ok_or(Error::Conflict("Invitation request changed or expired."))?;
            if granted=="admin" && mine!="owner" {return Err(Error::Forbidden);}
            if input.approve {
                tx.execute("INSERT INTO memberships VALUES(?1,?2,?3) ON CONFLICT(team_id,account_id) DO NOTHING",params![team,input.account_id,granted])?;
            }
            tx.execute("UPDATE invitations SET status=?1 WHERE id=?2",params![if input.approve {"accepted"}else{"declined"},id])?;
            Ok(())
        })
    }
    pub fn revoke_invite(&self, actor: &Actor, team: &str, id: &str) -> Result<()> {
        self.tx(|tx|{trusted(tx,actor)?;manager(tx,actor,team)?;
            let n=tx.execute("UPDATE invitations SET status='revoked' WHERE id=?1 AND team_id=?2 AND status IN ('issued','requested')",params![id,team])?;
            if n!=1{return Err(Error::Invalid("Invitation is no longer active."));} Ok(())
        })
    }
}

fn consume_nonce(tx: &Transaction<'_>, proof: &Proof, now: i64) -> Result<()> {
    tx.execute("DELETE FROM nonces WHERE expires_at<=?1", params![now])?;
    match tx.execute(
        "INSERT INTO nonces VALUES(?1,?2,?3)",
        params![
            proof.device_id,
            proof.nonce,
            now + 2 * CLOCK_SKEW as i64 + 1
        ],
    ) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(Error::Unauthorized)
        }
        Err(e) => Err(e.into()),
    }
}
fn trusted(tx: &Transaction<'_>, actor: &Actor) -> Result<()> {
    let status: Option<String> = tx
        .query_row(
            "SELECT status FROM devices WHERE id=?1 AND account_id=?2",
            params![actor.device_id, actor.account_id],
            |r| r.get(0),
        )
        .optional()?;
    if status.as_deref() != Some("trusted") {
        return Err(Error::Untrusted);
    }
    Ok(())
}
fn role(tx: &Transaction<'_>, actor: &Actor, team: &str) -> Result<String> {
    tx.query_row(
        "SELECT role FROM memberships WHERE team_id=?1 AND account_id=?2",
        params![team, actor.account_id],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(Error::Forbidden)
}
fn manager(tx: &Transaction<'_>, actor: &Actor, team: &str) -> Result<String> {
    let value = role(tx, actor, team)?;
    if !matches!(value.as_str(), "owner" | "admin") {
        return Err(Error::Forbidden);
    }
    Ok(value)
}
fn recipient(tx: &Transaction<'_>, actor: &Actor, email: Option<&str>) -> Result<()> {
    if let Some(expected) = email {
        let actual: String = tx.query_row(
            "SELECT email FROM accounts WHERE id=?1",
            params![&actor.account_id],
            |r| r.get(0),
        )?;
        if expected != actual {
            return Err(Error::Forbidden);
        }
    }
    Ok(())
}
fn valid_name(s: &str) -> Result<()> {
    if s.trim().is_empty()
        || s.len() > 128
        || s.chars()
            .any(|c| c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
    {
        return Err(Error::Invalid(
            "Use a name of 1–128 bytes without control characters.",
        ));
    }
    Ok(())
}
pub fn normalize_email(s: &str) -> Result<String> {
    let s = s.trim().to_ascii_lowercase();
    if s.len() > 254
        || s.len() < 3
        || s.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
        || s.matches('@').count() != 1
        || s.starts_with('@')
        || s.ends_with('@')
    {
        return Err(Error::Invalid("Use a valid email address."));
    }
    Ok(s)
}
