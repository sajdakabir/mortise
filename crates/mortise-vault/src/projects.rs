//! Projects, and the environments inside them.
//!
//! A project is a container for developer secrets: one per codebase, with
//! `dev`, `staging` and `prod` inside it. It is stored rather than derived
//! from the items, because the whole point of creating one is to have
//! somewhere to put the first file — and that moment is exactly when nothing
//! is in it yet.
//!
//! ## What is encrypted, and why
//!
//! The name, description and environment list are sealed under the account
//! META key, the same treatment `search_cache` gets. That key survives
//! locking, so the project list draws without a password, while the file on
//! disk does not disclose that this person works on `acme-payroll`. A project
//! name is content, not shape.
//!
//! ## What is not stored here
//!
//! Which secrets belong to a project. Each item carries the project's name in
//! its own sealed metadata, so the membership travels with the item and syncs
//! with it. The consequence is that a project cannot be renamed without
//! rewriting every item in it, which is why there is no rename yet.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use mortise_crypto::aead;

use crate::error::{Error, Result};
use crate::vault::Vault;

/// Environments a new project starts with.
///
/// Three, because a project with none cannot hold a secret and asking someone
/// to invent the word "prod" before they have pasted anything is a step that
/// teaches them nothing.
pub const DEFAULT_ENVIRONMENTS: [&str; 3] = ["dev", "staging", "prod"];

/// A project as the caller sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Identifier, hex, stable across renames.
    pub id: String,
    /// Display name, unique among projects.
    pub name: String,
    /// Optional description.
    pub description: String,
    /// Environments, in the order they were added.
    pub environments: Vec<String>,
    /// Creation time.
    pub created_at_ms: u64,
}

/// The part that is sealed.
#[derive(Serialize, Deserialize)]
struct Sealed {
    name: String,
    description: String,
    environments: Vec<String>,
}

/// Bind each project's ciphertext to its own id, so two rows cannot be
/// swapped to make one project wear another's name.
fn project_aad(id: &[u8]) -> Vec<u8> {
    let mut aad = b"mortise/project/v1".to_vec();
    aad.extend_from_slice(id);
    aad
}

impl Vault {
    /// Every project, oldest first.
    ///
    /// Readable while locked: the META key outlives [`Vault::lock`] so that
    /// search keeps working, and the same applies here.
    pub fn projects(&self) -> Result<Vec<Project>> {
        let key = self.meta_key()?;
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT project_id, sealed, created_at_ms FROM project ORDER BY created_at_ms, project_id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, sealed, created) = row?;
            let plain = aead::open(key, &sealed, &project_aad(&id))?;
            let s: Sealed = serde_json::from_slice(&plain)?;
            out.push(Project {
                id: hex(&id),
                name: s.name,
                description: s.description,
                environments: s.environments,
                created_at_ms: created as u64,
            });
        }
        Ok(out)
    }

    /// Create a project.
    ///
    /// Names are compared case-insensitively after trimming, because two
    /// projects called `Acme` and `acme` are a mistake every time rather than
    /// a distinction anyone meant to draw.
    pub fn create_project(&mut self, name: &str, description: &str) -> Result<Project> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid("a project needs a name"));
        }
        if self
            .projects()?
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case(name))
        {
            return Err(Error::Invalid("a project with that name already exists"));
        }

        let id = mortise_crypto::rand::bytes::<16>()?;
        let created_at_ms = crate::vault::now_ms();
        let sealed = Sealed {
            name: name.to_string(),
            description: description.trim().to_string(),
            environments: DEFAULT_ENVIRONMENTS.iter().map(|e| e.to_string()).collect(),
        };
        self.write_project(&id, &sealed, created_at_ms)?;

        Ok(Project {
            id: hex(&id),
            name: sealed.name,
            description: sealed.description,
            environments: sealed.environments,
            created_at_ms,
        })
    }

    /// Add an environment to a project.
    pub fn add_environment(&mut self, project_id: &str, environment: &str) -> Result<Project> {
        let environment = environment.trim();
        if environment.is_empty() {
            return Err(Error::Invalid("an environment needs a name"));
        }
        let id = unhex(project_id)?;
        let (mut sealed, created_at_ms) = self.read_project(&id)?;
        if sealed
            .environments
            .iter()
            .any(|e| e.eq_ignore_ascii_case(environment))
        {
            return Err(Error::Invalid("that environment already exists"));
        }
        sealed.environments.push(environment.to_string());
        self.write_project(&id, &sealed, created_at_ms)?;

        Ok(Project {
            id: project_id.to_string(),
            name: sealed.name,
            description: sealed.description,
            environments: sealed.environments,
            created_at_ms,
        })
    }

    /// Remove a project.
    ///
    /// Only when it is empty. Deleting a project that still holds secrets
    /// would either destroy them or orphan them, and neither is something to
    /// do on the strength of one click on a container.
    pub fn delete_project(&mut self, project_id: &str) -> Result<()> {
        let id = unhex(project_id)?;
        let (sealed, _) = self.read_project(&id)?;
        let holds = self
            .search("")?
            .into_iter()
            .any(|row| row.meta.project.as_deref() == Some(sealed.name.as_str()));
        if holds {
            return Err(Error::Invalid("that project still has secrets in it"));
        }
        self.conn()
            .execute("DELETE FROM project WHERE project_id = ?1", params![id])?;
        Ok(())
    }

    fn read_project(&self, id: &[u8]) -> Result<(Sealed, u64)> {
        let key = self.meta_key()?;
        let row: Option<(Vec<u8>, i64)> = self
            .conn()
            .query_row(
                "SELECT sealed, created_at_ms FROM project WHERE project_id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (sealed, created) = row.ok_or(Error::Invalid("no such project"))?;
        let plain = aead::open(key, &sealed, &project_aad(id))?;
        Ok((serde_json::from_slice(&plain)?, created as u64))
    }

    fn write_project(&self, id: &[u8], sealed: &Sealed, created_at_ms: u64) -> Result<()> {
        let key = self.meta_key()?;
        let json = serde_json::to_vec(sealed)?;
        let blob = aead::seal(key, &json, &project_aad(id))?;
        self.conn().execute(
            "INSERT INTO project (project_id, sealed, created_at_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT (project_id) DO UPDATE SET sealed = ?2",
            params![id, blob, created_at_ms as i64],
        )?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    // Bytes, not chars. Slicing `&s[i..i + 2]` on a multi-byte character
    // panics on a char boundary, and the id reaches here straight from the
    // webview — so a malformed one would take the process down rather than
    // return an error.
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Invalid("malformed project id"));
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
            Ok(hi << 4 | lo)
        })
        .collect()
}
