//! `.env` templates: the file you commit instead of the file with secrets.
//!
//! ```text
//! DATABASE_URL=mortise://api/dev/DATABASE_URL
//! STRIPE_KEY=mortise://payments/prod/STRIPE_SECRET_KEY
//! LOG_LEVEL=debug
//! ```
//!
//! A value of the form `mortise://<project>/<environment>/<KEY>` is fetched
//! from the vault; anything else is passed through literally. Parsing is the
//! vault's own `.env` reader, so a template accepts exactly what an import
//! does.

use mortise_vault::envfile;

/// Prefix that marks a value as a vault reference.
pub const SCHEME: &str = "mortise://";

/// One line of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The variable the child process sees.
    pub name: String,
    /// Where its value comes from.
    pub value: Value,
}

/// Where a template value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Used exactly as written.
    Literal(String),
    /// Fetched from the vault.
    Ref(Reference),
}

/// `mortise://<project>/<environment>/<KEY>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Project name.
    pub project: String,
    /// Environment name.
    pub environment: String,
    /// Variable name inside that environment.
    pub key: String,
}

impl Reference {
    /// Parse a reference. The key and environment are the last two segments,
    /// so a project name may itself contain `/`; an environment or key cannot.
    pub fn parse(text: &str) -> Result<Self, String> {
        let rest = text
            .strip_prefix(SCHEME)
            .ok_or_else(|| format!("`{text}` does not start with {SCHEME}"))?;
        let mut parts = rest.rsplitn(3, '/');
        let key = parts.next().unwrap_or_default().trim();
        let environment = parts.next().unwrap_or_default().trim();
        let project = parts.next().unwrap_or_default().trim();
        if key.is_empty() || environment.is_empty() || project.is_empty() {
            return Err(format!(
                "`{text}` should look like {SCHEME}<project>/<environment>/<KEY>"
            ));
        }
        Ok(Self {
            project: project.to_string(),
            environment: environment.to_string(),
            key: key.to_string(),
        })
    }
}

/// Parse a template's text.
///
/// Refuses the whole file if any line is unreadable or any reference is
/// malformed. Running with one variable quietly missing is worse than not
/// running: the failure surfaces later, somewhere less obvious.
pub fn parse(text: &str, source: &str) -> Result<Vec<Entry>, String> {
    let (vars, report) = envfile::parse(text);
    if report.unreadable > 0 {
        return Err(format!(
            "{source}: {} line(s) are not KEY=value",
            report.unreadable
        ));
    }
    vars.into_iter()
        .map(|var| {
            let value = if var.value.starts_with(SCHEME) {
                Value::Ref(Reference::parse(&var.value).map_err(|e| format!("{source}: {e}"))?)
            } else {
                Value::Literal(var.value)
            };
            Ok(Entry {
                name: var.key,
                value,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_and_literals_are_told_apart() {
        let entries = parse(
            "# comment\nDB=mortise://api/dev/DATABASE_URL\nLOG_LEVEL=debug\n",
            "t",
        )
        .unwrap();
        assert_eq!(
            entries,
            vec![
                Entry {
                    name: "DB".into(),
                    value: Value::Ref(Reference {
                        project: "api".into(),
                        environment: "dev".into(),
                        key: "DATABASE_URL".into(),
                    }),
                },
                Entry {
                    name: "LOG_LEVEL".into(),
                    value: Value::Literal("debug".into()),
                },
            ]
        );
    }

    #[test]
    fn a_project_name_may_contain_a_slash() {
        let r = Reference::parse("mortise://acme/web/prod/KEY").unwrap();
        assert_eq!(
            (r.project.as_str(), r.environment.as_str(), r.key.as_str()),
            ("acme/web", "prod", "KEY")
        );
    }

    #[test]
    fn malformed_references_and_lines_refuse_the_file() {
        for bad in [
            "A=mortise://api/KEY\n",
            "A=mortise://api/dev/\n",
            "A=mortise:///dev/KEY\n",
            "not a variable\n",
        ] {
            assert!(parse(bad, "t").is_err(), "{bad:?} should be refused");
        }
    }
}
