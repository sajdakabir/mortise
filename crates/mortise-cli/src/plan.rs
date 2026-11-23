//! Turning flags and templates into requests, and answers into an environment.
//!
//! Pure functions, no I/O, so the rules about what wins and what is an error
//! are tested directly rather than through a socket.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::protocol::Var;
use crate::template::{Entry, Value};

/// One project and environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Project name as the user wrote it.
    pub project: String,
    /// Environment name.
    pub environment: String,
}

impl Target {
    /// Identity for grouping. The app matches project names case-insensitively,
    /// so `API/dev` and `api/dev` are one request and one approval, not two.
    fn group(&self) -> (String, String) {
        (self.project.to_lowercase(), self.environment.clone())
    }
}

/// One request to send to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// Which environment.
    pub target: Target,
    /// Only these keys, or the whole environment when `None`.
    pub keys: Option<BTreeSet<String>>,
}

/// What `mortise run` was asked to inject.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// `--project`/`--env` (or `.mortise.toml`): every variable in it.
    pub whole: Option<Target>,
    /// `--env-file` entries, in file order.
    pub templates: Vec<Entry>,
}

impl Plan {
    /// Nothing to inject. Running anyway would look like it worked.
    pub fn is_empty(&self) -> bool {
        self.whole.is_none() && self.templates.is_empty()
    }

    /// The requests to make: one per environment, never more.
    pub fn fetches(&self) -> Vec<Fetch> {
        let mut by_group: BTreeMap<(String, String), Fetch> = BTreeMap::new();
        if let Some(whole) = &self.whole {
            by_group.insert(
                whole.group(),
                Fetch {
                    target: whole.clone(),
                    keys: None,
                },
            );
        }
        for entry in &self.templates {
            let Value::Ref(r) = &entry.value else {
                continue;
            };
            let target = Target {
                project: r.project.clone(),
                environment: r.environment.clone(),
            };
            let fetch = by_group.entry(target.group()).or_insert_with(|| Fetch {
                target,
                keys: Some(BTreeSet::new()),
            });
            // A whole-environment fetch already covers every key.
            if let Some(keys) = &mut fetch.keys {
                keys.insert(r.key.clone());
            }
        }
        by_group.into_values().collect()
    }

    /// The final environment, given each fetch's answer.
    ///
    /// Order is precedence, last wins: the whole environment first, then
    /// template lines in file order. A template line is the more specific
    /// statement, so it overrides.
    pub fn assemble(
        &self,
        answers: &[(Fetch, Vec<Var>)],
    ) -> Result<Vec<(String, Zeroizing<String>)>, String> {
        let lookup = |target: &Target| {
            answers
                .iter()
                .find(|(f, _)| f.target.group() == target.group())
                .map(|(_, vars)| vars.as_slice())
        };

        let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
        if let Some(whole) = &self.whole {
            let vars = lookup(whole).ok_or("internal: no answer for the project environment")?;
            out.extend(
                vars.iter()
                    .map(|v| (v.key.clone(), Zeroizing::new(v.value.clone()))),
            );
        }
        for entry in &self.templates {
            let value = match &entry.value {
                Value::Literal(s) => Zeroizing::new(s.clone()),
                Value::Ref(r) => {
                    let target = Target {
                        project: r.project.clone(),
                        environment: r.environment.clone(),
                    };
                    // The app refuses missing keys before answering, so this
                    // is a second line of defence against a mismatched app.
                    let var = lookup(&target)
                        .and_then(|vars| vars.iter().find(|v| v.key == r.key))
                        .ok_or_else(|| {
                            format!("{}/{} has no {}", r.project, r.environment, r.key)
                        })?;
                    Zeroizing::new(var.value.clone())
                }
            };
            out.push((entry.name.clone(), value));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::parse;

    fn var(k: &str, v: &str) -> Var {
        Var {
            key: k.into(),
            value: v.into(),
        }
    }

    fn target(p: &str, e: &str) -> Target {
        Target {
            project: p.into(),
            environment: e.into(),
        }
    }

    #[test]
    fn references_to_one_environment_become_one_request() {
        let plan = Plan {
            whole: None,
            templates: parse(
                "A=mortise://api/dev/X\nB=mortise://API/dev/Y\nC=mortise://api/prod/X\n",
                "t",
            )
            .unwrap(),
        };
        let fetches = plan.fetches();
        assert_eq!(fetches.len(), 2, "{fetches:?}");
        let dev = fetches
            .iter()
            .find(|f| f.target.environment == "dev")
            .unwrap();
        assert_eq!(
            dev.keys,
            Some(BTreeSet::from(["X".to_string(), "Y".to_string()]))
        );
    }

    #[test]
    fn a_whole_environment_absorbs_references_into_it() {
        let plan = Plan {
            whole: Some(target("api", "dev")),
            templates: parse("A=mortise://api/dev/X\n", "t").unwrap(),
        };
        assert_eq!(
            plan.fetches(),
            vec![Fetch {
                target: target("api", "dev"),
                keys: None
            }]
        );
    }

    #[test]
    fn template_lines_override_the_whole_environment_and_rename() {
        let plan = Plan {
            whole: Some(target("api", "dev")),
            templates: parse(
                "DATABASE_URL=override\nRENAMED=mortise://api/dev/TOKEN\n",
                "t",
            )
            .unwrap(),
        };
        let answers = vec![(
            plan.fetches()[0].clone(),
            vec![var("DATABASE_URL", "vault"), var("TOKEN", "t0k")],
        )];
        let env: Vec<(String, String)> = plan
            .assemble(&answers)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        assert_eq!(
            env,
            vec![
                ("DATABASE_URL".into(), "vault".into()),
                ("TOKEN".into(), "t0k".into()),
                ("DATABASE_URL".into(), "override".into()),
                ("RENAMED".into(), "t0k".into()),
            ],
            "later entries win when applied in order"
        );
    }

    #[test]
    fn a_reference_the_answer_lacks_is_an_error() {
        let plan = Plan {
            whole: None,
            templates: parse("A=mortise://api/dev/X\n", "t").unwrap(),
        };
        let answers = vec![(plan.fetches()[0].clone(), vec![var("Y", "y")])];
        assert!(plan.assemble(&answers).unwrap_err().contains("has no X"));
    }
}
