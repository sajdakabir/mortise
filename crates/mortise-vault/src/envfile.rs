//! Reading and writing `.env` text.
//!
//! Nobody types thirty environment variables one at a time, so the unit of
//! work here is the file, not the variable. This turns a pasted `.env` into
//! items and a set of items back into a file.
//!
//! Deliberately not a general `.env` implementation. The dialects disagree on
//! almost everything — `export` prefixes, multi-line values, interpolation,
//! comments after a value — and guessing wrong about a secret is worse than
//! refusing it. What is handled is what `dotenv`, Docker and the shell all
//! agree on; anything else is reported rather than silently reinterpreted.

/// One `KEY=value` pair read from a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// The name, left of the first `=`.
    pub key: String,
    /// The value, with surrounding quotes removed.
    pub value: String,
}

/// What a parse made of the text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvReport {
    /// Lines that were blank or a comment.
    pub skipped: usize,
    /// Lines that had no `=` and could not be read as a variable.
    pub unreadable: usize,
    /// Keys that appeared more than once. The last wins, which is what every
    /// loader does, but it is worth telling someone it happened.
    pub duplicates: Vec<String>,
}

/// Read `.env` text into variables.
///
/// Later definitions of a key replace earlier ones, matching how loaders
/// behave, and the key is reported as a duplicate so the caller can say so.
pub fn parse(text: &str) -> (Vec<EnvVar>, EnvReport) {
    let mut vars: Vec<EnvVar> = Vec::new();
    let mut report = EnvReport::default();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            report.skipped += 1;
            continue;
        }

        // `export FOO=bar` is how the same file gets sourced by a shell.
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);

        let Some((key, value)) = line.split_once('=') else {
            report.unreadable += 1;
            continue;
        };

        let key = key.trim();
        if key.is_empty() || !key.chars().all(is_key_char) {
            report.unreadable += 1;
            continue;
        }

        let value = unquote(value.trim());

        if let Some(existing) = vars.iter_mut().find(|v| v.key == key) {
            report.duplicates.push(key.to_string());
            existing.value = value;
        } else {
            vars.push(EnvVar {
                key: key.to_string(),
                value,
            });
        }
    }

    (vars, report)
}

/// A single-quoted value is literal; a double-quoted one has escapes.
///
/// An unquoted value keeps every character except surrounding whitespace. In
/// particular a `#` is left alone: `PASSWORD=hunter2#4` is a password, and
/// treating the rest as a comment would silently truncate a secret.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        return value[1..value.len() - 1].to_string();
    }
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        return value[1..value.len() - 1]
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }
    value.to_string()
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

/// Write variables back out as `.env` text.
///
/// A value is left bare only when nothing in it means anything to a shell.
/// Round-tripping through this module would survive an unquoted space, but
/// these files get `source`d at least as often as they are parsed, and there
/// an unquoted space turns one variable into a command and an argument.
pub fn format(vars: &[EnvVar]) -> String {
    let mut out = String::new();
    for var in vars {
        out.push_str(&var.key);
        out.push('=');
        out.push_str(&quote(&var.value));
        out.push('\n');
    }
    out
}

/// Characters that survive a shell unquoted, chosen to cover what actually
/// turns up in these files: URLs, paths, keys, base64.
fn shell_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_-./:@+,=".contains(c)
}

fn quote(value: &str) -> String {
    if !value.is_empty() && value.chars().all(shell_safe) {
        return value.to_string();
    }
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(vars: &[EnvVar]) -> Vec<&str> {
        vars.iter().map(|v| v.key.as_str()).collect()
    }

    #[test]
    fn reads_the_shapes_every_loader_agrees_on() {
        let (vars, report) = parse(
            "# a comment\n\
             \n\
             DATABASE_URL=postgres://localhost/acme\n\
             export PORT=5432\n\
             QUOTED=\"with spaces\"\n\
             LITERAL='no \\n escape here'\n\
             EMPTY=\n",
        );
        assert_eq!(
            keys(&vars),
            ["DATABASE_URL", "PORT", "QUOTED", "LITERAL", "EMPTY"]
        );
        assert_eq!(vars[2].value, "with spaces");
        assert_eq!(vars[3].value, "no \\n escape here");
        assert_eq!(vars[4].value, "");
        assert_eq!(report.skipped, 2);
        assert_eq!(report.unreadable, 0);
    }

    /// The case that silently destroys a secret if `#` is treated as a comment
    /// wherever it appears.
    #[test]
    fn a_hash_inside_a_value_is_part_of_the_value() {
        let (vars, _) = parse("PASSWORD=hunter2#4\n");
        assert_eq!(vars[0].value, "hunter2#4");
    }

    #[test]
    fn a_value_containing_an_equals_keeps_all_of_it() {
        let (vars, _) = parse("TOKEN=abc=def==\n");
        assert_eq!(vars[0].value, "abc=def==");
    }

    #[test]
    fn the_last_definition_wins_and_is_reported() {
        let (vars, report) = parse("PORT=1\nPORT=2\n");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].value, "2");
        assert_eq!(report.duplicates, ["PORT"]);
    }

    #[test]
    fn a_line_that_is_not_a_variable_is_counted_not_guessed_at() {
        let (vars, report) = parse("DATABASE_URL=ok\nnot a variable\nalso bad!=x\n");
        assert_eq!(keys(&vars), ["DATABASE_URL"]);
        assert_eq!(report.unreadable, 2);
    }

    #[test]
    fn writing_then_reading_returns_the_same_values() {
        let original = vec![
            EnvVar {
                key: "PLAIN".into(),
                value: "simple".into(),
            },
            EnvVar {
                key: "SPACED".into(),
                value: "two words".into(),
            },
            EnvVar {
                key: "EMPTY".into(),
                value: String::new(),
            },
            EnvVar {
                key: "HASH".into(),
                value: "hunter2#4".into(),
            },
            EnvVar {
                key: "QUOTE".into(),
                value: "say \"hi\"".into(),
            },
            EnvVar {
                key: "LINES".into(),
                value: "one\ntwo".into(),
            },
            EnvVar {
                key: "TRAILING".into(),
                value: "pad ".into(),
            },
        ];
        let (round_tripped, report) = parse(&format(&original));
        assert_eq!(round_tripped, original);
        assert_eq!(report.unreadable, 0);
    }

    #[test]
    fn only_values_that_need_quoting_get_quoted() {
        let text = format(&[
            EnvVar {
                key: "A".into(),
                value: "plain".into(),
            },
            EnvVar {
                key: "B".into(),
                value: "two words".into(),
            },
        ]);
        assert_eq!(text, "A=plain\nB=\"two words\"\n");
    }
}
