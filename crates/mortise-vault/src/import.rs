//! Reading other password managers' CSV exports.
//!
//! The switching cost is the thing that keeps people on a manager they have
//! already decided to leave, so this has to work on the first try with the
//! file they actually have, not a file we wish they had.
//!
//! ## One mapper, not one parser per vendor
//!
//! Every exporter writes the same handful of columns under a different name:
//! `username`, `login_username`, `Login Username`, `User Name`. Branching per
//! vendor means a new branch for every manager and silent breakage whenever
//! one renames a column. Instead each field has a list of accepted headers and
//! the first match wins, so an exporter nobody here has heard of still imports
//! correctly as long as its columns are recognisably named.
//!
//! Vendor detection exists only so the UI can say "1Password export, 214
//! logins" rather than being load-bearing.
//!
//! ## Security
//!
//! The file is plaintext credentials sitting on disk. Nothing here logs a row,
//! a field, or an error containing either, and the caller is expected to tell
//! the user to delete the file afterwards. Parsing happens in Rust rather than
//! in the webview precisely so the plaintext never enters the JS heap.

use std::io::Read;

use serde::Serialize;

use crate::model::{ItemMeta, ItemPayload};

/// Which exporter a file appears to have come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// 1Password, identified by its `OTPAuth` column.
    OnePassword,
    /// Bitwarden, identified by its `login_uri` column.
    Bitwarden,
    /// Chrome's built-in password export.
    Chrome,
    /// LastPass, identified by its `grouping` column.
    LastPass,
    /// Safari / iCloud Keychain.
    Safari,
    /// Headers we recognise, from something we do not.
    Generic,
}

impl Source {
    /// For the UI.
    pub fn label(self) -> &'static str {
        match self {
            Self::OnePassword => "1Password",
            Self::Bitwarden => "Bitwarden",
            Self::Chrome => "Chrome",
            Self::LastPass => "LastPass",
            Self::Safari => "Safari",
            Self::Generic => "CSV",
        }
    }
}

/// What a parse produced.
#[derive(Debug, Clone, Serialize)]
pub struct ParseReport {
    /// Best guess at the exporter.
    pub source: Source,
    /// Rows that became items.
    pub parsed: usize,
    /// Rows with neither a password nor a note — nothing worth importing.
    pub empty: usize,
    /// Rows of a kind this does not handle yet, such as identities.
    pub unsupported: usize,
}

/// Why a file could not be read at all.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not CSV, or unreadable.
    #[error("That file could not be read as CSV.")]
    NotCsv,
    /// CSV, but with no column that looks like a password or a note.
    #[error("No password column found. Export again as CSV rather than an encrypted archive.")]
    NoRecognisedColumns,
    /// Valid CSV with headers but no rows.
    #[error("That export is empty.")]
    NoRows,
}

/// Accepted spellings for each field, lowercased and stripped of spaces and
/// underscores before comparison so `Login Username`, `login_username` and
/// `loginusername` all collapse to the same key.
const TITLE: &[&str] = &["name", "title", "accountname", "itemname", "displayname"];
const URL: &[&str] = &["url", "urls", "loginuri", "uri", "website", "weburl", "loginurl"];
const USERNAME: &[&str] = &["username", "loginusername", "user", "email", "account", "loginname"];
const PASSWORD: &[&str] = &["password", "loginpassword", "pass"];
const NOTES: &[&str] = &["notes", "note", "extra", "comment", "comments"];
const TOTP: &[&str] = &["totp", "logintotp", "otpauth", "otp", "twofactor", "authkey"];
const FOLDER: &[&str] = &["folder", "grouping", "group", "category", "collection"];
const KIND: &[&str] = &["type", "itemtype"];

fn normalise(header: &str) -> String {
    header
        .trim()
        .trim_start_matches('\u{feff}') // Excel and some exporters prepend a BOM.
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Index of the first header matching any accepted spelling.
fn find(headers: &[String], accepted: &[&str]) -> Option<usize> {
    accepted
        .iter()
        .find_map(|want| headers.iter().position(|h| h == want))
}

fn guess_source(headers: &[String]) -> Source {
    // Each of these is a column the others do not have.
    if headers.iter().any(|h| h == "loginuri") {
        Source::Bitwarden
    } else if headers.iter().any(|h| h == "grouping") {
        Source::LastPass
    } else if headers.iter().any(|h| h == "otpauth") {
        Source::OnePassword
    } else if headers.iter().any(|h| h == "note") && headers.iter().any(|h| h == "name") {
        Source::Chrome
    } else if headers.iter().any(|h| h == "title") && headers.iter().any(|h| h == "url") {
        Source::Safari
    } else {
        Source::Generic
    }
}

fn cell(row: &csv::StringRecord, index: Option<usize>) -> Option<String> {
    let value = index.and_then(|i| row.get(i))?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Parse a CSV export into items ready for `create_item`.
///
/// Returns the items alongside a report, rather than failing the whole file
/// because one row was odd. A partial import the user can see the shape of
/// beats an all-or-nothing error on a 2,000-row export.
pub fn parse<R: Read>(reader: R) -> Result<(Vec<(ItemMeta, ItemPayload)>, ParseReport), Error> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(reader);

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|_| Error::NotCsv)?
        .iter()
        .map(normalise)
        .collect();

    let (i_pw, i_notes) = (find(&headers, PASSWORD), find(&headers, NOTES));
    if i_pw.is_none() && i_notes.is_none() {
        return Err(Error::NoRecognisedColumns);
    }

    let source = guess_source(&headers);
    let (i_title, i_url) = (find(&headers, TITLE), find(&headers, URL));
    let (i_user, i_totp) = (find(&headers, USERNAME), find(&headers, TOTP));
    let (i_folder, i_kind) = (find(&headers, FOLDER), find(&headers, KIND));

    let mut items = Vec::new();
    let mut report = ParseReport {
        source,
        parsed: 0,
        empty: 0,
        unsupported: 0,
    };

    for row in rdr.records() {
        // A row that will not even parse as CSV is counted, never logged:
        // the reason would quote the row, and the row is a credential.
        let Ok(row) = row else {
            report.unsupported += 1;
            continue;
        };

        let kind = cell(&row, i_kind).map(|k| k.to_ascii_lowercase());
        let password = cell(&row, i_pw);
        let notes = cell(&row, i_notes);

        // Bitwarden and 1Password mark cards and identities in a type column.
        // Importing those as logins would put a card number in a password
        // field, so they are counted and skipped until there is real support.
        //
        // API keys and env secrets are a different case: both are a single
        // opaque string, which is exactly what the password column already
        // holds, so they map across without inventing anything.
        if let Some(k) = kind.as_deref()
            && !matches!(
                k,
                "login" | "note" | "securenote" | "secure note" | "1"
                    | "apikey" | "api key" | "api_key" | "token"
                    | "env" | "envsecret" | "env secret" | "secret"
            )
        {
            report.unsupported += 1;
            continue;
        }

        if password.is_none() && notes.is_none() {
            report.empty += 1;
            continue;
        }

        let title = cell(&row, i_title)
            .or_else(|| cell(&row, i_url))
            .or_else(|| cell(&row, i_user))
            .unwrap_or_else(|| "Untitled".to_string());

        // A note row has no password, so importing it as a login would create
        // an item whose only content sat in a field the UI hides by default.
        let payload = match (kind.as_deref(), password) {
            (Some("apikey" | "api key" | "api_key" | "token"), Some(secret)) => {
                ItemPayload::ApiKey { key: secret, notes }
            }
            (Some("env" | "envsecret" | "env secret" | "secret"), Some(secret)) => {
                ItemPayload::EnvSecret { value: secret }
            }
            (_, Some(password)) => ItemPayload::Login {
                password,
                totp_seed: cell(&row, i_totp),
                notes,
            },
            (_, None) => ItemPayload::SecureNote {
                body: notes.unwrap_or_default(),
            },
        };

        // A folder of "acme-api/prod" is how every exporter spells a project
        // and an environment, because none of them has a field for either.
        // Split it rather than make someone re-file forty secrets by hand.
        let folder = cell(&row, i_folder);
        let (project, environment) = match folder.as_deref().and_then(|f| f.split_once('/')) {
            Some((p, e)) => (Some(p.trim().to_string()), Some(e.trim().to_string())),
            None => (folder.clone(), None),
        };

        let meta = ItemMeta {
            title,
            urls: cell(&row, i_url).into_iter().collect(),
            username: cell(&row, i_user),
            folder,
            project,
            environment,
            tags: Vec::new(),
        };

        items.push((meta, payload));
        report.parsed += 1;
    }

    if items.is_empty() && report.empty == 0 && report.unsupported == 0 {
        return Err(Error::NoRows);
    }
    Ok((items, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> (Vec<(ItemMeta, ItemPayload)>, ParseReport) {
        parse(s.as_bytes()).unwrap()
    }

    fn password_of(p: &ItemPayload) -> &str {
        match p {
            ItemPayload::Login { password, .. } => password,
            _ => panic!("expected a login"),
        }
    }

    #[test]
    fn a_type_column_can_name_an_api_key_or_an_env_secret() {
        let (items, report) = parse_str(
            "name,username,password,type\n\
             Stripe,,placeholder-key-abc,apikey\n\
             DATABASE_URL,,postgres://localhost/acme,env\n",
        );
        assert_eq!(report.parsed, 2);
        assert_eq!(report.unsupported, 0);
        assert!(matches!(&items[0].1, ItemPayload::ApiKey { key, .. } if key == "placeholder-key-abc"));
        assert!(
            matches!(&items[1].1, ItemPayload::EnvSecret { value } if value == "postgres://localhost/acme")
        );
    }

    /// Cards carry four fields no CSV column here holds, so they stay skipped
    /// rather than being flattened into a password.
    #[test]
    fn a_card_row_is_still_counted_and_skipped() {
        let (items, report) = parse_str(
            "name,username,password,type\n\
             Visa,,4111-not-a-card,card\n",
        );
        assert!(items.is_empty());
        assert_eq!(report.unsupported, 1);
    }

    #[test]
    fn a_folder_of_project_slash_environment_is_split_into_both() {
        let (items, _) = parse_str(
            "name,password,folder,type\n\
             DATABASE_URL,postgres://x,acme-api/prod,env\n\
             GitHub,hunter2,Personal,login\n\
             NESTED,v,acme/web/prod,env\n",
        );
        assert_eq!(items[0].0.project.as_deref(), Some("acme-api"));
        assert_eq!(items[0].0.environment.as_deref(), Some("prod"));

        // No slash means the whole thing is the project and there is no
        // environment to invent.
        assert_eq!(items[1].0.project.as_deref(), Some("Personal"));
        assert_eq!(items[1].0.environment, None);

        // Split on the first slash only: the rest is the environment's name,
        // whatever shape it is.
        assert_eq!(items[2].0.project.as_deref(), Some("acme"));
        assert_eq!(items[2].0.environment.as_deref(), Some("web/prod"));

        // The folder itself survives, so nothing is lost by the split.
        assert_eq!(items[0].0.folder.as_deref(), Some("acme-api/prod"));
    }

    #[test]
    fn reads_a_chrome_export() {
        let (items, report) = parse_str(
            "name,url,username,password,note\n\
             GitHub,https://github.com,octocat,hunter2,\n",
        );
        assert_eq!(report.source, Source::Chrome);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0.title, "GitHub");
        assert_eq!(items[0].0.username.as_deref(), Some("octocat"));
        assert_eq!(items[0].0.urls, vec!["https://github.com"]);
        assert_eq!(password_of(&items[0].1), "hunter2");
    }

    #[test]
    fn reads_a_bitwarden_export() {
        let (items, report) = parse_str(
            "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
             Work,,login,Fastmail,,,https://app.fastmail.com,me@fastmail.com,s3cret,JBSWY3DP\n",
        );
        assert_eq!(report.source, Source::Bitwarden);
        assert_eq!(items[0].0.folder.as_deref(), Some("Work"));
        assert_eq!(items[0].0.username.as_deref(), Some("me@fastmail.com"));
        match &items[0].1 {
            ItemPayload::Login {
                password,
                totp_seed,
                ..
            } => {
                assert_eq!(password, "s3cret");
                assert_eq!(totp_seed.as_deref(), Some("JBSWY3DP"));
            }
            _ => panic!("expected a login"),
        }
    }

    #[test]
    fn reads_a_lastpass_export() {
        let (items, report) = parse_str(
            "url,username,password,totp,extra,name,grouping,fav\n\
             https://example.com,alice,pw1,,a note,Example,Personal,0\n",
        );
        assert_eq!(report.source, Source::LastPass);
        assert_eq!(items[0].0.title, "Example");
        assert_eq!(items[0].0.folder.as_deref(), Some("Personal"));
    }

    /// The whole point of the alias table: a vendor nobody anticipated still
    /// imports as long as its columns are recognisably named.
    #[test]
    fn reads_an_exporter_it_has_never_seen() {
        let (items, _) = parse_str(
            "Account Name,Web URL,User Name,Password\n\
             Bank,https://bank.example,alice,letmein\n",
        );
        assert_eq!(items[0].0.title, "Bank");
        assert_eq!(items[0].0.username.as_deref(), Some("alice"));
        assert_eq!(password_of(&items[0].1), "letmein");
    }

    /// Notes routinely contain commas, quotes and newlines. Hand-rolled
    /// splitting on ',' mangles exactly these, and the damage is invisible
    /// until someone opens the item months later.
    #[test]
    fn survives_quoted_fields_with_commas_and_newlines() {
        let (items, _) = parse_str(
            "name,username,password,notes\n\
             \"Acme, Inc.\",alice,\"pa,ss\"\"word\",\"line one\nline two\"\n",
        );
        assert_eq!(items[0].0.title, "Acme, Inc.");
        assert_eq!(password_of(&items[0].1), "pa,ss\"word");
        match &items[0].1 {
            ItemPayload::Login { notes, .. } => {
                assert_eq!(notes.as_deref(), Some("line one\nline two"));
            }
            _ => panic!("expected a login"),
        }
    }

    /// Excel prepends a BOM, which would otherwise make the first column
    /// unrecognisable and send the whole file down the "no columns" path.
    #[test]
    fn tolerates_a_byte_order_mark() {
        let (items, _) = parse_str("\u{feff}name,username,password\nX,u,p\n");
        assert_eq!(items[0].0.title, "X");
    }

    #[test]
    fn a_row_with_no_password_becomes_a_note() {
        let (items, _) = parse_str("name,username,password,notes\nIdeas,,,just thoughts\n");
        match &items[0].1 {
            ItemPayload::SecureNote { body } => assert_eq!(body, "just thoughts"),
            _ => panic!("expected a note"),
        }
    }

    /// Importing a card as a login would put the card number in a password
    /// field, which is worse than not importing it.
    #[test]
    fn skips_kinds_it_cannot_represent() {
        let (items, report) = parse_str(
            "type,name,notes,login_uri,login_username,login_password\n\
             login,Good,,,,pw\n\
             card,Visa,,,,\n\
             identity,Me,,,,\n",
        );
        assert_eq!(items.len(), 1);
        assert_eq!(report.unsupported, 2);
    }

    #[test]
    fn counts_rows_with_nothing_in_them() {
        let (items, report) = parse_str("name,username,password,notes\nEmpty,alice,,\n");
        assert!(items.is_empty());
        assert_eq!(report.empty, 1);
    }

    #[test]
    fn falls_back_to_the_url_then_the_username_for_a_title() {
        let (items, _) = parse_str("url,username,password\nhttps://a.example,,pw\n");
        assert_eq!(items[0].0.title, "https://a.example");
    }

    #[test]
    fn refuses_a_file_with_no_password_or_note_column() {
        let e = parse("first,last\nada,lovelace\n".as_bytes()).unwrap_err();
        assert!(matches!(e, Error::NoRecognisedColumns));
    }

    #[test]
    fn refuses_a_header_only_file() {
        let e = parse("name,username,password\n".as_bytes()).unwrap_err();
        assert!(matches!(e, Error::NoRows));
    }

    /// Several exporters quote every field including the headers.
    #[test]
    fn handles_quoted_headers() {
        let (items, _) = parse_str("\"name\",\"username\",\"password\"\nX,u,p\n");
        assert_eq!(password_of(&items[0].1), "p");
    }
}
