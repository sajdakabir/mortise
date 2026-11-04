//! The account state machine is shared by SQLite and Postgres. Values always
//! travel as bound parameters; only static, application-owned SQL is translated.
use crate::{Error, Result};
use rusqlite::Connection;
use std::sync::Mutex;

#[cfg(feature = "postgres")]
use r2d2_postgres::{PostgresConnectionManager, postgres, r2d2};
#[cfg(feature = "postgres")]
use std::{cell::RefCell, time::Duration};

pub(crate) enum Database {
    Sqlite(Mutex<Connection>),
    #[cfg(feature = "postgres")]
    Postgres(r2d2::Pool<PostgresConnectionManager<postgres_native_tls::MakeTlsConnector>>),
}

pub(crate) enum Transaction<'a> {
    Sqlite(rusqlite::Transaction<'a>),
    #[cfg(feature = "postgres")]
    Postgres(RefCell<postgres::Transaction<'a>>),
}

/// Deliberately small interface: the accounts schema only binds text, optional
/// text, and signed 64-bit timestamps. Neither backend sees vault data.
pub(crate) trait Parameter: Sync {
    fn sqlite(&self) -> &dyn rusqlite::ToSql;
    #[cfg(feature = "postgres")]
    fn postgres(&self) -> &(dyn postgres::types::ToSql + Sync);
}
#[cfg(feature = "postgres")]
impl<T: rusqlite::ToSql + postgres::types::ToSql + Sync> Parameter for T {
    fn sqlite(&self) -> &dyn rusqlite::ToSql {
        self
    }
    fn postgres(&self) -> &(dyn postgres::types::ToSql + Sync) {
        self
    }
}
#[cfg(not(feature = "postgres"))]
impl<T: rusqlite::ToSql + Sync> Parameter for T {
    fn sqlite(&self) -> &dyn rusqlite::ToSql {
        self
    }
}
macro_rules! params {
    ($($value:expr),* $(,)?) => { &[$(&$value as &dyn $crate::database::Parameter),*][..] };
}
pub(crate) use params;

pub(crate) enum Row<'a> {
    Sqlite(&'a rusqlite::Row<'a>),
    #[cfg(feature = "postgres")]
    Postgres(&'a postgres::Row),
}
impl Row<'_> {
    #[cfg(feature = "postgres")]
    pub fn get<T: rusqlite::types::FromSql + for<'a> postgres::types::FromSql<'a>>(
        &self,
        index: usize,
    ) -> rusqlite::Result<T> {
        match self {
            Self::Sqlite(row) => row.get(index),
            Self::Postgres(row) => row.try_get(index).map_err(pg_error),
        }
    }
    #[cfg(not(feature = "postgres"))]
    pub fn get<T: rusqlite::types::FromSql>(&self, index: usize) -> rusqlite::Result<T> {
        match self {
            Self::Sqlite(row) => row.get(index),
        }
    }
}

pub(crate) struct Statement<'a, 'db> {
    tx: &'a Transaction<'db>,
    sql: &'a str,
}
impl Statement<'_, '_> {
    pub fn query_map<T>(
        &mut self,
        params: &[&dyn Parameter],
        map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<std::vec::IntoIter<rusqlite::Result<T>>> {
        self.tx.query(self.sql, params, map).map(Vec::into_iter)
    }
}
impl<'db> Transaction<'db> {
    pub fn execute(&self, sql: &str, params: &[&dyn Parameter]) -> rusqlite::Result<usize> {
        match self {
            Self::Sqlite(tx) => tx.execute(
                sql,
                rusqlite::params_from_iter(params.iter().map(|p| p.sqlite())),
            ),
            #[cfg(feature = "postgres")]
            Self::Postgres(tx) => tx
                .borrow_mut()
                .execute(
                    &sql.replace('?', "$"),
                    &params.iter().map(|p| p.postgres()).collect::<Vec<_>>(),
                )
                .map(|n| n as usize)
                .map_err(pg_error),
        }
    }
    fn query<T>(
        &self,
        sql: &str,
        params: &[&dyn Parameter],
        mut map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<Vec<rusqlite::Result<T>>> {
        match self {
            Self::Sqlite(tx) => {
                let mut query = tx.prepare(sql)?;
                Ok(query
                    .query_map(
                        rusqlite::params_from_iter(params.iter().map(|p| p.sqlite())),
                        |r| map(&Row::Sqlite(r)),
                    )?
                    .collect())
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(tx) => {
                let rows = tx
                    .borrow_mut()
                    .query(
                        &sql.replace('?', "$"),
                        &params.iter().map(|p| p.postgres()).collect::<Vec<_>>(),
                    )
                    .map_err(pg_error)?;
                Ok(rows.iter().map(|r| map(&Row::Postgres(r))).collect())
            }
        }
    }
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[&dyn Parameter],
        map: impl FnMut(&Row<'_>) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.query(sql, params, map)?
            .into_iter()
            .next()
            .unwrap_or(Err(rusqlite::Error::QueryReturnedNoRows))
    }
    pub fn prepare<'a>(&'a self, sql: &'a str) -> rusqlite::Result<Statement<'a, 'db>> {
        Ok(Statement { tx: self, sql })
    }
    fn commit(self) -> Result<()> {
        match self {
            Self::Sqlite(tx) => tx.commit().map_err(Into::into),
            #[cfg(feature = "postgres")]
            Self::Postgres(tx) => tx.into_inner().commit().map_err(|_| Error::Storage),
        }
    }
}

impl Database {
    pub fn tx<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        match self {
            Self::Sqlite(conn) => {
                let mut conn = conn.lock().map_err(|_| Error::Storage)?;
                let tx = Transaction::Sqlite(
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?,
                );
                let value = f(&tx)?;
                tx.commit()?;
                Ok(value)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => {
                let mut conn = pool.get().map_err(|_| Error::Storage)?;
                let mut tx = conn.transaction().map_err(|_| Error::Storage)?;
                // Preserve SQLite's serialized account mutations across all API
                // instances. This prevents two first devices or last-device
                // revocations racing. Lock belongs to the transaction (pool-safe).
                tx.batch_execute("SET LOCAL search_path=mortise_accounts; SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='10s'; SELECT pg_advisory_xact_lock(1296122691, 1)").map_err(|_| Error::Storage)?;
                let tx = Transaction::Postgres(RefCell::new(tx));
                let value = f(&tx)?;
                tx.commit()?;
                Ok(value)
            }
        }
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(url: &str) -> Result<Self> {
        let (config, tls) = pg_config(url)?;
        let manager = PostgresConnectionManager::new(config, tls);
        let pool = r2d2::Pool::builder()
            .max_size(5)
            .min_idle(Some(0))
            .connection_timeout(Duration::from_secs(15))
            .idle_timeout(Some(Duration::from_secs(60)))
            .build(manager)
            .map_err(|_| Error::Storage)?;
        let mut conn = pool.get().map_err(|_| Error::Storage)?;
        let version: i64 = conn
            .query_one(
                "SELECT version FROM mortise_accounts.schema_version WHERE id=1",
                &[],
            )
            .map_err(|_| Error::Storage)?
            .get(0);
        if version != 1 {
            return Err(Error::Invalid(
                "Unsupported accounts schema. Run the account migrations.",
            ));
        }
        Ok(Self::Postgres(pool))
    }
}

#[cfg(feature = "postgres")]
fn pg_config(url: &str) -> Result<(postgres::Config, postgres_native_tls::MakeTlsConnector)> {
    let mut config: postgres::Config = url
        .parse()
        .map_err(|_| Error::Invalid("Invalid account database URL."))?;
    // sslmode=require alone does not verify a certificate in every driver.
    // native-tls performs both chain and hostname validation; never disable it.
    config
        .ssl_mode(postgres::config::SslMode::Require)
        .connect_timeout(Duration::from_secs(15));
    let tls = native_tls::TlsConnector::new().map_err(|_| Error::Unavailable)?;
    Ok((config, postgres_native_tls::MakeTlsConnector::new(tls)))
}

#[cfg(feature = "postgres")]
pub(crate) fn migrate(url: &str) -> Result<()> {
    let parsed =
        url::Url::parse(url).map_err(|_| Error::Invalid("Invalid migration database URL."))?;
    if parsed
        .host_str()
        .is_some_and(|host| host.contains("-pooler"))
    {
        return Err(Error::Invalid("Migrations require DATABASE_URL_UNPOOLED."));
    }
    let (config, tls) = pg_config(url)?;
    let mut conn = config.connect(tls).map_err(|_| Error::Storage)?;
    let mut tx = conn.transaction().map_err(|_| Error::Storage)?;
    tx.batch_execute("SET LOCAL search_path=mortise_accounts; SET LOCAL statement_timeout='30s'; SELECT pg_advisory_xact_lock(1296122691, 1); CREATE SCHEMA IF NOT EXISTS mortise_accounts; CREATE TABLE IF NOT EXISTS mortise_accounts.schema_version(id BIGINT PRIMARY KEY CHECK(id=1), version BIGINT NOT NULL)").map_err(|_| Error::Storage)?;
    let version = tx
        .query_opt(
            "SELECT version FROM mortise_accounts.schema_version WHERE id=1",
            &[],
        )
        .map_err(|_| Error::Storage)?
        .map(|r| r.get::<_, i64>(0));
    match version {
        None => {
            tx.batch_execute(include_str!("../migrations/001_accounts.sql"))
                .map_err(|_| Error::Storage)?;
            tx.batch_execute("INSERT INTO mortise_accounts.schema_version VALUES(1,1)")
                .map_err(|_| Error::Storage)?;
        }
        Some(1) => (),
        _ => return Err(Error::Invalid("Unsupported accounts schema.")),
    }
    tx.commit().map_err(|_| Error::Storage)
}

#[cfg(feature = "postgres")]
fn pg_error(error: postgres::Error) -> rusqlite::Error {
    // Retain the one semantic SQL error the state machine handles, without
    // leaking database messages, connection strings, or parameters to clients.
    if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            None,
        )
    } else {
        rusqlite::Error::InvalidQuery
    }
}
