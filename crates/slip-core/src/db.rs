//! SQLite-backed deploy history with STRICT tables.
//!
//! Provides a [`Db`] wrapper around a single `rusqlite::Connection` behind
//! `Arc<Mutex<>>`.  All public methods are **synchronous** — callers are
//! responsible for dispatching blocking work to `tokio::task::spawn_blocking`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use rusqlite_migration::{M, Migrations};

use crate::deploy::{DeployContext, DeployStatus, TriggerSource};

// ─── Migrations ─────────────────────────────────────────────────────────────────

/// Schema migrations, versioned by `rusqlite_migration`.
fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(include_str!(
        "../migrations/001_create_deploys.sql"
    ))])
}

// ─── Db wrapper ────────────────────────────────────────────────────────────────

/// A thread-safe wrapper around a single SQLite connection.
///
/// All database operations are dispatched through `spawn_blocking` so they
/// never block the async runtime.
#[derive(Clone)]
pub struct Db(pub(crate) Arc<Mutex<Connection>>);

impl Db {
    /// Open (or create) a database at `path`, set pragmas, and run migrations.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let mut conn = Connection::open(path)?;
        Self::configure(&mut conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    /// Open an in-memory database (for tests).
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let mut conn = Connection::open_in_memory()?;
        Self::configure(&mut conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    // ── Connection setup ──────────────────────────────────────────────────────

    /// Set per-connection pragmas and run migrations.
    fn configure(conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", "5000")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrations()
            .to_latest(conn)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(())
    }

    // ── CRUD operations ───────────────────────────────────────────────────────

    /// Insert or replace a deploy context (upsert by id).
    pub fn insert_deploy(&self, ctx: &DeployContext) -> Result<(), rusqlite::Error> {
        let conn = self.0.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO deploys
             (id, app, image, tag, status, started_at, finished_at, error,
              triggered_by, new_container_id, new_port, new_pod_name, new_manifest_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                ctx.id,
                ctx.app,
                ctx.image,
                ctx.tag,
                deploy_status_to_string(&ctx.status),
                ctx.started_at,
                ctx.finished_at,
                ctx.error,
                trigger_source_to_string(&ctx.triggered_by),
                ctx.new_container_id,
                ctx.new_port,
                ctx.new_pod_name,
                ctx.new_manifest_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string()),
            ],
        )?;
        Ok(())
    }

    /// Get a deploy by id.
    pub fn get_deploy(&self, id: &str) -> Result<Option<DeployContext>, rusqlite::Error> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, app, image, tag, status, started_at, finished_at, error,
                    triggered_by, new_container_id, new_port, new_pod_name, new_manifest_path
             FROM deploys WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], row_to_deploy)?;
        match rows.next() {
            Some(Ok(ctx)) => Ok(Some(ctx)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Get the latest deploy for a given app (by started_at DESC).
    pub fn get_latest_deploy_for_app(
        &self,
        app: &str,
    ) -> Result<Option<DeployContext>, rusqlite::Error> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, app, image, tag, status, started_at, finished_at, error,
                    triggered_by, new_container_id, new_port, new_pod_name, new_manifest_path
             FROM deploys WHERE app = ?1
             ORDER BY started_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![app], row_to_deploy)?;
        match rows.next() {
            Some(Ok(ctx)) => Ok(Some(ctx)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Get the most recent *completed* deploy for an app, excluding the given id.
    /// Used by rollback to find the previous successful deploy.
    pub fn get_previous_successful_deploy(
        &self,
        app: &str,
        before_id: &str,
    ) -> Result<Option<DeployContext>, rusqlite::Error> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, app, image, tag, status, started_at, finished_at, error,
                    triggered_by, new_container_id, new_port, new_pod_name, new_manifest_path
             FROM deploys
             WHERE app = ?1 AND status = 'completed' AND id != ?2
             ORDER BY started_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![app, before_id], row_to_deploy)?;
        match rows.next() {
            Some(Ok(ctx)) => Ok(Some(ctx)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Get the latest deploy for every app.
    ///
    /// Uses a simple subquery approach.  Acceptable for <1000 rows.
    pub fn get_latest_deploys_per_app(
        &self,
    ) -> Result<std::collections::HashMap<String, DeployContext>, rusqlite::Error> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT d.id, d.app, d.image, d.tag, d.status, d.started_at, d.finished_at,
                    d.error, d.triggered_by, d.new_container_id, d.new_port,
                    d.new_pod_name, d.new_manifest_path
             FROM deploys d
             WHERE d.started_at = (
                 SELECT MAX(d2.started_at) FROM deploys d2 WHERE d2.app = d.app
             )",
        )?;
        let rows = stmt.query_map([], row_to_deploy)?;
        let mut result = std::collections::HashMap::new();
        for row in rows {
            let ctx = row?;
            result.insert(ctx.app.clone(), ctx);
        }
        Ok(result)
    }
}

// ─── Enum string conversion ────────────────────────────────────────────────────

/// Convert `DeployStatus` to its snake_case string representation.
fn deploy_status_to_string(status: &DeployStatus) -> &'static str {
    match status {
        DeployStatus::Accepted => "accepted",
        DeployStatus::Pulling => "pulling",
        DeployStatus::Configuring => "configuring",
        DeployStatus::Starting => "starting",
        DeployStatus::HealthChecking => "health_checking",
        DeployStatus::Switching => "switching",
        DeployStatus::Completed => "completed",
        DeployStatus::Failed => "failed",
    }
}

/// Parse a snake_case string back to `DeployStatus`.
fn string_to_deploy_status(s: &str) -> DeployStatus {
    match s {
        "accepted" => DeployStatus::Accepted,
        "pulling" => DeployStatus::Pulling,
        "configuring" => DeployStatus::Configuring,
        "starting" => DeployStatus::Starting,
        "health_checking" => DeployStatus::HealthChecking,
        "switching" => DeployStatus::Switching,
        "completed" => DeployStatus::Completed,
        "failed" => DeployStatus::Failed,
        _ => DeployStatus::Failed,
    }
}

/// Convert `TriggerSource` to its snake_case string representation.
fn trigger_source_to_string(source: &TriggerSource) -> &'static str {
    match source {
        TriggerSource::Webhook => "webhook",
        TriggerSource::Cli => "cli",
        TriggerSource::Rollback => "rollback",
    }
}

/// Parse a snake_case string back to `TriggerSource`.
fn string_to_trigger_source(s: &str) -> TriggerSource {
    match s {
        "webhook" => TriggerSource::Webhook,
        "cli" => TriggerSource::Cli,
        "rollback" => TriggerSource::Rollback,
        _ => TriggerSource::Cli,
    }
}

// ─── Row mapping ───────────────────────────────────────────────────────────────

fn row_to_deploy(row: &rusqlite::Row) -> rusqlite::Result<DeployContext> {
    let status_str: String = row.get("status")?;
    let triggered_by_str: String = row.get("triggered_by")?;

    let status = string_to_deploy_status(&status_str);
    let triggered_by = string_to_trigger_source(&triggered_by_str);

    let manifest_path_str: Option<String> = row.get("new_manifest_path")?;

    Ok(DeployContext {
        id: row.get("id")?,
        app: row.get("app")?,
        image: row.get("image")?,
        tag: row.get("tag")?,
        status,
        started_at: row.get("started_at")?,
        finished_at: row.get("finished_at")?,
        error: row.get("error")?,
        triggered_by,
        new_container_id: row.get("new_container_id")?,
        new_port: row.get("new_port")?,
        new_pod_name: row.get("new_pod_name")?,
        new_manifest_path: manifest_path_str.map(PathBuf::from),
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::Utc;

    use super::*;
    use crate::deploy::{DeployStatus, TriggerSource};

    fn test_db() -> Db {
        Db::open_in_memory().expect("in-memory db")
    }

    fn sample_deploy(id: &str, app: &str, status: DeployStatus) -> DeployContext {
        DeployContext {
            id: id.to_string(),
            app: app.to_string(),
            image: "ghcr.io/org/app".to_string(),
            tag: "v1.0".to_string(),
            status,
            started_at: Utc::now(),
            finished_at: None,
            error: None,
            triggered_by: TriggerSource::Webhook,
            new_container_id: None,
            new_port: None,
            new_pod_name: None,
            new_manifest_path: None,
        }
    }

    #[tokio::test]
    async fn test_insert_and_retrieve() {
        let db = test_db();
        let ctx = sample_deploy("dep_001", "myapp", DeployStatus::Accepted);

        db.insert_deploy(&ctx).unwrap();

        let loaded = db.get_deploy("dep_001").unwrap().expect("should exist");
        assert_eq!(loaded.id, "dep_001");
        assert_eq!(loaded.app, "myapp");
        assert_eq!(loaded.status, DeployStatus::Accepted);
    }

    #[tokio::test]
    async fn test_upsert_overwrites() {
        let db = test_db();
        let mut ctx = sample_deploy("dep_001", "myapp", DeployStatus::Accepted);
        db.insert_deploy(&ctx).unwrap();

        ctx.status = DeployStatus::Completed;
        ctx.finished_at = Some(Utc::now());
        db.insert_deploy(&ctx).unwrap();

        let loaded = db.get_deploy("dep_001").unwrap().expect("should exist");
        assert_eq!(loaded.status, DeployStatus::Completed);
        assert!(loaded.finished_at.is_some());
    }

    #[tokio::test]
    async fn test_get_latest_deploy_for_app() {
        let db = test_db();

        let ctx1 = sample_deploy("dep_001", "myapp", DeployStatus::Accepted);
        db.insert_deploy(&ctx1).unwrap();

        // Insert a second deploy for the same app (later timestamp).
        let mut ctx2 = sample_deploy("dep_002", "myapp", DeployStatus::Completed);
        ctx2.started_at = Utc::now() + chrono::Duration::seconds(10);
        db.insert_deploy(&ctx2).unwrap();

        let latest = db
            .get_latest_deploy_for_app("myapp")
            .unwrap()
            .expect("should exist");
        assert_eq!(latest.id, "dep_002");
    }

    #[tokio::test]
    async fn test_get_previous_successful_deploy() {
        let db = test_db();

        // Insert a completed deploy.
        let mut completed = sample_deploy("dep_001", "myapp", DeployStatus::Completed);
        completed.started_at = Utc::now() - chrono::Duration::hours(1);
        db.insert_deploy(&completed).unwrap();

        // Insert a failed deploy.
        let mut failed = sample_deploy("dep_002", "myapp", DeployStatus::Failed);
        failed.started_at = Utc::now();
        db.insert_deploy(&failed).unwrap();

        // Should find dep_001 (completed, not dep_002).
        let prev = db
            .get_previous_successful_deploy("myapp", "dep_002")
            .unwrap()
            .expect("should find previous completed");
        assert_eq!(prev.id, "dep_001");
    }

    #[tokio::test]
    async fn test_get_latest_deploys_per_app() {
        let db = test_db();

        // Two apps, two deploys each.
        let ctx1 = sample_deploy("dep_a1", "app-a", DeployStatus::Accepted);
        db.insert_deploy(&ctx1).unwrap();
        let mut ctx2 = sample_deploy("dep_a2", "app-a", DeployStatus::Completed);
        ctx2.started_at = Utc::now() + chrono::Duration::seconds(5);
        db.insert_deploy(&ctx2).unwrap();

        let ctx3 = sample_deploy("dep_b1", "app-b", DeployStatus::Pulling);
        db.insert_deploy(&ctx3).unwrap();

        let latest = db.get_latest_deploys_per_app().unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest.get("app-a").unwrap().id, "dep_a2");
        assert_eq!(latest.get("app-b").unwrap().id, "dep_b1");
    }

    #[tokio::test]
    async fn test_null_handling() {
        let db = test_db();
        let ctx = sample_deploy("dep_null", "myapp", DeployStatus::Accepted);
        db.insert_deploy(&ctx).unwrap();

        let loaded = db.get_deploy("dep_null").unwrap().expect("should exist");
        assert!(loaded.finished_at.is_none());
        assert!(loaded.error.is_none());
        assert!(loaded.new_container_id.is_none());
        assert!(loaded.new_port.is_none());
        assert!(loaded.new_pod_name.is_none());
        assert!(loaded.new_manifest_path.is_none());
    }

    #[tokio::test]
    async fn test_optional_fields_round_trip() {
        let db = test_db();
        let ctx = DeployContext {
            id: "dep_opt".to_string(),
            app: "myapp".to_string(),
            image: "ghcr.io/org/app".to_string(),
            tag: "v2.0".to_string(),
            status: DeployStatus::Completed,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            error: Some("something went wrong".to_string()),
            triggered_by: TriggerSource::Rollback,
            new_container_id: Some("ctr_abc".to_string()),
            new_port: Some(8080),
            new_pod_name: Some("pod-xyz".to_string()),
            new_manifest_path: Some(PathBuf::from("/tmp/manifest.yaml")),
        };
        db.insert_deploy(&ctx).unwrap();

        let loaded = db.get_deploy("dep_opt").unwrap().expect("should exist");
        assert_eq!(loaded.finished_at, ctx.finished_at);
        assert_eq!(loaded.error, ctx.error);
        assert_eq!(loaded.triggered_by, TriggerSource::Rollback);
        assert_eq!(loaded.new_container_id, Some("ctr_abc".to_string()));
        assert_eq!(loaded.new_port, Some(8080));
        assert_eq!(loaded.new_pod_name, Some("pod-xyz".to_string()));
        assert_eq!(
            loaded.new_manifest_path,
            Some(PathBuf::from("/tmp/manifest.yaml"))
        );
    }

    #[tokio::test]
    async fn test_get_nonexistent_deploy() {
        let db = test_db();
        let loaded = db.get_deploy("dep_nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_get_latest_for_nonexistent_app() {
        let db = test_db();
        let loaded = db.get_latest_deploy_for_app("nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_get_previous_successful_no_completed() {
        let db = test_db();
        let ctx = sample_deploy("dep_001", "myapp", DeployStatus::Failed);
        db.insert_deploy(&ctx).unwrap();

        let prev = db
            .get_previous_successful_deploy("myapp", "dep_001")
            .unwrap();
        assert!(prev.is_none());
    }

    #[tokio::test]
    async fn test_get_latest_deploys_per_app_empty() {
        let db = test_db();
        let latest = db.get_latest_deploys_per_app().unwrap();
        assert!(latest.is_empty());
    }

    #[tokio::test]
    async fn test_persistence_across_restart() {
        // Simulate a daemon restart by closing and reopening the database.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // First session: insert deploys.
        {
            let db = Db::open(&path).unwrap();
            let ctx1 = sample_deploy("dep_001", "app-a", DeployStatus::Completed);
            db.insert_deploy(&ctx1).unwrap();
            let mut ctx2 = sample_deploy("dep_002", "app-a", DeployStatus::Completed);
            ctx2.started_at = Utc::now() + chrono::Duration::seconds(10);
            db.insert_deploy(&ctx2).unwrap();
            let ctx3 = sample_deploy("dep_003", "app-b", DeployStatus::Failed);
            db.insert_deploy(&ctx3).unwrap();
        }

        // Second session: reopen and verify data survives.
        {
            let db = Db::open(&path).unwrap();

            // Individual lookups.
            let loaded = db.get_deploy("dep_001").unwrap().expect("should exist");
            assert_eq!(loaded.app, "app-a");
            assert_eq!(loaded.status, DeployStatus::Completed);

            // Latest per app.
            let latest = db.get_latest_deploys_per_app().unwrap();
            assert_eq!(latest.len(), 2);
            assert_eq!(latest.get("app-a").unwrap().id, "dep_002");
            assert_eq!(latest.get("app-b").unwrap().id, "dep_003");

            // Previous successful.
            let prev = db
                .get_previous_successful_deploy("app-a", "dep_002")
                .unwrap()
                .expect("should find previous completed");
            assert_eq!(prev.id, "dep_001");
        }
    }

    #[tokio::test]
    async fn test_strict_enforcement_rejects_wrong_type() {
        let db = test_db();

        // Attempt to insert a non-integer into the INTEGER `new_port` column.
        // STRICT tables reject this at the SQLite level.
        let conn = db.0.lock().unwrap();
        let result = conn.execute(
            "INSERT INTO deploys (id, app, image, tag, status, started_at, triggered_by, new_port)
             VALUES ('dep_bad', 'myapp', 'img', 'v1', 'accepted', '2024-01-01T00:00:00Z', 'cli', 'not-a-number')",
            [],
        );
        drop(conn);

        assert!(
            result.is_err(),
            "STRICT table should reject non-integer in INTEGER column"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cannot store"),
            "error message should mention the type mismatch: {msg}"
        );
    }
}
