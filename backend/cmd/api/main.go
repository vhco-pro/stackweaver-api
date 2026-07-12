// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/api/routes"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/handlers"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/profile"
	"github.com/michielvha/stackweaver/backend/internal/services/runner"
	"github.com/michielvha/stackweaver/backend/internal/services/sessions"
	teamsync "github.com/michielvha/stackweaver/backend/internal/services/team_sync"
	"github.com/michielvha/stackweaver/backend/internal/services/terraform"
	"github.com/michielvha/stackweaver/backend/internal/services/totp"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/queue"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/ansible"
	"github.com/michielvha/stackweaver/core/services/encryptionkey"
	"github.com/michielvha/stackweaver/core/services/oidc"
	statesvc "github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/services/variable"
	"github.com/michielvha/stackweaver/core/services/vcs"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

type Config struct {
	Server struct {
		Host         string        `yaml:"host"`
		Port         int           `yaml:"port"`
		ReadTimeout  time.Duration `yaml:"read_timeout"`
		WriteTimeout time.Duration `yaml:"write_timeout"`
	} `yaml:"server"`
	Database repository.Config `yaml:"database"`
	Zitadel  struct {
		Issuer       string `yaml:"issuer"`
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"` //nolint:gosec // G117: config field, not a hardcoded secret
	} `yaml:"zitadel"`
}

func main() {
	// Initialize logger first (reads LOG_LEVEL from environment)
	logLevel := os.Getenv("LOG_LEVEL")
	logger.Init(logLevel)

	// Load configuration
	// When CONFIG_PATH is explicitly set, the file must exist (misconfiguration is fatal).
	// When CONFIG_PATH is unset, the default path is tried; if missing the binary
	// continues with defaults + env-var overrides (enables file-free Kubernetes deploys).
	configPath := os.Getenv("CONFIG_PATH")
	explicitPath := configPath != ""
	if !explicitPath {
		configPath = "config/config.yaml"
	}

	config := defaultConfig()
	configData, err := os.ReadFile(configPath) //nolint:gosec // configPath is from environment variable, validated
	switch {
	case err == nil:
		if err := yaml.Unmarshal(configData, &config); err != nil {
			logger.Fatalf("Failed to parse config: %v", err)
		}
	case !explicitPath && (errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission)):
		logger.Info("No config file found, using environment variables only")
	default:
		logger.Fatalf("Failed to read config file: %v", err)
	}

	// Apply environment variable overrides (allows Kubernetes deployments to
	// inject configuration without modifying config.yaml).
	applyEnvOverrides(&config)

	// Initialize database
	db, err := repository.NewDatabase(config.Database)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	// Run database migrations
	logger.Info("Running database migrations...")

	// Enable UUID extension if not already enabled
	sqlDB, err := db.DB()
	if err != nil {
		logger.Fatalf("Failed to get underlying sql.DB: %v", err)
	}
	if _, err := sqlDB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\""); err != nil {
		logger.Warnf("Failed to enable uuid-ossp extension (may already be enabled): %v", err)
	}

	// Rebuild legacy single-column unique indexes on Ansible inventory host
	// and group names as the intended composite (inventory_id, name) indexes.
	// The original schema made host/group names globally unique across every
	// inventory, so the same name (e.g. "localhost") could only ever exist in
	// one inventory. Drop the legacy index when present so AutoMigrate (below)
	// recreates it as composite. Idempotent: once the index already covers
	// inventory_id it is left untouched.
	rebuildCompositeIndex := func(indexName, requiredColumn string) {
		var indexdef string
		if err := db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = ?", indexName).Scan(&indexdef).Error; err != nil {
			logger.Warnf("Failed to inspect index %s: %v", indexName, err)
			return
		}
		if indexdef != "" && !strings.Contains(indexdef, requiredColumn) {
			if err := db.Exec("DROP INDEX IF EXISTS " + indexName).Error; err != nil {
				logger.Warnf("Failed to drop legacy index %s: %v", indexName, err)
			} else {
				logger.Infof("Dropped legacy single-column index %s; AutoMigrate will rebuild it as composite (%s, name)", indexName, requiredColumn)
			}
		}
	}
	rebuildCompositeIndex("idx_inventory_host", "inventory_id")
	rebuildCompositeIndex("idx_inventory_group", "inventory_id")
	// Playbook and job template names were globally unique by accident (the
	// uniqueIndex tag only covered the name column); the intended scope is
	// per-project.
	rebuildCompositeIndex("idx_project_playbook", "project_id")
	rebuildCompositeIndex("idx_project_template", "project_id")
	// AUD-019: the same single-column-index accident affected workspace, runner,
	// Ansible credential and Ansible inventory names — all globally unique instead
	// of scoped to their project/organization. Drop the legacy indexes so AutoMigrate
	// rebuilds them as the intended composite (scope, name) indexes.
	rebuildCompositeIndex("idx_project_workspace", "project_id")
	rebuildCompositeIndex("idx_runner_org_name", "organization_id")
	rebuildCompositeIndex("idx_org_credential", "organization_id")
	rebuildCompositeIndex("idx_org_inventory", "organization_id")
	// AUD-137: the Ansible notification-template name was globally unique (uniqueIndex tag
	// covered only Name), so two orgs couldn't both have a template named e.g. "slack".
	// Drop the legacy single-column index so AutoMigrate rebuilds it as (organization_id, name).
	rebuildCompositeIndex("idx_org_notification", "organization_id")

	// queued_at (NULL = held by the template concurrency gate) is introduced by
	// this release. Detect whether the column predates this startup so jobs
	// created before the column existed can be backfilled exactly once below —
	// without the backfill they would all look "held" and be re-dispatched.
	var hasQueuedAt bool
	if err := db.Raw("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ansible_jobs' AND column_name = 'queued_at')").Scan(&hasQueuedAt).Error; err != nil {
		logger.Warnf("Failed to inspect ansible_jobs.queued_at column: %v", err)
		hasQueuedAt = true // fail safe: never backfill on uncertainty
	}

	// Notification dispatch markers are introduced by this release. Detect
	// whether they predate this startup so pre-existing finished jobs can be
	// marked notified exactly once below — otherwise attaching a notification
	// channel later would replay every historical job as a fresh notification.
	var hasNotifyMarkers bool
	if err := db.Raw("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ansible_jobs' AND column_name = 'notified_finished_at')").Scan(&hasNotifyMarkers).Error; err != nil {
		logger.Warnf("Failed to inspect ansible_jobs.notified_finished_at column: %v", err)
		hasNotifyMarkers = true // fail safe: never backfill on uncertainty
	}

	// The template multi-credential join table is introduced by this release;
	// when it doesn't exist yet, seed it from the legacy single credential_id
	// after AutoMigrate creates it.
	var hasTemplateCredentials bool
	if err := db.Raw("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ansible_job_template_credentials')").Scan(&hasTemplateCredentials).Error; err != nil {
		logger.Warnf("Failed to inspect ansible_job_template_credentials table: %v", err)
		hasTemplateCredentials = true // fail safe: never backfill on uncertainty
	}

	// AUD-150: variable_sets.global is introduced by this release. It decouples the TFE `global` flag
	// from ownership (previously both were crammed into `scope`). Detect whether the column predates
	// this startup so legacy rows can be backfilled exactly once below — without it every legacy set
	// would read global=false and org-wide sets would stop applying to all workspaces.
	var hasVarsetGlobal bool
	if err := db.Raw("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'variable_sets' AND column_name = 'global')").Scan(&hasVarsetGlobal).Error; err != nil {
		logger.Warnf("Failed to inspect variable_sets.global column: %v", err)
		hasVarsetGlobal = true // fail safe: never backfill on uncertainty
	}

	// Run GORM AutoMigrate to create/update tables. The model list is the shared
	// models.AllModels() source of truth (also used by integration tests) so schema drift
	// between the app and the tests is impossible.
	if err := models.AutoMigrate(db); err != nil {
		logger.Fatalf("Failed to run database migrations: %v", err)
	}

	// Ad hoc jobs have no playbook; AutoMigrate never relaxes an existing NOT
	// NULL constraint, so drop it explicitly (idempotent).
	if err := db.Exec("ALTER TABLE ansible_jobs ALTER COLUMN playbook_id DROP NOT NULL").Error; err != nil {
		logger.Warnf("Failed to drop NOT NULL on ansible_jobs.playbook_id: %v", err)
	}

	// AUD-020: users.email must allow multiple "no email" (empty-string) users. The original full
	// UNIQUE index on email rejected a second empty email, which forced identity-hijack and
	// row-deletion workarounds in user provisioning. Replace it with a PARTIAL unique index that
	// only constrains non-empty emails, so any number of email-less users can coexist. Idempotent:
	// the legacy full index is replaced once, then the partial index is left in place.
	var emailIdxDef string
	if err := db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_users_email'").Scan(&emailIdxDef).Error; err != nil {
		logger.Warnf("Failed to inspect idx_users_email: %v", err)
	} else if emailIdxDef != "" && !strings.Contains(emailIdxDef, "WHERE") {
		// Legacy full unique index — drop it so the partial index below replaces it.
		if err := db.Exec("DROP INDEX IF EXISTS idx_users_email").Error; err != nil {
			logger.Warnf("Failed to drop legacy idx_users_email: %v", err)
		} else {
			logger.Info("Dropped legacy full unique idx_users_email; recreating as partial (WHERE email <> '')")
		}
	}
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email) WHERE email <> ''").Error; err != nil {
		logger.Warnf("Failed to create partial unique idx_users_email: %v", err)
	}

	// AUD-150: one-time backfill for the new variable_sets.global column. Legacy rows encoded the TFE
	// `global` flag in `scope` ('organization' == global, 'workspace' == non-global). A legacy org-owned
	// set applied to ALL workspaces only when it had scope='organization' AND no explicit attachments;
	// otherwise it was gated to its attached projects/workspaces. Reconstruct `global` from that, then
	// normalize `scope` to reflect ownership (organization vs project). Idempotent (runs once, when the
	// column was just added).
	if !hasVarsetGlobal {
		if err := db.Exec(`UPDATE variable_sets SET global = true
			WHERE project_id IS NULL AND scope = 'organization'
			  AND NOT EXISTS (SELECT 1 FROM variable_set_projects vsp WHERE vsp.variable_set_id = variable_sets.id)
			  AND NOT EXISTS (SELECT 1 FROM variable_set_workspaces vsw WHERE vsw.variable_set_id = variable_sets.id)`).Error; err != nil {
			logger.Warnf("Failed to backfill variable_sets.global: %v", err)
		} else if err := db.Exec(`UPDATE variable_sets SET scope = CASE WHEN project_id IS NULL THEN 'organization' ELSE 'project' END`).Error; err != nil {
			logger.Warnf("Failed to normalize variable_sets.scope to ownership: %v", err)
		} else {
			logger.Info("Backfilled variable_sets.global and normalized scope to ownership (AUD-150)")
		}
	}

	// One-time backfill: jobs created before queued_at existed were all
	// dispatched at creation time, so mark them released.
	if !hasQueuedAt {
		if err := db.Exec("UPDATE ansible_jobs SET queued_at = created_at WHERE queued_at IS NULL").Error; err != nil {
			logger.Warnf("Failed to backfill ansible_jobs.queued_at: %v", err)
		} else {
			logger.Info("Backfilled ansible_jobs.queued_at for pre-existing jobs")
		}
	}

	// One-time cutover: mark every pre-existing job/workflow run as already
	// notified for the transitions that already happened, so the polling
	// notification worker only fires on transitions that occur AFTER this
	// upgrade. Without this, attaching a channel replays the entire history.
	if !hasNotifyMarkers {
		for _, stmt := range []string{
			"UPDATE ansible_jobs SET notified_started_at = COALESCE(started_at, created_at) WHERE started_at IS NOT NULL AND notified_started_at IS NULL",
			"UPDATE ansible_jobs SET notified_finished_at = COALESCE(finished_at, updated_at) WHERE finished_at IS NOT NULL AND notified_finished_at IS NULL",
			"UPDATE ansible_workflow_jobs SET notified_started_at = COALESCE(started_at, created_at) WHERE started_at IS NOT NULL AND notified_started_at IS NULL",
			"UPDATE ansible_workflow_jobs SET notified_finished_at = COALESCE(finished_at, updated_at) WHERE finished_at IS NOT NULL AND notified_finished_at IS NULL",
		} {
			if err := db.Exec(stmt).Error; err != nil {
				logger.Warnf("Failed to backfill notification markers: %v", err)
			}
		}
		logger.Info("Backfilled notification dispatch markers for pre-existing jobs and workflow runs")
	}

	// One-time backfill: seed the multi-credential set from the legacy single
	// credential reference.
	if !hasTemplateCredentials {
		if err := db.Exec("INSERT INTO ansible_job_template_credentials (ansible_job_template_id, ansible_credential_id) SELECT id, credential_id FROM ansible_job_templates WHERE credential_id IS NOT NULL ON CONFLICT DO NOTHING").Error; err != nil {
			logger.Warnf("Failed to backfill ansible_job_template_credentials: %v", err)
		} else {
			logger.Info("Backfilled ansible_job_template_credentials from legacy credential_id")
		}
	}

	// Schedules consolidation: the embedded per-template cron fields were never
	// executed by anything — migrate them into real AnsibleSchedule rows (which
	// the scheduler does run) and switch the embedded flag off. Idempotent:
	// after the first run no template has schedule_enabled set.
	if err := db.Exec(`
		INSERT INTO ansible_schedules (id, organization_id, name, description, type, status, job_template_id, cron_expression, timezone, config, created_at, updated_at)
		SELECT uuid_generate_v4(), p.organization_id, 'Migrated: ' || t.name,
		       'Migrated from the job template''s embedded schedule fields',
		       'job_template', 'enabled', t.id, t.schedule_cron, 'UTC', '{}', NOW(), NOW()
		FROM ansible_job_templates t
		JOIN projects p ON p.id = t.project_id
		WHERE t.schedule_enabled = true AND t.schedule_cron <> ''
		  AND NOT EXISTS (SELECT 1 FROM ansible_schedules s WHERE s.job_template_id = t.id)`).Error; err != nil {
		logger.Warnf("Failed to migrate embedded template schedules: %v", err)
	} else if err := db.Exec("UPDATE ansible_job_templates SET schedule_enabled = false WHERE schedule_enabled = true").Error; err != nil {
		logger.Warnf("Failed to clear embedded template schedule flags: %v", err)
	}
	// State Storage Rework: object storage is now the single source of truth for raw state.
	// The legacy state_versions.state_data jsonb column is dropped. On a deployment upgrading
	// from an older release the column still exists with data, so FIRST materialize any
	// not-yet-materialized history from it (raw SQL — the model no longer maps the column),
	// THEN drop it. Guarded by column existence so this is a no-op on already-migrated DBs.
	{
		var hasStateDataCol bool
		if err := db.Raw("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'state_versions' AND column_name = 'state_data')").Scan(&hasStateDataCol).Error; err != nil {
			hasStateDataCol = false // fail safe: skip on uncertainty
		}
		if hasStateDataCol {
			// Encrypt sensitive output values during backfill too (#95), so an upgrading
			// deployment's legacy plaintext sensitive outputs land encrypted in the new
			// table rather than waiting for the next state write. nil key = plaintext.
			var backfillCrypto *crypto.CryptoService
			if keyBytes := encryptionkey.Resolve(os.Getenv("ENCRYPTION_KEY")); len(keyBytes) > 0 {
				backfillCrypto, _ = crypto.NewCryptoService(keyBytes)
			}
			materializer := statesvc.NewMaterializer(
				repository.NewStateVersionOutputRepository(db),
				repository.NewStateVersionResourceRepository(db),
				backfillCrypto,
			)
			type pendingRow struct {
				ID        string
				StateData []byte
			}
			var rows []pendingRow
			if err := db.Raw(`SELECT id, state_data FROM state_versions
				WHERE state_data IS NOT NULL AND state_data::text NOT IN ('null', '{}')
				  AND NOT EXISTS (SELECT 1 FROM state_version_resources r WHERE r.state_version_id = state_versions.id)
				  AND NOT EXISTS (SELECT 1 FROM state_version_outputs o WHERE o.state_version_id = state_versions.id)`).Scan(&rows).Error; err != nil {
				logger.Warnf("Failed to query state versions for materialization backfill: %v", err)
			} else if len(rows) > 0 {
				backfilled := 0
				for _, row := range rows {
					var sd map[string]any
					if err := json.Unmarshal(row.StateData, &sd); err != nil {
						logger.Warnf("Backfill: failed to parse state_data for %s: %v", row.ID, err)
						continue
					}
					if err := materializer.Materialize(row.ID, sd); err != nil {
						logger.Warnf("Backfill: failed to materialize state version %s: %v", row.ID, err)
						continue
					}
					backfilled++
				}
				logger.Infof("Backfilled materialized outputs/resources for %d state version(s)", backfilled)
			}
			// Drop the duplicate column now that history is materialized.
			if err := db.Exec("ALTER TABLE state_versions DROP COLUMN IF EXISTS state_data").Error; err != nil {
				logger.Warnf("Failed to drop state_versions.state_data column: %v", err)
			} else {
				logger.Info("Dropped legacy state_versions.state_data column (state is in object storage)")
			}
		}
	}

	// Initialize the denormalized workspace.resource_count from each workspace's latest
	// state version's materialized managed resources. Self-healing guard: runs only when a
	// workspace has materialized managed resources but a zero count (i.e. not yet initialized),
	// so it fires once after the resource_count column is added and is a no-op thereafter.
	// Live state writes keep the count current via the materializer (SyncWorkspaceResourceCount).
	{
		var needsResourceCountInit bool
		if err := db.Raw(`SELECT EXISTS (
			SELECT 1 FROM workspaces w
			WHERE w.resource_count = 0
			  AND EXISTS (SELECT 1 FROM state_versions sv
			              JOIN state_version_resources r ON r.state_version_id = sv.id
			              WHERE sv.workspace_id = w.id AND r.mode = 'managed')
		)`).Scan(&needsResourceCountInit).Error; err != nil {
			needsResourceCountInit = false // fail safe
		}
		if needsResourceCountInit {
			if err := db.Exec(`
				UPDATE workspaces w SET resource_count = COALESCE((
					SELECT count(*) FROM state_version_resources r
					JOIN state_versions sv ON r.state_version_id = sv.id
					WHERE sv.workspace_id = w.id AND r.mode = 'managed'
					  AND sv.version = (SELECT max(version) FROM state_versions sv2 WHERE sv2.workspace_id = w.id)
				), 0)`).Error; err != nil {
				logger.Warnf("Failed to initialize workspace resource counts: %v", err)
			} else {
				logger.Info("Initialized workspace resource_count from materialized resources")
			}
		}
	}

	// AUD-023: reconcile foreign-key ON DELETE behavior. GORM's AutoMigrate creates foreign keys
	// but never alters an existing constraint's ON DELETE clause, so every historical constraint is
	// NO ACTION — which is why deleting a parent relied on long, hand-ordered manual cascades in the
	// repositories (fragile: one missed child orphans rows or wedges the delete). This converts each
	// constraint to its intended behavior so the database enforces integrity as a backstop, covering
	// the full organization/project object graph (an interconnected closure — it must be converted as
	// one consistent set, since a partial conversion would make a parent delete fail against a
	// leftover NO ACTION reference). The rules (see models.FKDeleteRules):
	//   - CASCADE for compositions and junction rows (a child that cannot exist without its parent),
	//     so a single DELETE reaches every descendant.
	//   - SET NULL for nullable references whose row outlives the parent — critically the org-scoped
	//     resources (schedules, variable sets, workflows, inventories, credentials, configs) that
	//     survive a *project* delete but point at project-scoped rows being removed; without SET NULL
	//     those surviving references would block the delete.
	//   - Untouched (NO ACTION): the NOT-NULL "uses" references (job_template -> playbook/inventory,
	//     job -> inventory, runner -> agent_pool). Both endpoints die together in any org/project
	//     delete (the deferred end-of-statement check passes), and a standalone delete of an in-use
	//     resource stays correctly blocked.
	// Idempotent: a constraint already at the desired behavior is skipped; a missing/renamed
	// constraint (e.g. a GORM join table that lacks FKs on a fresh migrate) is skipped quietly.
	reconcileFKOnDelete := func(table, constraint, behavior string) {
		var def string
		if err := db.Raw(
			"SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = ? AND conrelid = ?::regclass",
			constraint, table,
		).Scan(&def).Error; err != nil {
			logger.Warnf("FK reconcile: inspect %s.%s: %v", table, constraint, err)
			return
		}
		if def == "" {
			return // constraint absent on this schema variant — nothing to reconcile
		}
		want := "ON DELETE " + behavior
		if strings.Contains(def, want) {
			return // already at the desired behavior
		}
		base := def
		if i := strings.Index(base, " ON DELETE "); i >= 0 {
			base = base[:i] // strip any existing (non-matching) ON DELETE clause
		}
		desired := base + " " + want
		if err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s", table, constraint)).Error; err != nil {
				return err
			}
			return tx.Exec(fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s %s", table, constraint, desired)).Error
		}); err != nil {
			logger.Warnf("FK reconcile: convert %s.%s to %s: %v", table, constraint, behavior, err)
		} else {
			logger.Infof("FK reconcile: %s.%s -> ON DELETE %s", table, constraint, behavior)
		}
	}
	// Some pure GORM many-to-many join tables (variable_set_projects, variable_set_workspaces) are
	// created with NO foreign keys at all on a fresh migrate — so deleting a variable set, project,
	// or workspace leaves orphaned join rows (the reconciliation below can only convert constraints
	// that already exist). Older DBs migrated by earlier GORM versions do have these FKs (as
	// NO ACTION), so this only creates what is missing; existing constraints are left for the
	// reconcile pass to convert to CASCADE. Idempotent: skipped when the named constraint exists.
	ensureJoinFK := func(table, constraint, column, parent, parentCol string) {
		var exists bool
		if err := db.Raw(
			"SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname = ? AND conrelid = ?::regclass)",
			constraint, table,
		).Scan(&exists).Error; err != nil {
			logger.Warnf("ensure join FK: inspect %s.%s: %v", table, constraint, err)
			return
		}
		if exists {
			return
		}
		if err := db.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s(%s) ON DELETE CASCADE",
			table, constraint, column, parent, parentCol,
		)).Error; err != nil {
			logger.Warnf("ensure join FK: create %s.%s: %v", table, constraint, err)
		} else {
			logger.Infof("ensure join FK: created %s.%s -> %s(%s) ON DELETE CASCADE", table, constraint, parent, parentCol)
		}
	}
	ensureJoinFK("variable_set_projects", "fk_variable_set_projects_variable_set", "variable_set_id", "variable_sets", "id")
	ensureJoinFK("variable_set_projects", "fk_variable_set_projects_project", "project_id", "projects", "id")
	ensureJoinFK("variable_set_workspaces", "fk_variable_set_workspaces_variable_set", "variable_set_id", "variable_sets", "id")
	ensureJoinFK("variable_set_workspaces", "fk_variable_set_workspaces_workspace", "workspace_id", "workspaces", "id")

	for _, r := range models.FKDeleteRules {
		reconcileFKOnDelete(r.Table, r.Constraint, r.Behavior)
	}

	logger.Info("Database migrations completed successfully")

	// Seed official Terraform versions (like TFE's built-in version catalog)
	handlers.SeedOfficialVersions(db)
	logger.Info("Terraform versions seeded")

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)

	// Initialize auth service
	authService := auth.NewService(userRepo)

	// Initialize Zitadel verifier
	// Prefer environment variables over config file values
	zitadelClientID := os.Getenv("ZITADEL_API_CLIENT_ID")
	if zitadelClientID == "" {
		zitadelClientID = config.Zitadel.ClientID
	}

	zitadelClientSecret := os.Getenv("ZITADEL_API_CLIENT_SECRET")
	if zitadelClientSecret == "" {
		zitadelClientSecret = config.Zitadel.ClientSecret
	}

	zitadelIssuer := os.Getenv("ZITADEL_ISSUER")
	if zitadelIssuer == "" {
		zitadelIssuer = config.Zitadel.Issuer
	}

	// ZITADEL_INTERNAL_ADDR is used for JWKS fetching and gRPC connections (stays on localhost)
	// ZITADEL_ISSUER may be an external domain (e.g. https://zitadel.example.com) for JWT validation
	zitadelInternalAddr := os.Getenv("ZITADEL_INTERNAL_ADDR")
	if zitadelInternalAddr == "" {
		zitadelInternalAddr = "internal-zitadel:8080"
	}

	if err := authService.InitializeZitadel(zitadelIssuer, zitadelClientID, zitadelClientSecret, zitadelInternalAddr); err != nil {
		logger.Fatalf("Failed to initialize Zitadel verifier: %v", err)
	}
	// AUD-012: register the Stackweaver client_ids an access token may carry in `aud`. Real
	// user tokens are issued to the frontend PKCE client, so its id must be accepted; the API
	// client id covers any future service-to-service token. Tokens for other clients on the
	// same Zitadel instance are rejected.
	authService.RegisterAudience(zitadelClientID)
	zitadelFrontendClientID := os.Getenv("ZITADEL_FRONTEND_CLIENT_ID")
	if zitadelFrontendClientID == "" {
		logger.Warn("ZITADEL_FRONTEND_CLIENT_ID not set — access-token audience enforcement (AUD-012) may reject real user tokens. Set it to the frontend OIDC client_id.")
	}
	authService.RegisterAudience(zitadelFrontendClientID)

	loginServicePAT := os.Getenv("ZITADEL_LOGIN_SERVICE_USER_TOKEN")
	if loginServicePAT == "" {
		logger.Warn("ZITADEL_LOGIN_SERVICE_USER_TOKEN not set, TOTP service will not be available")
	}

	var totpService *totp.Service
	if loginServicePAT != "" {
		totpService, err = totp.NewService(zitadelIssuer, zitadelInternalAddr, loginServicePAT)
		if err != nil {
			logger.Warnf("Failed to initialize TOTP service: %v", err)
		}
	}

	// Initialize Profile service
	var profileService *profile.Service
	if loginServicePAT != "" {
		profileService, err = profile.NewService(zitadelIssuer, zitadelInternalAddr, loginServicePAT)
		if err != nil {
			logger.Warnf("Failed to initialize Profile service: %v", err)
		}
	}

	// Initialize Sessions service
	var sessionsService *sessions.Service
	if loginServicePAT != "" {
		sessionsService, err = sessions.NewService(zitadelIssuer, zitadelInternalAddr, loginServicePAT)
		if err != nil {
			logger.Warnf("Failed to initialize Sessions service: %v", err)
		}
	}

	// Initialize API Key service
	apiKeyRepo := repository.NewAPIKeyRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	apiKeyService := apikey.NewService(apiKeyRepo, orgRepo, projectRepo, teamRepo)

	// Set API key service in auth service for authentication
	authService.SetAPIKeyService(apiKeyService)

	// Initialize TeamSync service for automatic SSO team assignment
	teamSyncConfig := teamsync.ConfigFromEnv()
	teamSyncService := teamsync.NewService(teamSyncConfig, teamRepo, orgRepo)
	authService.SetTeamSyncer(teamSyncService)
	if teamSyncConfig.Enabled {
		logger.Info("SSO team sync enabled")
	}

	// Initialize GitHub App Manager (loaded once at startup - like Terraform Enterprise)
	githubAppManager, err := vcs.NewGitHubAppManager()
	switch {
	case err != nil:
		logger.Warnf("Failed to initialize GitHub App Manager: %v (GitHub App features will be disabled)", err)
		githubAppManager = nil
	case githubAppManager != nil && githubAppManager.IsEnabled():
		logger.Info("GitHub App Manager initialized successfully")
	default:
		logger.Info("GitHub App Manager not configured (set GITHUB_APP_ID, GITHUB_APP_NAME, and GITHUB_APP_PRIVATE_KEY to enable)")
	}

	// Initialize Scheduler Service for scheduled Ansible jobs
	var schedulerService *ansible.SchedulerService
	schedulerEnabled := os.Getenv("ANSIBLE_SCHEDULER_ENABLED") != "false" // Enabled by default

	if schedulerEnabled {
		// Initialize repositories needed for scheduler
		scheduleRepo := repository.NewAnsibleScheduleRepository(db)
		ansibleJobRepo := repository.NewAnsibleJobRepository(db)
		ansibleTemplateRepo := repository.NewAnsibleJobTemplateRepository(db)
		ansiblePlaybookRepo := repository.NewAnsiblePlaybookRepository(db)
		ansibleInventoryRepo := repository.NewAnsibleInventoryRepository(db)
		ansibleCredentialRepo := repository.NewAnsibleCredentialRepository(db)
		inventorySourceRepo := repository.NewAnsibleInventorySourceRepository(db)

		// Get encryption key for credentials. Fails loud on a missing/insecure key
		// (AUD-013); DEV_INSECURE_KEY=1 is the local-dev escape hatch.
		encryptionKey := os.Getenv("ANSIBLE_ENCRYPTION_KEY")
		if encryptionKey == "" {
			encryptionKey = os.Getenv("ENCRYPTION_KEY")
		}
		encryptionKeyBytes := encryptionkey.Resolve(encryptionKey)

		// Initialize crypto service
		cryptoService, err := crypto.NewCryptoService(encryptionKeyBytes)
		if err != nil {
			logger.Warnf("Failed to initialize crypto service for scheduler: %v", err)
		}

		// Initialize inventory source service
		inventorySourceService := ansible.NewInventorySourceService(
			inventorySourceRepo,
			ansibleInventoryRepo,
			ansibleCredentialRepo,
			cryptoService,
		)
		// Record scheduler/workflow-triggered sync runs in the history table
		inventorySourceService.SetSyncRepo(repository.NewAnsibleInventorySyncRepository(db))

		// Wire OIDC workload identity support for Azure inventory sync
		azureOIDCRepo := repository.NewAzureOIDCConfigurationRepository(db)
		oidcSigningKey, oidcErr := oidc.NewSigningKey()
		if oidcErr != nil {
			logger.Warnf("Failed to initialize OIDC signing key for inventory sync: %v (OIDC auth will be disabled)", oidcErr)
		} else {
			issuerURL := os.Getenv("OIDC_ISSUER_URL")
			if issuerURL == "" {
				issuerURL = os.Getenv("API_URL")
			}
			if issuerURL == "" {
				issuerURL = "http://localhost:8022"
			}
			oidcTokenService := oidc.NewTokenService(oidcSigningKey, issuerURL)
			inventorySourceService.SetOIDCServices(azureOIDCRepo, oidcTokenService)
			logger.Info("OIDC workload identity enabled for Azure inventory sync")
		}

		// Initialize variable service for Ansible (with variable sets, workspace, and template variable support)
		workspaceRepoForAnsible := repository.NewWorkspaceRepository(db)
		variableRepoForAnsible := repository.NewVariableRepository(db)
		variableSetRepoForAnsible := repository.NewVariableSetRepository(db)
		templateVariableRepoForAnsible := repository.NewAnsibleJobTemplateVariableRepository(db)
		variableServiceForAnsible := variable.NewServiceWithTemplateVariables(variableRepoForAnsible, variableSetRepoForAnsible, workspaceRepoForAnsible, templateVariableRepoForAnsible, encryptionKeyBytes)

		// Redis queue so scheduled launches and released held jobs actually
		// dispatch to platform runners (a nil queue here used to leave scheduled
		// jobs pending forever).
		redisHost := os.Getenv("REDIS_HOST")
		if redisHost == "" {
			redisHost = "localhost"
		}
		redisPort := 6379
		if portStr := os.Getenv("REDIS_PORT"); portStr != "" {
			if p, perr := strconv.Atoi(portStr); perr == nil {
				redisPort = p
			}
		}
		// Assign through an interface var so a connection failure leaves a true
		// nil queue (a nil *RedisQueue assigned to a queue.Queue is a typed-nil
		// that defeats the `== nil` dispatch guards and panics on Enqueue).
		var schedulerQueue queue.Queue
		if q, qErr := queue.NewRedisQueue(redisHost, redisPort, os.Getenv("REDIS_PASSWORD"), 0); qErr != nil {
			logger.Warnf("Failed to initialize Redis queue for the Ansible scheduler: %v (scheduled platform jobs will not dispatch)", qErr)
		} else {
			schedulerQueue = q
		}

		// Initialize job service with variable set support
		jobService := ansible.NewJobServiceWithVariables(
			ansibleJobRepo,
			ansiblePlaybookRepo,
			ansibleInventoryRepo,
			ansibleTemplateRepo,
			projectRepo,
			variableServiceForAnsible,
			schedulerQueue,
		)
		// Honor update_on_launch on scheduled/held launches: stale dynamic
		// sources sync first and the job is held until they settle.
		jobService.SetInventorySourceRepo(inventorySourceRepo)
		jobService.SetOrganizationRepo(repository.NewOrganizationRepository(db))

		// Create scheduler service
		schedulerService = ansible.NewSchedulerService(
			scheduleRepo,
			ansibleJobRepo,
			ansibleTemplateRepo,
			ansiblePlaybookRepo,
			inventorySourceService,
			jobService,
			repository.NewOrganizationRepository(db),
		)

		// Workflow execution engine advanced by the scheduler tick.
		schedulerService.SetWorkflowEngine(ansible.NewWorkflowEngineService(
			repository.NewAnsibleWorkflowRepository(db),
			ansibleJobRepo,
			jobService,
			inventorySourceService,
		))

		// Notification delivery advanced by the scheduler tick.
		if cryptoSvc, cryptoErr := crypto.NewCryptoService(encryptionKeyBytes); cryptoErr == nil {
			schedulerService.SetNotificationService(ansible.NewNotificationService(
				repository.NewAnsibleNotificationRepository(db),
				ansibleJobRepo,
				cryptoSvc,
			))
		} else {
			logger.Warnf("Notification service disabled: %v", cryptoErr)
		}

		// Start the scheduler
		schedulerService.Start()
		logger.Info("Ansible Scheduler Service started")
	} else {
		logger.Info("Ansible Scheduler Service disabled (set ANSIBLE_SCHEDULER_ENABLED=true to enable)")

		// The held-job gates (template concurrency, update-on-launch syncs,
		// constructed rebuilds) apply to every launch regardless of this flag,
		// and the scheduler tick is their only release path — so without the
		// scheduler, held jobs would stay pending forever. Run a minimal
		// release loop instead.
		var releaseQueue queue.Queue
		{
			redisHost := os.Getenv("REDIS_HOST")
			if redisHost == "" {
				redisHost = "localhost"
			}
			redisPort := 6379
			if portStr := os.Getenv("REDIS_PORT"); portStr != "" {
				if p, perr := strconv.Atoi(portStr); perr == nil {
					redisPort = p
				}
			}
			if q, qErr := queue.NewRedisQueue(redisHost, redisPort, os.Getenv("REDIS_PASSWORD"), 0); qErr != nil {
				logger.Warnf("Held-job release loop: Redis unavailable: %v (released platform jobs will not dispatch)", qErr)
			} else {
				releaseQueue = q
			}
		}
		releaseJobService := ansible.NewJobService(
			repository.NewAnsibleJobRepository(db),
			repository.NewAnsiblePlaybookRepository(db),
			repository.NewAnsibleInventoryRepository(db),
			repository.NewAnsibleJobTemplateRepository(db),
			repository.NewProjectRepository(db),
			releaseQueue,
		)
		releaseJobService.SetInventorySourceRepo(repository.NewAnsibleInventorySourceRepository(db))
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				releaseJobService.ReleaseHeldJobs(context.Background())
			}
		}()
		logger.Info("Held-job release loop started (scheduler disabled)")
	}

	// Initialize Drift Detection Service for Terraform workspaces
	var driftDetectionService *terraform.DriftDetectionService
	driftDetectionEnabled := os.Getenv("TERRAFORM_DRIFT_DETECTION_ENABLED") != "false" // Enabled by default

	if driftDetectionEnabled {
		workspaceRepo := repository.NewWorkspaceRepository(db)
		runRepo := repository.NewRunRepository(db)
		configVersionRepo := repository.NewConfigurationVersionRepository(db)

		driftDetectionService = terraform.NewDriftDetectionService(
			workspaceRepo,
			runRepo,
			configVersionRepo,
		)

		// Start the drift detection service
		driftDetectionService.Start()
		logger.Info("Terraform Drift Detection Service started")
	} else {
		logger.Info("Terraform Drift Detection Service disabled (set TERRAFORM_DRIFT_DETECTION_ENABLED=true to enable)")
	}

	// Initialize and start Runner Monitor Service (marks stale runners as offline)
	runnerMonitorEnabled := os.Getenv("RUNNER_MONITOR_ENABLED") != "false" // Enabled by default
	var runnerMonitorService *runner.MonitorService
	if runnerMonitorEnabled {
		runnerRepo := repository.NewRunnerRepository(db)
		runnerMonitorService = runner.NewMonitorService(runnerRepo)
		go runnerMonitorService.Start(context.Background())
		logger.Info("Runner Monitor Service started")
	} else {
		logger.Info("Runner Monitor Service disabled (set RUNNER_MONITOR_ENABLED=true to enable)")
	}

	// Initialize Auth Proxy for custom login UI (replaces the hosted Zitadel login-ui container)
	// Round 25 hardening (item 15): in production, refuse to start when
	// ZITADEL_API_CLIENT_ID is empty. Without it, backchannel-logout
	// audience binding silently disables and any Zitadel-signed
	// logout_token from any other RP on the same instance can terminate
	// sessions in this app (Round 23 Finding 1). The handler-side check
	// in `getBackchannelVerifier` would also panic, but only on first
	// backchannel request — possibly hours/days after deploy. Failing
	// here at startup gives the operator instant feedback (pod
	// CrashLoopBackOff visible in helm install output).
	isProduction := os.Getenv("GIN_MODE") == "release"
	if isProduction && loginServicePAT != "" && zitadelClientID == "" {
		logger.Errorf("startup: ZITADEL_API_CLIENT_ID is empty in production — refusing to start. Set ZITADEL_API_CLIENT_ID to the OIDC client_id this RP is registered under at Zitadel (required for backchannel-logout audience binding per OIDC §2.6).")
		os.Exit(1)
	}

	var authProxy *handlers.AuthProxy
	if loginServicePAT != "" {
		zitadelInternalURL := "http://" + zitadelInternalAddr
		notificationMode := handlers.NotificationModeReturnCode
		if mode := os.Getenv("STACKWEAVER_NOTIFICATION_MODE"); mode == "email" {
			notificationMode = handlers.NotificationModeEmail
		}
		// F-sec-5/6 lockout — env-overridable so prod / staging / dev
		// can each pick a sensible threshold. The defaults inside
		// NewAuthProxy (5 attempts in 15 min) cover the common case;
		// here we only override when the operator explicitly opts in.
		lockoutThreshold := 0
		if v := os.Getenv("STACKWEAVER_LOGINNAME_LOCKOUT_THRESHOLD"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				lockoutThreshold = n
			}
		}
		var lockoutWindow time.Duration
		if v := os.Getenv("STACKWEAVER_LOGINNAME_LOCKOUT_WINDOW"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				lockoutWindow = d
			}
		}
		// Round 25 Wave 5 (item 5): parse STACKWEAVER_POST_LOGOUT_HOSTS
		// (comma-separated extra hosts the EndSession redirect-host
		// allowlist will accept on top of STACKWEAVER_APP_URL's host).
		var postLogoutHosts []string
		if v := os.Getenv("STACKWEAVER_POST_LOGOUT_HOSTS"); v != "" {
			for _, h := range strings.Split(v, ",") {
				if h = strings.TrimSpace(h); h != "" {
					postLogoutHosts = append(postLogoutHosts, h)
				}
			}
		}

		// AUD-113/AUD-071: parse STACKWEAVER_TRUSTED_HOSTS (comma-separated extra
		// hosts honored in X-Forwarded-Host / X-Zitadel-* headers when building the
		// OIDC discovery doc + IdP redirect URLs). The hosts of STACKWEAVER_PUBLIC_URL,
		// STACKWEAVER_APP_URL and the Zitadel issuer are added automatically in
		// NewAuthProxy; this is for any additional fronting hostname.
		var trustedForwardHosts []string
		if v := os.Getenv("STACKWEAVER_TRUSTED_HOSTS"); v != "" {
			for _, h := range strings.Split(v, ",") {
				if h = strings.TrimSpace(h); h != "" {
					trustedForwardHosts = append(trustedForwardHosts, h)
				}
			}
		}

		// Round 25 Wave 6 (item 6 / Round 22 OOS): parse the optional
		// shared decoy secret for HA deployments. Base64-encoded ≥32
		// bytes. Empty / unset → NewAuthProxy generates a per-process
		// random secret (single-replica friendly). Misconfiguration
		// (set but invalid encoding / too short) is fatal in
		// production so the operator notices.
		var decoySecret []byte
		if raw := os.Getenv("STACKWEAVER_DECOY_SECRET"); raw != "" {
			decoded, err := base64.StdEncoding.DecodeString(raw)
			switch {
			case err != nil:
				if isProduction {
					logger.Errorf("startup: STACKWEAVER_DECOY_SECRET is not valid base64 (production refuses to start with a bad shared secret): %v", err)
					os.Exit(1)
				}
				logger.Warnf("startup: STACKWEAVER_DECOY_SECRET is not valid base64 — falling back to per-process random secret: %v", err)
			case len(decoded) < 32:
				if isProduction {
					logger.Errorf("startup: STACKWEAVER_DECOY_SECRET decodes to only %d bytes (need ≥32) — production refuses to start", len(decoded))
					os.Exit(1)
				}
				logger.Warnf("startup: STACKWEAVER_DECOY_SECRET decodes to only %d bytes (need ≥32) — falling back to per-process random secret", len(decoded))
			default:
				decoySecret = decoded
				logger.Info("auth proxy: STACKWEAVER_DECOY_SECRET configured — decoy ids will be stable across replicas")
			}
		}

		authProxy = handlers.NewAuthProxy(handlers.AuthProxyConfig{
			ZitadelInternalURL:        zitadelInternalURL,
			ZitadelIssuer:             zitadelIssuer,
			PAT:                       loginServicePAT,
			ClientID:                  zitadelClientID,
			NotificationMode:          notificationMode,
			DefaultRedirectURI:        os.Getenv("STACKWEAVER_DEFAULT_REDIRECT_URI"),
			AutoSubmitCode:            os.Getenv("STACKWEAVER_AUTO_SUBMIT_CODE") == "true",
			CustomRequestHeaders:      os.Getenv("CUSTOM_REQUEST_HEADERS"),
			IsProduction:              isProduction,
			PublicFrontendURL:         os.Getenv("STACKWEAVER_APP_URL"),
			PublicAPIBaseURL:          os.Getenv("STACKWEAVER_PUBLIC_URL"),
			TrustedForwardHosts:       trustedForwardHosts,
			PostLogoutAllowedHosts:    postLogoutHosts,
			DecoySecret:               decoySecret,
			LoginNameLockoutThreshold: lockoutThreshold,
			LoginNameLockoutWindow:    lockoutWindow,
		})
		logger.Info("Auth Proxy initialized for custom login UI")
	} else {
		logger.Warn("Auth Proxy not initialized — ZITADEL_LOGIN_SERVICE_USER_TOKEN not set")
	}

	// Setup routes
	router := routes.SetupRoutes(db, authService, totpService, profileService, sessionsService, apiKeyService, githubAppManager, authProxy)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  config.Server.ReadTimeout,
		WriteTimeout: config.Server.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.Infof("Server starting on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Stop scheduler service if running
	if schedulerService != nil {
		schedulerService.Stop()
		logger.Info("Ansible Scheduler Service stopped")
	}

	// Stop drift detection service if running
	if driftDetectionService != nil {
		driftDetectionService.Stop()
		logger.Info("Terraform Drift Detection Service stopped")
	}

	// Stop runner monitor service if running
	if runnerMonitorService != nil {
		runnerMonitorService.Stop()
		logger.Info("Runner Monitor Service stopped")
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	if err := srv.Shutdown(ctx); err != nil {
		cancel()
		logger.Fatalf("Server forced to shutdown: %v", err)
	}
	cancel()

	logger.Info("Server exited")
}

// defaultConfig returns a Config with sensible defaults matching the values
// in config/config.yaml. This ensures the binary works without a config file
// when all required values are supplied via environment variables.
func defaultConfig() Config {
	var cfg Config
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 8022
	cfg.Server.ReadTimeout = 30 * time.Second
	cfg.Server.WriteTimeout = 30 * time.Second
	cfg.Database.Port = 5432
	cfg.Database.SSLMode = "disable"
	cfg.Database.MaxOpenConns = 25
	cfg.Database.MaxIdleConns = 5
	cfg.Database.ConnMaxLifetime = 5 * time.Minute
	return cfg
}

// applyEnvOverrides overrides config.yaml values with environment variables when set.
// This allows Kubernetes pods to inject configuration via env vars without modifying config.yaml.
func applyEnvOverrides(config *Config) {
	// Server
	if v := os.Getenv("SERVER_HOST"); v != "" {
		config.Server.Host = v
	}
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			config.Server.Port = p
		}
	}
	if v := os.Getenv("SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.ReadTimeout = d
		}
	}
	if v := os.Getenv("SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.WriteTimeout = d
		}
	}

	// Database
	if v := os.Getenv("DATABASE_HOST"); v != "" {
		config.Database.Host = v
	}
	if v := os.Getenv("DATABASE_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			config.Database.Port = p
		}
	}
	if v := os.Getenv("DATABASE_USER"); v != "" {
		config.Database.User = v
	}
	if v := os.Getenv("DATABASE_PASSWORD"); v != "" {
		config.Database.Password = v
	}
	if v := os.Getenv("DATABASE_NAME"); v != "" {
		config.Database.DBName = v
	}
	if v := os.Getenv("DATABASE_SSLMODE"); v != "" {
		config.Database.SSLMode = v
	}
	if v := os.Getenv("DATABASE_MAX_OPEN_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			config.Database.MaxOpenConns = n
		}
	}
	if v := os.Getenv("DATABASE_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			config.Database.MaxIdleConns = n
		}
	}
	if v := os.Getenv("DATABASE_CONN_MAX_LIFETIME"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Database.ConnMaxLifetime = d
		}
	}

	// Zitadel (also overridden later in main via os.Getenv, kept here for completeness)
	if v := os.Getenv("ZITADEL_ISSUER"); v != "" {
		config.Zitadel.Issuer = v
	}
	if v := os.Getenv("ZITADEL_API_CLIENT_ID"); v != "" {
		config.Zitadel.ClientID = v
	}
	if v := os.Getenv("ZITADEL_API_CLIENT_SECRET"); v != "" {
		config.Zitadel.ClientSecret = v
	}
}

// sync smoke test 1779753492
