// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// An inventory source is created by one INSERT that carries every attribute the caller sent, the
// three flags that default to on included: `enabled`, `update-on-launch` and `group-by-region`
// are stored as sent, and are on when the attribute is absent.
//
// The defect this test was written against (#879): the three columns carried `gorm:"default:true"`,
// and GORM substitutes a literal default for a zero value in the INSERT, so a false sent on create
// could not be inserted. The handler papered over it by creating the row and then writing the
// caller's values again with a second statement. The values came out right; the row was written
// twice, and a failure of the second write left a source with flags the caller had turned off
// switched on. The defaults live in InventorySourceService.CreateInventorySourceWithOptions now,
// and the statement count below is what fails when the second write comes back.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is strictly
// row-scoped (the database may be live). Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ansible/ -run TestInventorySourceCreate

//go:build integration

package ansible

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/repository"
	ansiblesvc "github.com/michielvha/stackweaver/core/services/ansible"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// sourceWrites is a GORM logger that keeps the statements written to ansible_inventory_sources,
// so the test can say how many writes one create made rather than only what the row holds after.
type sourceWrites struct {
	mu      sync.Mutex
	inserts int
	updates int
}

func (w *sourceWrites) LogMode(logger.LogLevel) logger.Interface { return w }
func (w *sourceWrites) Info(context.Context, string, ...any)     {}
func (w *sourceWrites) Warn(context.Context, string, ...any)     {}
func (w *sourceWrites) Error(context.Context, string, ...any)    {}

func (w *sourceWrites) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case strings.HasPrefix(sql, `INSERT INTO "ansible_inventory_sources"`):
		w.inserts++
	case strings.HasPrefix(sql, `UPDATE "ansible_inventory_sources"`):
		w.updates++
	}
}

// take returns the counts since the last call and resets them.
func (w *sourceWrites) take() (inserts, updates int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	inserts, updates = w.inserts, w.updates
	w.inserts, w.updates = 0, 0
	return inserts, updates
}

func TestInventorySourceCreate_FlagsAreStoredAsSentInOneWrite(t *testing.T) {
	// Org A with an owner and an inventory. The fixture's cleanup deletes every source of that
	// inventory, which covers the ones created below.
	f := setupAnsibleSubResourceAuthz(t)
	db := f.db

	writes := &sourceWrites{}
	recorded := db.Session(&gorm.Session{Logger: writes})

	orgRepo := repository.NewOrganizationRepository(db)
	inventoryService := ansiblesvc.NewInventoryService(f.inventoryRepo, orgRepo)
	sourceService := ansiblesvc.NewInventorySourceService(
		repository.NewAnsibleInventorySourceRepository(recorded),
		f.inventoryRepo,
		repository.NewAnsibleCredentialRepository(db),
		nil,
	)
	h := NewInventorySourceHandler(
		sourceService,
		inventoryService,
		auth.NewService(repository.NewUserRepository(db)),
		rbac.NewServiceWithTeams(orgRepo, repository.NewTeamRepository(db), repository.NewProjectRepository(db)),
		nil,
	)
	router := storedAsSentRouter()
	router.POST("/api/v2/ansible/inventories/:id/sources", h.Create)
	router.GET("/api/v2/ansible/inventory-sources/:source_id", h.Get)

	const (
		enabled        = "enabled"
		updateOnLaunch = "update-on-launch"
		groupByRegion  = "group-by-region"
	)
	flags := []string{enabled, updateOnLaunch, groupByRegion}

	create := func(t *testing.T, attrs map[string]any) (created, read map[string]any) {
		t.Helper()
		attrs["name"] = "srcflags-" + uuid.NewString()[:8]
		attrs["source-type"] = "custom"
		raw, err := json.Marshal(map[string]any{"data": map[string]any{"type": "inventory-sources", "attributes": attrs}})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		writes.take()
		code, body := storedAsSentCall(t, router, http.MethodPost,
			"/api/v2/ansible/inventories/"+f.inventoryID+"/sources", f.owner.ID, string(raw))
		if code != http.StatusCreated {
			t.Fatalf("create = %d, want 201 (%s)", code, body)
		}
		if inserts, updates := writes.take(); inserts != 1 || updates != 0 {
			t.Errorf("the create wrote ansible_inventory_sources with %d INSERT and %d UPDATE, want 1 and 0", inserts, updates)
		}
		var createdDoc struct {
			Data storedAsSentResource `json:"data"`
		}
		if err := json.Unmarshal(body, &createdDoc); err != nil {
			t.Fatalf("decode create response: %v\n%s", err, body)
		}

		code, body = storedAsSentCall(t, router, http.MethodGet,
			"/api/v2/ansible/inventory-sources/"+createdDoc.Data.ID, f.owner.ID, "")
		if code != http.StatusOK {
			t.Fatalf("read = %d, want 200 (%s)", code, body)
		}
		var readDoc struct {
			Data storedAsSentResource `json:"data"`
		}
		if err := json.Unmarshal(body, &readDoc); err != nil {
			t.Fatalf("decode read response: %v\n%s", err, body)
		}
		return createdDoc.Data.Attributes, readDoc.Data.Attributes
	}

	cases := []struct {
		name string
		sent map[string]bool // a flag left out is absent from the request
		want map[string]bool
	}{
		{"all absent", nil, map[string]bool{enabled: true, updateOnLaunch: true, groupByRegion: true}},
		{
			"all on",
			map[string]bool{enabled: true, updateOnLaunch: true, groupByRegion: true},
			map[string]bool{enabled: true, updateOnLaunch: true, groupByRegion: true},
		},
		{
			"enabled off",
			map[string]bool{enabled: false},
			map[string]bool{enabled: false, updateOnLaunch: true, groupByRegion: true},
		},
		{
			"update-on-launch off",
			map[string]bool{updateOnLaunch: false},
			map[string]bool{enabled: true, updateOnLaunch: false, groupByRegion: true},
		},
		{
			"group-by-region off",
			map[string]bool{groupByRegion: false},
			map[string]bool{enabled: true, updateOnLaunch: true, groupByRegion: false},
		},
		{
			"all off",
			map[string]bool{enabled: false, updateOnLaunch: false, groupByRegion: false},
			map[string]bool{enabled: false, updateOnLaunch: false, groupByRegion: false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]any{}
			for flag, value := range tc.sent {
				attrs[flag] = value
			}
			created, read := create(t, attrs)
			for _, flag := range flags {
				assertStoredBool(t, "create response", created, flag, tc.want[flag])
				assertStoredBool(t, "read back", read, flag, tc.want[flag])
			}
		})
	}

	// The other sync attributes used to reach the row through the second write as well. They ride
	// in the same INSERT now, with the verbosity clamp the update path applies.
	t.Run("the remaining sync attributes are stored by the same write", func(t *testing.T) {
		created, read := create(t, map[string]any{
			"update-cache-timeout":       300,
			"overwrite":                  true,
			"overwrite-vars":             true,
			"verbosity":                  9,
			"group-by-instance-id":       true,
			"group-by-availability-zone": true,
			"group-by-tag":               "Environment",
			"hostname-var":               "private_ip",
			"instance-filters":           `[{"name":"tag:Role","values":["web"]}]`,
			"sync-schedule":              "0 */6 * * *",
		})
		for where, attrs := range map[string]map[string]any{"create response": created, "read back": read} {
			for attr, want := range map[string]any{
				"update-cache-timeout":       float64(300),
				"overwrite":                  true,
				"overwrite-vars":             true,
				"verbosity":                  float64(4),
				"group-by-instance-id":       true,
				"group-by-availability-zone": true,
				"group-by-tag":               "Environment",
				"hostname-var":               "private_ip",
				"instance-filters":           `[{"name":"tag:Role","values":["web"]}]`,
				"sync-schedule":              "0 */6 * * *",
			} {
				if got := attrs[attr]; got != want {
					t.Errorf("%s: %s = %v, want %v", where, attr, got, want)
				}
			}
		}
	})

	// An attribute the caller leaves out keeps the model's own default, as it did before.
	t.Run("an absent hostname-var is public_ip", func(t *testing.T) {
		created, read := create(t, map[string]any{})
		for where, attrs := range map[string]map[string]any{"create response": created, "read back": read} {
			if got := attrs["hostname-var"]; got != "public_ip" {
				t.Errorf("%s: hostname-var = %v, want public_ip", where, got)
			}
		}
	})
}
