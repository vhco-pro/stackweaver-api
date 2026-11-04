// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package apikey

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// TestOwnerlessKeys covers the keys the platform mints for itself (#933, D1, AC69): a row with no
// owning user can be stored and verified, and appears in no user's API-keys listing.
func TestOwnerlessKeys(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.AutoMigrate(&models.APIKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := repository.NewAPIKeyRepository(db)
	svc := NewService(repo, nil, nil, nil)

	raw, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	key := &models.APIKey{Name: "ownerless-" + uuid.NewString()[:8], Kind: models.APIKeyKindOrg, KeyHash: hash, KeyPrefix: GetKeyPrefix(raw)}
	if err := repo.Create(key); err != nil {
		t.Fatalf("creating an ownerless key: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })

	got, err := svc.VerifyAPIKey(raw)
	if err != nil || got.ID != key.ID {
		t.Fatalf("VerifyAPIKey = %v, %v", got, err)
	}
	if got.UserID != nil {
		t.Fatalf("UserID = %v, want nil", got.UserID)
	}

	// No user's listing carries it: the listings are by owner, and it has none.
	for _, list := range []func(uuid.UUID) ([]*models.APIKey, error){svc.ListAPIKeys, svc.ListUserTokens} {
		keys, err := list(uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if k.ID == key.ID {
				t.Fatal("an ownerless key appeared in a user's listing")
			}
		}
	}
}
