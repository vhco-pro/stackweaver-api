// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package apikey

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

// A revoked job token stops verifying but is still recognised as a revoked job token, so the API
// can answer its executor with job-token-revoked and the executor stops within one status poll
// instead of retrying a 401 until its timeout (#933, D2, AC67, AC72). An unknown token and an
// expired key of another kind are not.
func TestRevokedJobToken_RecognisedAfterRevocation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dsn, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	repo := repository.NewAPIKeyRepository(db)
	svc := NewService(repo, nil, nil, nil)
	jobID := "run-" + uuid.NewString()[:12]
	p := JobPrincipal{Kind: models.JobTypeTofuRun, JobID: jobID, RunnerID: uuid.New(), Attempt: 1}
	key, raw, err := svc.CreateJobToken(uuid.New(), p, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", key.ID).Delete(&models.APIKey{}) })

	if _, err := svc.VerifyAPIKey(raw); err != nil {
		t.Fatalf("a fresh job token does not verify: %v", err)
	}
	if svc.IsRevokedJobToken(raw) {
		t.Fatal("a live job token reads as revoked")
	}
	if err := svc.RevokeJobTokens(models.JobTypeTofuRun, jobID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := svc.VerifyAPIKey(raw); err == nil {
		t.Fatal("a revoked job token still verifies")
	}
	if !svc.IsRevokedJobToken(raw) {
		t.Error("a revoked job token is not recognised as one")
	}

	unknown, _ := GenerateAPIKey()
	if svc.IsRevokedJobToken(unknown) {
		t.Error("an unknown token reads as a revoked job token")
	}
	expiredRaw, _ := GenerateAPIKey()
	hash, _ := HashKey(expiredRaw)
	past := time.Now().Add(-time.Minute)
	other := &models.APIKey{Name: "expired-" + uuid.NewString()[:8], Kind: models.APIKeyKindOrg, KeyHash: hash, KeyPrefix: GetKeyPrefix(expiredRaw), ExpiresAt: &past}
	if err := repo.Create(other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Where("id = ?", other.ID).Delete(&models.APIKey{}) })
	if svc.IsRevokedJobToken(expiredRaw) {
		t.Error("an expired organization key reads as a revoked job token")
	}
}
