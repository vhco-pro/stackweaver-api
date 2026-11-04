// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Encryption at rest of the objects the API writes on a job's behalf (#933, D2, AC73): saved plans,
// configuration tarballs, playbook snapshots and state are not readable as plaintext in the bucket,
// they are all sealed by crypto.CryptoService.EncryptAtRest, and nothing outside core/crypto calls
// the cipher itself.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Run with:
//
//	go test -tags integration ./internal/api/v2/handlers/ -run TestAtRest

//go:build integration

package handlers

import (
	"bytes"
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/services/apikey"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/storage"
)

func TestAtRest_EveryJobArtifactIsSealed(t *testing.T) {
	f := setupAgentPrepFixture(t)
	cs, err := crypto.NewCryptoService([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	raw := newSnapshotStore()
	sealed := storage.NewSealed(raw, cs, storage.ArtifactSealRules()...)
	secret := []byte("hunter2-at-rest")

	// A configuration tarball written the way the upload handlers write it, through the sealed client.
	run := f.seedRun(t, f.runnerA1)
	tarball := append([]byte("\x1f\x8b\x08 "), secret...)
	cvRun := f.seedRunWithConfig(t, &snapshotStore{Memory: raw.Memory}, []byte("placeholder"))
	cvKey := "configuration-versions/" + *cvRun.ConfigurationVersionID + "/config.tar.gz"
	if err := sealed.Put(t.Context(), cvKey, tarball); err != nil {
		t.Fatal(err)
	}

	stateSvc := state.NewService(repository.NewStateVersionRepository(f.db), repository.NewStateLockRepository(f.db), repository.NewWorkspaceRepository(f.db), sealed, nil, cs)
	h := &RunnerAgentHandler{
		db: f.db, runnerRepo: repository.NewRunnerRepository(f.db), apiKeyService: apikey.NewService(repository.NewAPIKeyRepository(f.db), nil, nil, nil),
		ansibleJobRepo: repository.NewAnsibleJobRepository(f.db), storageClient: sealed, cryptoService: cs, stateService: stateSvc,
	}

	// State and a saved plan, written by their own writers.
	stateFile := []byte(`{"version":4,"serial":1,"lineage":"at-rest","outputs":{"s":{"value":"` + string(secret) + `"}},"resources":[]}`)
	if err := stateSvc.PutStateObject(t.Context(), run.WorkspaceID, 1, stateFile); err != nil {
		t.Fatal(err)
	}
	sealedPlan, err := h.atRest().EncryptAtRest(append([]byte("PK"), secret...))
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Put(t.Context(), planFileKey(run.ID), sealedPlan); err != nil {
		t.Fatal(err)
	}
	// A playbook snapshot.
	if err := sealed.Put(t.Context(), "playbooks/"+f.projectA.String()+"/snapshot.tar.gz", append([]byte("\x1f\x8b"), secret...)); err != nil {
		t.Fatal(err)
	}

	objects, err := raw.List(t.Context(), "")
	if err != nil || len(objects) < 4 {
		t.Fatalf("listing the bucket: %d objects, %v", len(objects), err)
	}
	for _, o := range objects {
		data, _ := raw.Get(t.Context(), o.Key)
		if bytes.Contains(data, secret) {
			t.Errorf("%s is readable as plaintext in the bucket", o.Key)
		}
	}

	// The job still receives the plaintext tarball.
	if err := f.db.Model(&models.Run{}).Where("id = ?", cvRun.ID).Update("status", models.RunStatusPlanning).Error; err != nil {
		t.Fatal(err)
	}
	router := f.router(func(authed *gin.RouterGroup) { authed.GET("/jobs/:id/artifacts", h.GetJobArtifacts) })
	arts, _ := artifactsAs(t, router, "a1", cvRun.ID, runnercontract.CapabilityPlaybookSnapshot)
	got, err := base64.StdEncoding.DecodeString(arts.ConfigTarball)
	if err != nil || !bytes.Equal(got, tarball) {
		t.Fatalf("the job received %q, want the plaintext tarball", got)
	}
}

// TestAtRest_NoSecondEncryptingWriter is the static half: no object-storage writer holds a cipher
// of its own and nothing outside core/crypto calls the at-rest cipher directly, so every object is
// sealed by the one helper.
func TestAtRest_NoSecondEncryptingWriter(t *testing.T) {
	roots := []string{"../../../..", "../../../../../core"}
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasSuffix(path, "core/crypto")) {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
			if perr != nil {
				return nil
			}
			// An object-storage writer (a file using core/storage) never holds a cipher of its own.
			// Field encryption in the database, such as the Ansible credential service, writes no
			// object and is not this rule's concern.
			usesStorage := false
			for _, imp := range file.Imports {
				if imp.Path.Value == `"github.com/michielvha/stackweaver/core/storage"` {
					usesStorage = true
				}
			}
			for _, imp := range file.Imports {
				if usesStorage && (imp.Path.Value == `"crypto/aes"` || imp.Path.Value == `"crypto/cipher"`) {
					t.Errorf("%s writes object storage and imports %s: seal through crypto.CryptoService.EncryptAtRest", path, imp.Path.Value)
				}
			}
			full, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(full, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "EncryptBytes" || sel.Sel.Name == "DecryptBytes") {
					t.Errorf("%s calls %s: seal through EncryptAtRest", fset.Position(sel.Pos()), sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
