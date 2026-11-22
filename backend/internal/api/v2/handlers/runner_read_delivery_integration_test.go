// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

//go:build integration

package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/stackweaver/backend/internal/api/middleware"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/services/variable"
)

// runnerReadDeliveryRouter uses the production v2 and runner authentication chain. The store
// and claim fixtures remain injectable; deadline support comes from the actual network server.
func runnerReadDeliveryRouter(f *claimRouteFixture, selected bool, beforeRead ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	v2 := r.Group("/api/v2")
	if selected {
		v2.Use(middleware.RunnerReadResponse())
	}
	authService := auth.NewService(repository.NewUserRepository(f.db))
	authService.SetAPIKeyService(f.keys)
	v2.Use(middleware.AuthMiddleware(authService), middleware.OrgResolutionWall(middleware.NewDBOrgResolver(f.db)))
	permissions := rbac.NewServiceWithTeams(repository.NewOrganizationRepository(f.db), repository.NewTeamRepository(f.db), repository.NewProjectRepository(f.db))
	runner := v2.Group("/runner", middleware.RunnerAuth(repository.NewRunnerRepository(f.db), &middleware.LauncherTrust{Permissions: permissions}), middleware.RunnerPrincipalRateLimit(middleware.RunnerRateBudgetsFromEnv()))
	runner.Use(beforeRead...)
	runner.GET("/jobs/:id/blob/*name", middleware.JobData(), f.handler.GetJobBlob)
	runner.GET("/jobs/:id/artifacts", middleware.JobData(), f.handler.GetJobArtifacts)
	runner.GET("/jobs/:id/plan", middleware.JobData(), f.handler.DownloadPlan)
	runner.GET("/jobs/:id/playbook-snapshot", middleware.JobData(), f.handler.GetPlaybookSnapshot)
	runner.GET("/jobs/:id/status", f.handler.GetJobStatus)
	runner.GET("/cache/:kind/:sha256", middleware.RequireRunnerToken(), f.handler.GetCacheEntry)
	return r
}

func runnerReadDeliveryServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ReadTimeout = 30 * time.Second
	server.Config.WriteTimeout = 30 * time.Second
	server.Config.ConnState = func(connection net.Conn, status http.ConnState) {
		if status == http.StateNew {
			tcp, ok := connection.(*net.TCPConn)
			if !ok {
				t.Errorf("delivery fixture did not receive TCP: %v", errors.Join(errors.New("unsupported connection"), connection.Close()))
				return
			}
			if err := tcp.SetWriteBuffer(4096); err != nil {
				t.Errorf("configuring delivery TCP buffers: %v", errors.Join(err, connection.Close()))
			}
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	return server
}

type runnerDeliveryFixture struct {
	claim   *claimRouteFixture
	id      string
	token   runnercontract.JobToken
	store   *requiredInputStore
	payload []byte
	kind    string
	path    string
}

func newRunnerDeliveryFixture(t *testing.T, kind string, payload []byte) *runnerDeliveryFixture {
	t.Helper()
	fixture := &runnerDeliveryFixture{kind: kind, payload: payload}
	if kind == "plan" {
		fixture.claim = setupClaimRouteFixture(t)
		fixture.id, _, fixture.token = fixture.claim.startCompletion(t, startRouteCases[4])
		fixture.store = &requiredInputStore{Client: newSnapshotStore()}
		fixture.claim.handler.storageClient = fixture.store
		sealed, err := fixture.claim.handler.atRest().EncryptAtRest(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.Put(t.Context(), planFileKey(fixture.id), sealed); err != nil {
			t.Fatal(err)
		}
		fixture.path = "/api/v2/runner/jobs/" + fixture.id + "/plan"
	} else {
		fixture.claim, fixture.id, fixture.token, _, fixture.store = setupBlobRecoveryClaim(t, false)
		var run models.Run
		if err := fixture.claim.db.First(&run, "id = ?", fixture.id).Error; err != nil {
			t.Fatal(err)
		}
		var configuration models.ConfigurationVersion
		if err := fixture.claim.db.First(&configuration, "id = ?", run.ConfigurationVersionID).Error; err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.Put(t.Context(), configuration.TarballKey(), payload); err != nil {
			t.Fatal(err)
		}
		fixture.path = "/api/v2/runner/jobs/" + fixture.id + "/blob/config.tar.gz"
		if kind == "artifacts" {
			fixture.path = "/api/v2/runner/jobs/" + fixture.id + "/artifacts"
			fixture.claim.handler.inlineArtifactLimit = len(payload) + 1
			fixture.claim.handler.variableService = variable.NewServiceWithVariableSetsAndWorkspace(repository.NewVariableRepository(fixture.claim.db), nil, nil, []byte("0123456789abcdef0123456789abcdef"))
			fixture.claim.handler.stateService = state.NewService(repository.NewStateVersionRepository(fixture.claim.db), repository.NewStateLockRepository(fixture.claim.db), repository.NewWorkspaceRepository(fixture.claim.db), fixture.store, nil, fixture.claim.handler.cryptoService)
		}
	}
	return fixture
}

func (f *runnerDeliveryFixture) fetch(ctx context.Context, serverURL string) error {
	client := executor.NewClient(serverURL, f.token.Token, f.claim.runnerA1.ID.String())
	var got []byte
	var err error
	switch f.kind {
	case "blob":
		got, err = client.Blob(ctx, runnercontract.BlobRef{Path: f.path, SHA256: sha256Hex(f.payload), SizeBytes: int64(len(f.payload))})
	case "plan":
		got, err = client.Get(ctx, f.path)
	case "artifacts":
		var artifacts runnercontract.TofuArtifacts
		err = client.Artifacts(ctx, f.id, &artifacts, nil)
		if err == nil {
			got, err = base64.StdEncoding.DecodeString(artifacts.ConfigTarball)
		}
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(got, f.payload) {
		return fmt.Errorf("delivered %d bytes (%s), want %d (%s)", len(got), sha256Hex(got), len(f.payload), sha256Hex(f.payload))
	}
	return nil
}

func TestRunnerReadDelivery_NormalClientsAllContent(t *testing.T) {
	for _, kind := range []string{"blob", "plan", "artifacts"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newRunnerDeliveryFixture(t, kind, []byte("verified protected runner content"))
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			if err := fixture.fetch(t.Context(), server.URL); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// pacedRunnerRelay is an owned network fixture. Both its upstream and downstream are actual TCP
// connections. Small TCP buffers keep the production server writing throughout the paced transfer;
// a single large server Write cannot hide the entire body in a socket buffer before its deadline.
func pacedRunnerRelay(t *testing.T, upstream string) *httptest.Server {
	relay, _ := runnerDeliveryRelay(t, upstream, 5*time.Second, false)
	return relay
}

func runnerDeliveryRelay(t *testing.T, upstream string, interval time.Duration, stallFirst bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	trips := new(atomic.Int32)
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			tcp, ok := connection.(*net.TCPConn)
			if !ok {
				return nil, errors.Join(errors.New("delivery relay did not dial TCP"), connection.Close())
			}
			if err := tcp.SetReadBuffer(64 << 10); err != nil {
				return nil, errors.Join(err, connection.Close())
			}
			return connection, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		trip := trips.Add(1)
		forward, err := http.NewRequestWithContext(request.Context(), request.Method, upstream+request.URL.RequestURI(), nil) //nolint:gosec // G704: upstream is this test's owned HTTP server.
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		forward.Header = request.Header.Clone()
		response, err := client.Do(forward) //nolint:gosec // G704: forward targets this test's owned HTTP server.
		if err != nil {
			if request.Context().Err() == nil {
				t.Errorf("forwarding the delivery fixture: %v", err)
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		for name, values := range response.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(response.StatusCode)
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			return
		}
		if stallFirst && trip == 1 && response.StatusCode == http.StatusOK {
			if _, err := io.CopyN(w, response.Body, 64<<10); err != nil {
				t.Errorf("stalled-body fixture lacks its initial payload: %v", err)
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
			<-request.Context().Done()
			return
		}
		// The receive window holds several chunks, well below the multi-megabyte body.
		// This avoids zero-window probe delays obscuring the deliberate transfer rate;
		// an unchunked full-body Write must still block beyond its thirty-second bound.
		started := time.Now()
		var transferred int64
		nextLog := int64(512 << 10)
		defer func() {
			if interval > 0 {
				t.Logf("delivery relay trip=%d bytes=%d elapsed=%s", trip, transferred, time.Since(started))
			}
		}()
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := io.ReadFull(response.Body, buffer)
			if n > 0 {
				if _, err := w.Write(buffer[:n]); err != nil {
					return
				}
				if err := controller.Flush(); err != nil {
					return
				}
				transferred += int64(n)
				if interval > 0 && transferred >= nextLog {
					t.Logf("delivery relay trip=%d bytes=%d elapsed=%s", trip, transferred, time.Since(started))
					nextLog += 512 << 10
				}
			}
			if readErr != nil {
				return
			}
			// This is a deliberate transfer rate, below the idle interval, rather than a
			// readiness wait. The successful body must exceed its acquisition window.
			if interval > 0 {
				timer := time.NewTimer(interval)
				select {
				case <-request.Context().Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				timer.Stop()
			}
		}
	}))
	t.Cleanup(relay.Close)
	return relay, trips
}

func TestRunnerReadDelivery_ProductionTimeoutLongBody(t *testing.T) {
	for _, kind := range []string{"blob", "plan", "artifacts"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			fixture := newRunnerDeliveryFixture(t, kind, bytes.Repeat([]byte("x"), 2<<20))
			server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(fixture.claim, true))
			relay := pacedRunnerRelay(t, server.URL)
			ctx, cancel := context.WithTimeout(t.Context(), 9*time.Minute)
			defer cancel()
			started := time.Now()
			if err := fixture.fetch(ctx, relay.URL); err != nil {
				t.Fatalf("long %s body failed through production timeouts: %v", kind, err)
			}
			if elapsed := time.Since(started); elapsed <= 5*time.Minute {
				t.Errorf("long-body proof ended after %s without crossing acquisition", elapsed)
			}
		})
	}
}

func TestRunnerReadDelivery_ProductionTimeoutSlowHeaders(t *testing.T) {
	f, id, token, data, store := setupBlobRecoveryClaim(t, false)
	store.read = func(ctx context.Context, key string) ([]byte, error) {
		// Deliberately exceed the real server timeout: this is the storage latency under test,
		// rather than a wait for fixture readiness.
		timer := time.NewTimer(31 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			return store.Client.Get(ctx, key)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	server := runnerReadDeliveryServer(t, runnerReadDeliveryRouter(f, true))
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v2/runner/jobs/"+id+"/blob/config.tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	request.Header.Set("If-Match", "\""+sha256Hex(data)+"\"")
	client := &http.Client{Timeout: 45 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("authorized content with healthy slow storage failed through production timeouts: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	got, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("slow required read: status=%d bytes=%d error=%v", response.StatusCode, len(got), err)
	}
}
