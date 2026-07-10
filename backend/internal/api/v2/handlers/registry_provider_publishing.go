// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/rbac"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage"
)

// AUD-107: os/arch (from PostForm) and the upload filename (from the multipart
// header) are concatenated into object-storage keys, so they must be constrained to
// safe single path segments or an attacker can escape the providers/<org>/… prefix
// (e.g. arch=../../other-org) and overwrite or plant objects in another namespace.
var (
	platformSegmentRE  = regexp.MustCompile(`^[a-z0-9_]+$`)      // os / arch
	providerFilenameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`) // upload filename
)

// safeStorageFilename returns the filename reduced to a safe single path segment
// (no directory separators, no `..` traversal), or ok=false if it is unsafe. AUD-107.
func safeStorageFilename(name string) (string, bool) {
	base := filepath.Base(name)
	if base != name || base == "." || base == ".." || strings.Contains(base, "..") || !providerFilenameRE.MatchString(base) {
		return "", false
	}
	return base, true
}

// RegistryProviderPublishingHandler publishes provider versions and platforms into an org's
// private registry. Provider *shell* CRUD lives in RegistryProviderResourceHandler; this handler
// only uploads binaries and their publisher-provided SHA256SUMS + detached signature.
//
// Signing model (matches HashiCorp's): the PUBLISHER signs the SHA256SUMS file offline with the
// private half of a GPG key whose public half was uploaded via tfe_registry_gpg_key, then uploads
// the binary, SHA256SUMS and SHA256SUMS.sig. The server never holds a private key — it stores and
// serves these artifacts and advertises the public key to Terraform at install time.
type RegistryProviderPublishingHandler struct {
	providerRepo         *repository.ProviderRepository
	providerVersionRepo  *repository.ProviderVersionRepository
	providerPlatformRepo *repository.ProviderPlatformRepository
	orgRepo              *repository.OrganizationRepository
	gpgKeyRepo           *repository.GPGKeyRepository
	authService          *auth.Service
	rbacService          *rbac.Service
	storage              storage.Client
}

func NewRegistryProviderPublishingHandler(
	providerRepo *repository.ProviderRepository,
	providerVersionRepo *repository.ProviderVersionRepository,
	providerPlatformRepo *repository.ProviderPlatformRepository,
	orgRepo *repository.OrganizationRepository,
	gpgKeyRepo *repository.GPGKeyRepository,
	authService *auth.Service,
	rbacService *rbac.Service,
	storageClient storage.Client,
) *RegistryProviderPublishingHandler {
	return &RegistryProviderPublishingHandler{
		providerRepo:         providerRepo,
		providerVersionRepo:  providerVersionRepo,
		providerPlatformRepo: providerPlatformRepo,
		orgRepo:              orgRepo,
		gpgKeyRepo:           gpgKeyRepo,
		authService:          authService,
		rbacService:          rbacService,
		storage:              storageClient,
	}
}

// storagePrefix is the object-storage prefix for a provider version's artifacts.
func storagePrefix(org, provider, version string) string {
	return fmt.Sprintf("providers/%s/%s/%s", org, provider, version)
}

// PublishProviderPlatform handles
// POST /api/v2/organizations/:name/registry-providers/:registry_name/:namespace/:provider_name/versions/:version/platforms
//
// Multipart form fields:
//   - file        (required) the provider zip
//   - os, arch    (required) the target platform
//   - shasums     (required) the SHA256SUMS file listing the zip's checksum
//   - shasums_sig (required) the detached GPG signature of SHA256SUMS
//   - key_id      (required) the uploaded GPG key id that signed SHA256SUMS
//   - protocols   (optional) comma-separated plugin protocols, default "5.0"
func (h *RegistryProviderPublishingHandler) PublishProviderPlatform(c *gin.Context) {
	user, err := h.authService.GetUserFromContext(c)
	if err != nil {
		regProvErr(c, http.StatusUnauthorized, "Unauthorized", "Authentication required")
		return
	}

	org, err := h.orgRepo.GetByName(c.Param("name"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Organization not found")
		return
	}

	// AUD-103: publishing a binary into the org's registry requires manage-providers.
	// Previously this only checked authentication, so any authenticated user could
	// publish arbitrary binaries under any org's trusted namespace.
	if allowed, err := h.rbacService.CheckOrgManageProviders(c.Request.Context(), user.ID, org.ID); err != nil || !allowed {
		regProvErr(c, http.StatusForbidden, "Forbidden", "You do not have permission to publish to this organization's registry")
		return
	}

	provider, err := h.providerRepo.GetByComposite(org.ID, c.Param("registry_name"), c.Param("namespace"), c.Param("provider_name"))
	if err != nil {
		regProvErr(c, http.StatusNotFound, "Not Found", "Registry provider not found")
		return
	}

	version := registry.NormalizeVersion(c.Param("version"))
	if err := registry.ValidateSemanticVersion(version); err != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}

	os := c.PostForm("os")
	arch := c.PostForm("arch")
	if os == "" || arch == "" {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "os and arch are required")
		return
	}
	// AUD-107: os/arch become path segments in the storage key — reject anything
	// but a lowercase alphanumeric/underscore token so they cannot escape the prefix.
	if !platformSegmentRE.MatchString(os) || !platformSegmentRE.MatchString(arch) {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "os and arch must match [a-z0-9_]+")
		return
	}

	keyID := c.PostForm("key_id")
	if keyID == "" {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "key_id is required (the GPG key that signed SHA256SUMS)")
		return
	}
	if _, err := h.gpgKeyRepo.GetByKeyID(org.ID, keyID); err != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", fmt.Sprintf("GPG key %s not found in this organization", keyID))
		return
	}

	protocols := c.PostForm("protocols")
	if protocols == "" {
		protocols = "5.0"
	}

	prefix := storagePrefix(org.Name, provider.Name, version)

	// --- binary --------------------------------------------------------------
	file, err := c.FormFile("file")
	if err != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "file is required")
		return
	}
	// AUD-107: the multipart filename becomes the final path segment of the storage
	// key — reduce it to a safe base name so it cannot inject separators or traversal.
	filename, ok := safeStorageFilename(file.Filename)
	if !ok {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid provider filename")
		return
	}
	shasum, err := h.storeUpload(c, file, fmt.Sprintf("%s/%s_%s/%s", prefix, os, arch, filename), true)
	if err != nil {
		return // storeUpload already wrote the error
	}

	// --- SHA256SUMS + detached signature (publisher-provided) ----------------
	shasumsFile, err := c.FormFile("shasums")
	if err != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "shasums (the SHA256SUMS file) is required")
		return
	}
	shasumsPath := prefix + "/SHA256SUMS"
	if _, err := h.storeUpload(c, shasumsFile, shasumsPath, false); err != nil {
		return
	}

	sigFile, err := c.FormFile("shasums_sig")
	if err != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", "shasums_sig (the detached SHA256SUMS signature) is required")
		return
	}
	shasumsSigPath := prefix + "/SHA256SUMS.sig"
	if _, err := h.storeUpload(c, sigFile, shasumsSigPath, false); err != nil {
		return
	}

	// --- version (get-or-create) + signing metadata --------------------------
	providerVersion, err := h.providerVersionRepo.GetByProviderAndVersion(provider.ID, version)
	if err != nil {
		providerVersion = &models.ProviderVersion{ProviderID: provider.ID, Version: version}
		providerVersion.Protocols = protocols
		providerVersion.KeyID = keyID
		providerVersion.ShasumsPath = shasumsPath
		providerVersion.ShasumsSigPath = shasumsSigPath
		if err := h.providerVersionRepo.Create(providerVersion); err != nil {
			regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
			return
		}
	} else {
		providerVersion.Protocols = protocols
		providerVersion.KeyID = keyID
		providerVersion.ShasumsPath = shasumsPath
		providerVersion.ShasumsSigPath = shasumsSigPath
		if err := h.providerVersionRepo.Update(providerVersion); err != nil {
			regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
			return
		}
	}

	// --- platform ------------------------------------------------------------
	if existing, err := h.providerPlatformRepo.GetByVersionAndPlatform(providerVersion.ID, os, arch); err == nil && existing != nil {
		regProvErr(c, http.StatusUnprocessableEntity, "Unprocessable Entity", fmt.Sprintf("platform %s/%s already exists for this version", os, arch))
		return
	}

	platform := &models.ProviderPlatform{
		ProviderVersionID: providerVersion.ID,
		OS:                os,
		Arch:              arch,
		Filename:          filename,
		Shasum:            shasum,
		BinaryPath:        fmt.Sprintf("%s/%s_%s/%s", prefix, os, arch, filename),
		BinarySize:        file.Size,
		GPGKeyID:          keyID,
	}
	if err := h.providerPlatformRepo.Create(platform); err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"id":   platform.ID.String(),
			"type": "registry-provider-platforms",
			"attributes": gin.H{
				"os":                       platform.OS,
				"arch":                     platform.Arch,
				"filename":                 platform.Filename,
				"shasum":                   platform.Shasum,
				"provider-binary-uploaded": true,
			},
		},
	})
}

// storeUpload streams a multipart file into object storage at key. When wantSha is true it also
// returns the file's SHA256 (hex). On any failure it writes the JSON error and returns an error.
func (h *RegistryProviderPublishingHandler) storeUpload(c *gin.Context, fh *multipart.FileHeader, key string, wantSha bool) (string, error) {
	src, err := fh.Open()
	if err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return "", err
	}
	defer func() {
		if cerr := src.Close(); cerr != nil {
			logger.Warnf("Failed to close upload %s: %v", key, cerr)
		}
	}()

	var sha string
	if wantSha {
		hasher := sha256.New()
		if _, err := io.Copy(hasher, src); err != nil {
			regProvErr(c, http.StatusInternalServerError, "Internal Server Error", "failed to hash upload")
			return "", err
		}
		sha = hex.EncodeToString(hasher.Sum(nil))
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			regProvErr(c, http.StatusInternalServerError, "Internal Server Error", "failed to rewind upload")
			return "", err
		}
	}

	if err := h.storage.PutStream(c.Request.Context(), key, src, fh.Size); err != nil {
		regProvErr(c, http.StatusInternalServerError, "Internal Server Error", "failed to upload to storage")
		return "", err
	}
	return sha, nil
}
