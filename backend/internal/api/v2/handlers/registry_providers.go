// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage"
)

type RegistryProviderHandler struct {
	providerService *registry.ProviderService
	gpgKeyRepo      *repository.GPGKeyRepository
	storage         storage.Client
}

func NewRegistryProviderHandler(
	providerService *registry.ProviderService,
	gpgKeyRepo *repository.GPGKeyRepository,
	storageClient storage.Client,
) *RegistryProviderHandler {
	return &RegistryProviderHandler{
		providerService: providerService,
		gpgKeyRepo:      gpgKeyRepo,
		storage:         storageClient,
	}
}

// ListProviders handles GET /v1/providers
// Query params: offset, limit, verified, namespace (optional in path)
func (h *RegistryProviderHandler) ListProviders(c *gin.Context) {
	namespace := c.Param("namespace") // Optional path parameter
	verifiedStr := c.Query("verified")

	var verified *bool
	switch verifiedStr {
	case "true":
		v := true
		verified = &v
	case "false":
		v := false
		verified = &v
	}

	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	if limit > 100 {
		limit = 100
	}

	providers, total, err := h.providerService.ListProviders(namespace, verified, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []string{"Failed to list providers"},
		})
		return
	}

	// Format response according to Terraform Registry API spec
	response := gin.H{
		"meta": gin.H{
			"limit":          limit,
			"current_offset": offset,
		},
		"providers": formatProviders(providers),
	}

	if offset+limit < int(total) {
		response["meta"].(gin.H)["next_offset"] = offset + limit
		response["meta"].(gin.H)["next_url"] = c.Request.URL.Path + "?limit=" + strconv.Itoa(limit) + "&offset=" + strconv.Itoa(offset+limit)
	}

	c.JSON(http.StatusOK, response)
}

// SearchProviders handles GET /v1/providers/search
func (h *RegistryProviderHandler) SearchProviders(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"errors": []string{"Query parameter 'q' is required"},
		})
		return
	}

	namespace := c.Query("namespace")
	verifiedStr := c.Query("verified")

	var verified *bool
	switch verifiedStr {
	case "true":
		v := true
		verified = &v
	case "false":
		v := false
		verified = &v
	}

	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	if limit > 100 {
		limit = 100
	}

	providers, total, err := h.providerService.SearchProviders(query, namespace, verified, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []string{"Failed to search providers"},
		})
		return
	}

	response := gin.H{
		"meta": gin.H{
			"limit":          limit,
			"current_offset": offset,
		},
		"providers": formatProviders(providers),
	}

	if offset+limit < int(total) {
		response["meta"].(gin.H)["next_offset"] = offset + limit
		response["meta"].(gin.H)["next_url"] = c.Request.URL.Path + "?q=" + query + "&limit=" + strconv.Itoa(limit) + "&offset=" + strconv.Itoa(offset+limit)
	}

	c.JSON(http.StatusOK, response)
}

// GetProviderVersions handles GET /v1/providers/:namespace/:name/versions
func (h *RegistryProviderHandler) GetProviderVersions(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")

	versions, err := h.providerService.GetProviderVersions(namespace, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"Provider not found"},
		})
		return
	}

	// Format response according to Terraform Registry API spec
	versionList := make([]gin.H, len(versions))
	for i, v := range versions {
		platforms := make([]gin.H, len(v.Platforms))
		for j, p := range v.Platforms {
			platforms[j] = gin.H{
				"os":   p.OS,
				"arch": p.Arch,
			}
		}

		versionList[i] = gin.H{
			"version":   v.Version,
			"protocols": protocolList(v.Protocols),
			"platforms": platforms,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"versions": versionList,
	})
}

// GetProvider handles GET /v1/providers/:namespace/:name (latest version)
func (h *RegistryProviderHandler) GetProvider(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")

	provider, err := h.providerService.GetProvider(namespace, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"Provider not found"},
		})
		return
	}

	latestVersion, err := h.providerService.GetLatestVersion(namespace, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"No versions found for this provider"},
		})
		return
	}

	response := formatProviderDetail(provider, latestVersion)
	c.JSON(http.StatusOK, response)
}

// GetProviderVersion handles GET /v1/providers/:namespace/:name/:version
func (h *RegistryProviderHandler) GetProviderVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	version := c.Param("version")

	provider, err := h.providerService.GetProvider(namespace, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"Provider not found"},
		})
		return
	}

	providerVersion, err := h.providerService.GetProviderVersion(namespace, name, version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"Provider version not found"},
		})
		return
	}

	response := formatProviderDetail(provider, providerVersion)
	c.JSON(http.StatusOK, response)
}

// DownloadProvider handles GET /v1/providers/:namespace/:name/:version/download/:os/:arch
// and GET /v1/providers/:namespace/:name/download/:os/:arch (latest version).
//
// This implements the Terraform provider-install "find a package" step: it returns the package
// metadata JSON (protocols, download_url, shasums_url, shasums_signature_url, shasum, signing_keys)
// so Terraform can download the zip, verify its checksum against SHA256SUMS, and verify the
// SHA256SUMS signature against the advertised GPG public key. The URLs point back at this API so
// everything is reachable over the same host Terraform used for discovery.
func (h *RegistryProviderHandler) DownloadProvider(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	version := c.Param("version")
	osParam := c.Param("os")
	arch := c.Param("arch")

	if version == "" {
		latestVersion, err := h.providerService.GetLatestVersion(namespace, name)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider or version not found"}})
			return
		}
		version = latestVersion.Version
	}

	provider, err := h.providerService.GetProvider(namespace, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider not found"}})
		return
	}
	providerVersion, err := h.providerService.GetProviderVersion(namespace, name, version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider version not found"}})
		return
	}

	var platform *models.ProviderPlatform
	for i := range providerVersion.Platforms {
		if providerVersion.Platforms[i].OS == osParam && providerVersion.Platforms[i].Arch == arch {
			platform = &providerVersion.Platforms[i]
			break
		}
	}
	if platform == nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider binary not available for this platform"}})
		return
	}

	// Resolve the signing key advertised to Terraform (the public half uploaded via
	// tfe_registry_gpg_key that the publisher signed SHA256SUMS with).
	gpgKeys := make([]gin.H, 0, 1)
	if providerVersion.KeyID != "" {
		if key, kerr := h.gpgKeyRepo.GetByKeyID(provider.OrganizationID, providerVersion.KeyID); kerr == nil && key != nil {
			gpgKeys = append(gpgKeys, gin.H{
				"key_id":          key.KeyID,
				"ascii_armor":     key.ASCIIArmor,
				"trust_signature": "",
				"source":          "",
				"source_url":      nil,
			})
		}
	}

	base := fmt.Sprintf("%s/v1/providers/%s/%s/%s", externalBaseURL(c), namespace, name, version)

	// Track the download without blocking the response.
	platformID := platform.ID
	go func() {
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		_ = h.providerService.TrackDownload(platformID, ip, ua)
	}()

	c.JSON(http.StatusOK, gin.H{
		"protocols":             protocolList(providerVersion.Protocols),
		"os":                    platform.OS,
		"arch":                  platform.Arch,
		"filename":              platform.Filename,
		"download_url":          fmt.Sprintf("%s/binary/%s/%s", base, osParam, arch),
		"shasums_url":           base + "/sha256sums",
		"shasums_signature_url": base + "/sha256sums.sig",
		"shasum":                platform.Shasum,
		"signing_keys":          gin.H{"gpg_public_keys": gpgKeys},
	})
}

// DownloadBinary streams a provider zip: GET /v1/providers/:namespace/:name/:version/binary/:os/:arch.
func (h *RegistryProviderHandler) DownloadBinary(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	version := c.Param("version")
	osParam := c.Param("os")
	arch := c.Param("arch")

	providerVersion, err := h.providerService.GetProviderVersion(namespace, name, version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider version not found"}})
		return
	}
	for i := range providerVersion.Platforms {
		p := &providerVersion.Platforms[i]
		if p.OS == osParam && p.Arch == arch {
			h.streamObject(c, p.BinaryPath, "application/zip", p.Filename)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider binary not available for this platform"}})
}

// DownloadShasums streams the SHA256SUMS file: GET /v1/providers/:namespace/:name/:version/sha256sums.
func (h *RegistryProviderHandler) DownloadShasums(c *gin.Context) {
	pv, ok := h.versionForShasums(c)
	if !ok {
		return
	}
	h.streamObject(c, pv.ShasumsPath, "text/plain", "SHA256SUMS")
}

// DownloadShasumsSig streams the detached signature: GET /v1/providers/:namespace/:name/:version/sha256sums.sig.
func (h *RegistryProviderHandler) DownloadShasumsSig(c *gin.Context) {
	pv, ok := h.versionForShasums(c)
	if !ok {
		return
	}
	h.streamObject(c, pv.ShasumsSigPath, "application/octet-stream", "SHA256SUMS.sig")
}

func (h *RegistryProviderHandler) versionForShasums(c *gin.Context) (*models.ProviderVersion, bool) {
	pv, err := h.providerService.GetProviderVersion(c.Param("namespace"), c.Param("name"), c.Param("version"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Provider version not found"}})
		return nil, false
	}
	if pv.ShasumsPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"SHA256SUMS not available for this version"}})
		return nil, false
	}
	return pv, true
}

// streamObject pipes an object-storage key to the response with the given content type and
// download filename.
func (h *RegistryProviderHandler) streamObject(c *gin.Context, key, contentType, filename string) {
	if key == "" {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Object not available"}})
		return
	}
	obj, err := h.storage.GetStream(c.Request.Context(), key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"errors": []string{"Object not available"}})
		return
	}
	defer func() {
		if cerr := obj.Close(); cerr != nil {
			logger.Warnf("Failed to close storage stream %s: %v", key, cerr)
		}
	}()
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", contentType)
	if _, err := io.Copy(c.Writer, obj); err != nil {
		logger.Warnf("Failed to stream object %s: %v", key, err)
	}
}

// protocolList splits a stored comma-separated protocols string into the JSON array Terraform
// expects, e.g. "5.0,6.0" -> ["5.0","6.0"]. Empty input defaults to ["5.0"].
func protocolList(protocols string) []string {
	if strings.TrimSpace(protocols) == "" {
		return []string{"5.0"}
	}
	parts := strings.Split(protocols, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return []string{"5.0"}
	}
	return out
}

// externalBaseURL reconstructs the scheme+host Terraform used to reach this API, honoring the
// reverse-proxy / tunnel forwarded headers so download URLs are reachable from the client.
func externalBaseURL(c *gin.Context) string {
	scheme := "https"
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if c.Request.TLS == nil {
		scheme = "http"
	}
	host := c.Request.Host
	if fwd := c.GetHeader("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// GetProviderDownloadsSummary handles GET /v2/providers/:namespace/:name/downloads/summary
func (h *RegistryProviderHandler) GetProviderDownloadsSummary(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")

	latestVersion, err := h.providerService.GetLatestVersion(namespace, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"No versions found for this provider"},
		})
		return
	}

	// Get stats for the first platform (or aggregate all platforms)
	if len(latestVersion.Platforms) == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"errors": []string{"No platforms found for this provider version"},
		})
		return
	}

	// For now, use the first platform's stats
	stats, err := h.providerService.GetDownloadStats(latestVersion.Platforms[0].ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"errors": []string{"Failed to get download statistics"},
		})
		return
	}

	// Format according to Terraform Registry v2 API spec
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"type": "provider-downloads-summary",
			"id":   latestVersion.ID.String(),
			"attributes": gin.H{
				"week":  stats["week"],
				"month": stats["month"],
				"year":  stats["year"],
				"total": stats["total"],
			},
		},
	})
}

// Helper functions

func formatProviders(providers []models.Provider) []gin.H {
	result := make([]gin.H, 0, len(providers))
	for _, p := range providers {
		// Get latest version for each provider
		var latestVersion *models.ProviderVersion
		if len(p.Versions) > 0 {
			latestVersion = &p.Versions[0]
		}

		if latestVersion != nil {
			result = append(result, gin.H{
				"id":           p.Organization.Name + "/" + p.Name + "/" + latestVersion.Version,
				"namespace":    p.Organization.Name,
				"name":         p.Name,
				"version":      latestVersion.Version,
				"published_at": latestVersion.PublishedAt.Format("2006-01-02T15:04:05Z"),
				"downloads":    latestVersion.Downloads,
				"verified":     p.Verified,
			})
		}
	}
	return result
}

func formatProviderDetail(provider *models.Provider, version *models.ProviderVersion) gin.H {
	platforms := make([]gin.H, len(version.Platforms))
	for i, p := range version.Platforms {
		platforms[i] = gin.H{
			"os":       p.OS,
			"arch":     p.Arch,
			"shasum":   p.Shasum,
			"filename": p.Filename,
		}
	}

	// Get all versions for the provider
	allVersions := make([]string, len(provider.Versions))
	for i, v := range provider.Versions {
		allVersions[i] = v.Version
	}

	return gin.H{
		"id":           provider.Organization.Name + "/" + provider.Name + "/" + version.Version,
		"namespace":    provider.Organization.Name,
		"name":         provider.Name,
		"version":      version.Version,
		"published_at": version.PublishedAt.Format("2006-01-02T15:04:05Z"),
		"downloads":    version.Downloads,
		"verified":     provider.Verified,
		"platforms":    platforms,
		"versions":     allVersions,
	}
}
