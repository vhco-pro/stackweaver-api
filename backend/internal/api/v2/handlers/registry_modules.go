// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/backend/internal/api/v2/jsonapi"
	"github.com/michielvha/stackweaver/backend/internal/services/auth"
	"github.com/michielvha/stackweaver/backend/internal/services/registry"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
)

type RegistryModuleHandler struct {
	moduleService *registry.ModuleService
	authService   *auth.Service
	orgRepo       *repository.OrganizationRepository
}

func NewRegistryModuleHandler(moduleService *registry.ModuleService, authService *auth.Service, orgRepo *repository.OrganizationRepository) *RegistryModuleHandler {
	return &RegistryModuleHandler{
		moduleService: moduleService,
		authService:   authService,
		orgRepo:       orgRepo,
	}
}

// ListModules handles GET /v1/modules
// Query params: offset, limit, provider, verified, namespace (optional in path)
func (h *RegistryModuleHandler) ListModules(c *gin.Context) {
	namespace := c.Param("namespace") // Optional path parameter
	provider := c.Query("provider")
	verifiedStr := c.Query("verified")

	var verified *bool
	if verifiedStr != "" {
		v := verifiedStr == "true"
		verified = &v
	}

	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	if limit > 100 {
		limit = 100 // Max limit
	}
	if limit < 1 {
		limit = 15 // Default limit
	}

	modules, total, err := h.moduleService.ListModules(namespace, provider, verified, limit, offset)
	if err != nil {
		jsonapi.WriteRegistryLookupError(c, err, "module not found", "failed to list modules")
		return
	}
	modules = h.filterAccessibleModules(c, modules)

	// Format response according to Terraform Registry API spec
	response := RegistryModuleListResponse{
		Meta:    RegistryListMeta{Limit: limit, CurrentOffset: offset},
		Modules: formatModules(modules),
	}
	if int64(offset+limit) < total {
		response.Meta.NextOffset = offset + limit
		response.Meta.NextURL = buildNextURL(c, offset+limit, limit, provider, verified)
	}

	c.JSON(http.StatusOK, response)
}

// SearchModules handles GET /v1/modules/search
func (h *RegistryModuleHandler) SearchModules(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		jsonapi.WriteRegistryError(c, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}

	namespace := c.Query("namespace")
	provider := c.Query("provider")
	verifiedStr := c.Query("verified")

	var verified *bool
	if verifiedStr != "" {
		v := verifiedStr == "true"
		verified = &v
	}

	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	if limit > 100 {
		limit = 100
	}
	if limit < 1 {
		limit = 15
	}

	modules, total, err := h.moduleService.SearchModules(query, namespace, provider, verified, limit, offset)
	if err != nil {
		jsonapi.WriteRegistryLookupError(c, err, "module not found", "failed to list modules")
		return
	}
	modules = h.filterAccessibleModules(c, modules)

	response := RegistryModuleListResponse{
		Meta:    RegistryListMeta{Limit: limit, CurrentOffset: offset},
		Modules: formatModules(modules),
	}
	if int64(offset+limit) < total {
		response.Meta.NextOffset = offset + limit
		response.Meta.NextURL = buildSearchNextURL(c, query, offset+limit, limit, namespace, provider, verified)
	}

	c.JSON(http.StatusOK, response)
}

// GetModuleVersions handles GET /v1/modules/:namespace/:name/:provider/versions
func (h *RegistryModuleHandler) GetModuleVersions(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	provider := c.Param("provider")

	module, err := h.moduleService.GetModule(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module not found")
		return
	}
	if !authorizeRegistryRead(c, h.authService, h.orgRepo, module.OrganizationID, false) {
		return
	}

	versions, err := h.moduleService.GetModuleVersions(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module not found")
		return
	}

	// Format according to Terraform Registry API spec
	versionList := make([]ModuleVersionEntry, 0, len(versions))
	for _, v := range versions {
		submodules := []string{}
		if v.Submodules != nil {
			if submods, ok := v.Submodules["paths"].([]interface{}); ok {
				for _, sm := range submods {
					if smStr, ok := sm.(string); ok {
						submodules = append(submodules, smStr)
					}
				}
			}
		}

		versionList = append(versionList, ModuleVersionEntry{
			Version:    v.Version,
			Submodules: submodules,
		})
	}

	c.JSON(http.StatusOK, ModuleVersionsResponse{
		Modules: []ModuleVersionsEntry{{
			Source:   "", // Will be populated from module source
			Versions: versionList,
		}},
	})
}

// GetModule handles GET /v1/modules/:namespace/:name/:provider (latest version)
func (h *RegistryModuleHandler) GetModule(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	provider := c.Param("provider")

	module, err := h.moduleService.GetModule(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module not found")
		return
	}
	// AUD-123: every module belongs to an org's private registry - gate on membership.
	if !authorizeRegistryRead(c, h.authService, h.orgRepo, module.OrganizationID, false) {
		return
	}

	latestVersion, err := h.moduleService.GetLatestVersion(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "No versions found for this module")
		return
	}

	response := formatModuleDetail(module, latestVersion)
	c.JSON(http.StatusOK, response)
}

// GetModuleVersion handles GET /v1/modules/:namespace/:name/:provider/:version
func (h *RegistryModuleHandler) GetModuleVersion(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	provider := c.Param("provider")
	version := c.Param("version")

	module, err := h.moduleService.GetModule(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module not found")
		return
	}
	if !authorizeRegistryRead(c, h.authService, h.orgRepo, module.OrganizationID, false) {
		return
	}

	moduleVersion, err := h.moduleService.GetModuleVersion(namespace, name, provider, version)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module version not found")
		return
	}

	response := formatModuleDetail(module, moduleVersion)
	c.JSON(http.StatusOK, response)
}

// DownloadModule handles GET /v1/modules/:namespace/:name/:provider/:version/download
// and GET /v1/modules/:namespace/:name/:provider/download (latest version)
func (h *RegistryModuleHandler) DownloadModule(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	provider := c.Param("provider")
	version := c.Param("version")

	module, err := h.moduleService.GetModule(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module not found")
		return
	}
	if !authorizeRegistryRead(c, h.authService, h.orgRepo, module.OrganizationID, false) {
		return
	}

	// If version is empty, get latest version
	if version == "" {
		latestVersion, err := h.moduleService.GetLatestVersion(namespace, name, provider)
		if err != nil {
			jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module or version not found")
			return
		}
		version = latestVersion.Version
	}

	// Get download URL (presigned)
	downloadURL, err := h.moduleService.GetDownloadURL(c.Request.Context(), namespace, name, provider, version)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module version not available for download")
		return
	}

	// Track download asynchronously. AUD-062: capture request-derived values before the goroutine -
	// gin pools and reuses *gin.Context after the handler returns, so reading c inside the goroutine
	// is a data race.
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	go func() {
		moduleVersion, err := h.moduleService.GetModuleVersion(namespace, name, provider, version)
		if err == nil {
			_ = h.moduleService.TrackDownload(moduleVersion.ID, ipAddress, userAgent)
		}
	}()

	// Redirect to presigned URL (302 as per Terraform Registry spec)
	c.Redirect(http.StatusFound, downloadURL)
}

// GetModuleDownloadsSummary handles GET /v2/modules/:namespace/:name/:provider/downloads/summary
func (h *RegistryModuleHandler) GetModuleDownloadsSummary(c *gin.Context) {
	namespace := c.Param("namespace")
	name := c.Param("name")
	provider := c.Param("provider")

	module, err := h.moduleService.GetModule(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "Module not found")
		return
	}
	if !authorizeRegistryRead(c, h.authService, h.orgRepo, module.OrganizationID, false) {
		return
	}

	latestVersion, err := h.moduleService.GetLatestVersion(namespace, name, provider)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusNotFound, "No versions found for this module")
		return
	}

	stats, err := h.moduleService.GetDownloadStats(latestVersion.ID)
	if err != nil {
		jsonapi.WriteRegistryError(c, http.StatusInternalServerError, "Failed to get download statistics")
		return
	}

	// Format according to Terraform Registry v2 API spec
	jsonapi.WriteDocument(c, http.StatusOK, jsonapi.Resource[ModuleDownloadsSummaryAttributes]{
		ID:   latestVersion.ID.String(),
		Type: "module-downloads-summary",
		Attributes: ModuleDownloadsSummaryAttributes{
			Week:  stats["week"],
			Month: stats["month"],
			Year:  stats["year"],
			Total: stats["total"],
		},
	})
}

// filterAccessibleModules drops modules whose org the caller is not a member of (AUD-123).
// All modules are org-private, so an anonymous or cross-tenant caller sees an empty list
// rather than another org's private module names/versions. Pagination counts stay based on
// the unfiltered query, so the caller simply pages through their accessible subset.
func (h *RegistryModuleHandler) filterAccessibleModules(c *gin.Context, modules []models.Module) []models.Module {
	orgIDs := make([]uuid.UUID, 0, len(modules))
	for i := range modules {
		orgIDs = append(orgIDs, modules[i].OrganizationID)
	}
	accessible := registryAccessibleOrgs(c, h.authService, h.orgRepo, orgIDs)
	kept := make([]models.Module, 0, len(modules))
	for _, m := range modules {
		if accessible[m.OrganizationID] {
			kept = append(kept, m)
		}
	}
	return kept
}

// Helper functions

func formatModules(modules []models.Module) []RegistryModuleSummary {
	result := make([]RegistryModuleSummary, 0, len(modules))
	for _, m := range modules {
		// Get latest version for each module
		var latestVersion string
		var publishedAt time.Time
		var downloads int

		if len(m.Versions) > 0 {
			latestVersion = m.Versions[0].Version
			publishedAt = m.Versions[0].PublishedAt
			downloads = m.Versions[0].Downloads
		}

		moduleID := m.Organization.Name + "/" + m.Name + "/" + m.Provider
		if latestVersion != "" {
			moduleID += "/" + latestVersion
		}

		result = append(result, RegistryModuleSummary{
			ID:          moduleID,
			Namespace:   m.Organization.Name,
			Name:        m.Name,
			Version:     latestVersion,
			Provider:    m.Provider,
			Description: m.Description,
			Source:      m.Source,
			PublishedAt: publishedAt.Format("2006-01-02T15:04:05Z"),
			Downloads:   downloads,
			Verified:    m.Verified,
		})
	}
	return result
}

func formatModuleDetail(module *models.Module, version *models.ModuleVersion) RegistryModuleDetail {
	// Get all versions for this module
	allVersions := make([]string, 0, len(module.Versions))
	for _, v := range module.Versions {
		allVersions = append(allVersions, v.Version)
	}

	// The parsed-config projections below shape the stored parse blobs, whose inner values are
	// arbitrary JSON from the module's own configuration - hence the any-typed members.
	inputs := []RegistryModuleInput{}
	if version.Inputs != nil {
		if inputsList, ok := version.Inputs["inputs"].([]interface{}); ok {
			for _, input := range inputsList {
				if inputMap, ok := input.(map[string]interface{}); ok {
					inputs = append(inputs, RegistryModuleInput{
						Name:        inputMap["name"],
						Description: inputMap["description"],
						Default:     inputMap["default"],
						Type:        inputMap["type"],
					})
				}
			}
		}
	}

	outputs := []RegistryModuleOutput{}
	if version.Outputs != nil {
		if outputsList, ok := version.Outputs["outputs"].([]interface{}); ok {
			for _, output := range outputsList {
				if outputMap, ok := output.(map[string]interface{}); ok {
					outputs = append(outputs, RegistryModuleOutput{
						Name:        outputMap["name"],
						Description: outputMap["description"],
					})
				}
			}
		}
	}

	resources := []RegistryModuleResource{}
	if version.Resources != nil {
		if resourcesList, ok := version.Resources["resources"].([]interface{}); ok {
			for _, resource := range resourcesList {
				if resourceMap, ok := resource.(map[string]interface{}); ok {
					resources = append(resources, RegistryModuleResource{
						Name: resourceMap["name"],
						Type: resourceMap["type"],
					})
				}
			}
		}
	}

	submodules := []RegistryModuleSubmodule{}
	if version.Submodules != nil {
		if submodsList, ok := version.Submodules["submodules"].([]interface{}); ok {
			for _, submod := range submodsList {
				if submodMap, ok := submod.(map[string]interface{}); ok {
					submodReadme := ""
					if readmeVal, ok := submodMap["readme"].(string); ok {
						submodReadme = readmeVal // raw markdown for frontend Shiki rendering
					}
					submodules = append(submodules, RegistryModuleSubmodule{
						Path:    submodMap["path"],
						Readme:  submodReadme,
						Empty:   submodMap["empty"],
						Inputs:  submodMap["inputs"],
						Outputs: submodMap["outputs"],
					})
				}
			}
		}
	}

	return RegistryModuleDetail{
		RegistryModuleSummary: RegistryModuleSummary{
			ID:          formatModuleIDWithVersion(module, version),
			Namespace:   module.Organization.Name,
			Name:        module.Name,
			Version:     version.Version,
			Provider:    module.Provider,
			Description: module.Description,
			Source:      module.Source,
			PublishedAt: version.PublishedAt.Format("2006-01-02T15:04:05Z"),
			Downloads:   version.Downloads,
			Verified:    module.Verified,
		},
		Root: RegistryModuleRoot{
			Readme:       version.Readme, // raw markdown for frontend Shiki rendering
			Inputs:       inputs,
			Outputs:      outputs,
			Dependencies: []struct{}{}, // TODO: parse from version.Dependencies
			Resources:    resources,
		},
		Submodules: submodules,
		Providers:  []string{module.Provider}, // TODO: extract from dependencies
		Versions:   allVersions,
	}
}

// func formatModuleID(module models.Module) string {
// 	latestVersion := ""
// 	if len(module.Versions) > 0 {
// 		latestVersion = module.Versions[0].Version
// 	}
// 	if latestVersion == "" {
// 		return module.Organization.Name + "/" + module.Name + "/" + module.Provider
// 	}
// 	return formatModuleIDWithVersion(&module, &module.Versions[0])
// }

func formatModuleIDWithVersion(module *models.Module, version *models.ModuleVersion) string {
	return module.Organization.Name + "/" + module.Name + "/" + module.Provider + "/" + version.Version
}

func buildNextURL(c *gin.Context, offset, limit int, provider string, verified *bool) string {
	url := "/v1/modules"
	if c.Param("namespace") != "" {
		url += "/" + c.Param("namespace")
	}
	url += "?offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(limit)
	if provider != "" {
		url += "&provider=" + provider
	}
	if verified != nil {
		url += "&verified=" + strconv.FormatBool(*verified)
	}
	return url
}

func buildSearchNextURL(c *gin.Context, query string, offset, limit int, namespace, provider string, verified *bool) string {
	url := "/v1/modules/search?q=" + query + "&offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(limit)
	if namespace != "" {
		url += "&namespace=" + namespace
	}
	if provider != "" {
		url += "&provider=" + provider
	}
	if verified != nil {
		url += "&verified=" + strconv.FormatBool(*verified)
	}
	return url
}

// markdownToHTML converts markdown text to HTML with proper formatting
// func markdownToHTML(markdownText string) string {
// 	if markdownText == "" {
// 		return ""
// 	}

// 	// Configure parser with comprehensive extensions
// 	// CommonExtensions includes: tables, fenced code, autolinks, strikethrough, etc.
// 	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
// 	p := parser.NewWithExtensions(extensions)

// 	// Parse markdown
// 	doc := p.Parse([]byte(markdownText))

// 	// Configure HTML renderer with comprehensive flags
// 	// CommonFlags includes: UseXHTML, Smartypants, SmartypantsFractions, etc.
// 	htmlFlags := html.CommonFlags | html.HrefTargetBlank
// 	opts := html.RendererOptions{
// 		Flags: htmlFlags,
// 	}
// 	renderer := html.NewRenderer(opts)

// 	// Render to HTML
// 	htmlBytes := markdown.Render(doc, renderer)
// 	htmlStr := string(htmlBytes)

// 	// Wrap in a container div with proper classes for styling
// 	// This ensures proper spacing and formatting even without Tailwind Typography
// 	return "<div class=\"markdown-content\">" + htmlStr + "</div>"
// }
