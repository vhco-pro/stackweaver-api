// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package handlers

// Typed payloads for the Terraform Registry Protocol endpoints (#755, Phase 3).
//
// These are not JSON:API and must never become JSON:API. `/v1/modules` and `/v1/providers`
// implement HashiCorp's registry protocol, whose member names and nesting are fixed by the
// published specification, and `terraform init` parses them by name. The types exist so the
// shapes are written down once instead of being re-spelled as anonymous maps at each call site.
//
// Reference: https://developer.hashicorp.com/terraform/registry/api-docs

// ModuleVersionEntry is one version in a module's `versions` list.
type ModuleVersionEntry struct {
	Version    string   `json:"version"`
	Submodules []string `json:"submodules"`
}

// ModuleVersionsEntry is one module in the `modules` list of a versions listing.
type ModuleVersionsEntry struct {
	Source   string               `json:"source"`
	Versions []ModuleVersionEntry `json:"versions"`
}

// ModuleVersionsResponse is the body of GET /v1/modules/:namespace/:name/:provider/versions.
type ModuleVersionsResponse struct {
	Modules []ModuleVersionsEntry `json:"modules"`
}

// ProviderPlatform is one os/arch pair a provider version was published for.
type ProviderPlatform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// ProviderVersionEntry is one version in a provider's `versions` list.
type ProviderVersionEntry struct {
	Version   string             `json:"version"`
	Protocols []string           `json:"protocols"`
	Platforms []ProviderPlatform `json:"platforms"`
}

// ProviderVersionsResponse is the body of GET /v1/providers/:namespace/:name/versions.
type ProviderVersionsResponse struct {
	Versions []ProviderVersionEntry `json:"versions"`
}

// GPGPublicKey is one signing key in a provider download response.
//
// SourceURL is a pointer because the protocol sends JSON null rather than an empty string when
// there is no source URL, and Terraform distinguishes the two.
type GPGPublicKey struct {
	KeyID          string  `json:"key_id"`
	ASCIIArmor     string  `json:"ascii_armor"`
	TrustSignature string  `json:"trust_signature"`
	Source         string  `json:"source"`
	SourceURL      *string `json:"source_url"`
}

// SigningKeys wraps the GPG keys a provider version is signed with.
type SigningKeys struct {
	GPGPublicKeys []GPGPublicKey `json:"gpg_public_keys"`
}

// ProviderDownloadResponse is the body of
// GET /v1/providers/:namespace/:name/:version/download/:os/:arch.
type ProviderDownloadResponse struct {
	Protocols           []string    `json:"protocols"`
	OS                  string      `json:"os"`
	Arch                string      `json:"arch"`
	Filename            string      `json:"filename"`
	DownloadURL         string      `json:"download_url"`
	ShasumsURL          string      `json:"shasums_url"`
	ShasumsSignatureURL string      `json:"shasums_signature_url"`
	Shasum              string      `json:"shasum"`
	SigningKeys         SigningKeys `json:"signing_keys"`
}

// ServiceDiscoveryLogin is the `login.v1` block of the service-discovery document, which is
// what lets `terraform login <host>` work.
type ServiceDiscoveryLogin struct {
	Client     string   `json:"client"`
	GrantTypes []string `json:"grant_types"`
	Authz      string   `json:"authz"`
	Token      string   `json:"token"`
	Ports      []int    `json:"ports"`
}

// ServiceDiscoveryResponse is the body of GET /.well-known/terraform.json.
//
// The member names carry dots by specification (`tfe.v2.2`), which is why they are spelled in
// the struct tags rather than derived from the field names.
type ServiceDiscoveryResponse struct {
	TFEV2       string                `json:"tfe.v2"`
	TFEV21      string                `json:"tfe.v2.1"`
	TFEV22      string                `json:"tfe.v2.2"`
	ModulesV1   string                `json:"modules.v1"`
	ProvidersV1 string                `json:"providers.v1"`
	LoginV1     ServiceDiscoveryLogin `json:"login.v1"`
}

// OpenIDConfigurationResponse is the OIDC discovery document served at
// /.well-known/openid-configuration, whose member names are fixed by the OIDC Discovery spec.
type OpenIDConfigurationResponse struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// RegistryListMeta is the registry protocol's offset-pagination meta block; next_offset and
// next_url appear only when another page exists.
type RegistryListMeta struct {
	Limit         int    `json:"limit"`
	CurrentOffset int    `json:"current_offset"`
	NextOffset    int    `json:"next_offset,omitempty"`
	NextURL       string `json:"next_url,omitempty"`
}

// RegistryModuleSummary is one module row in a registry list/search response.
type RegistryModuleSummary struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
	Source      string `json:"source"`
	PublishedAt string `json:"published_at"`
	Downloads   int    `json:"downloads"`
	Verified    bool   `json:"verified"`
}

// RegistryModuleListResponse is the body of /v1/modules and /v1/modules/search.
type RegistryModuleListResponse struct {
	Meta    RegistryListMeta        `json:"meta"`
	Modules []RegistryModuleSummary `json:"modules"`
}

// RegistryModuleInput / Output / Resource: the registry protocol's parsed-config projections.
// Their members come out of the stored parse blobs, so values stay any where the parser stores
// arbitrary JSON (defaults can be any shape).
type RegistryModuleInput struct {
	Name        any `json:"name"`
	Description any `json:"description"`
	Default     any `json:"default"`
	Type        any `json:"type"`
}

type RegistryModuleOutput struct {
	Name        any `json:"name"`
	Description any `json:"description"`
}

type RegistryModuleResource struct {
	Name any `json:"name"`
	Type any `json:"type"`
}

// RegistryModuleSubmodule: readme is raw markdown for the frontend's Shiki rendering; inputs
// and outputs are forwarded as stored.
type RegistryModuleSubmodule struct {
	Path    any    `json:"path"`
	Readme  string `json:"readme"`
	Empty   any    `json:"empty"`
	Inputs  any    `json:"inputs"`
	Outputs any    `json:"outputs"`
}

// RegistryModuleRoot is the root-module block of a module detail.
type RegistryModuleRoot struct {
	Path         string                   `json:"path"`
	Readme       string                   `json:"readme"`
	Empty        bool                     `json:"empty"`
	Inputs       []RegistryModuleInput    `json:"inputs"`
	Outputs      []RegistryModuleOutput   `json:"outputs"`
	Dependencies []struct{}               `json:"dependencies"`
	Resources    []RegistryModuleResource `json:"resources"`
}

// RegistryModuleDetail is the body of the module detail endpoints.
type RegistryModuleDetail struct {
	RegistryModuleSummary
	Root       RegistryModuleRoot        `json:"root"`
	Submodules []RegistryModuleSubmodule `json:"submodules"`
	Providers  []string                  `json:"providers"`
	Versions   []string                  `json:"versions"`
}

// ModuleDownloadsSummaryAttributes is the v2 downloads-summary attribute block. Members are
// any because the stats service returns untyped counters and the old map forwarded them
// verbatim; narrowing them here would be a wire change.
type ModuleDownloadsSummaryAttributes struct {
	Week  any `json:"week"`
	Month any `json:"month"`
	Year  any `json:"year"`
	Total any `json:"total"`
}

// RegistryProviderSummary is one provider row in a /v1/providers list/search response.
type RegistryProviderSummary struct {
	ID          string `json:"id"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	PublishedAt string `json:"published_at"`
	Downloads   int    `json:"downloads"`
	Verified    bool   `json:"verified"`
}

// RegistryProviderListResponse is the body of /v1/providers and /v1/providers/search.
type RegistryProviderListResponse struct {
	Meta      RegistryListMeta          `json:"meta"`
	Providers []RegistryProviderSummary `json:"providers"`
}

// RegistryProviderPlatformEntry is one os/arch build in a provider detail.
type RegistryProviderPlatformEntry struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Shasum   string `json:"shasum"`
	Filename string `json:"filename"`
}

// RegistryProviderDetail is the body of the provider detail endpoint.
type RegistryProviderDetail struct {
	RegistryProviderSummary
	Platforms []RegistryProviderPlatformEntry `json:"platforms"`
	Versions  []string                        `json:"versions"`
}

// ProviderDownloadsSummaryAttributes mirrors ModuleDownloadsSummaryAttributes for providers.
type ProviderDownloadsSummaryAttributes struct {
	Week  any `json:"week"`
	Month any `json:"month"`
	Year  any `json:"year"`
	Total any `json:"total"`
}
