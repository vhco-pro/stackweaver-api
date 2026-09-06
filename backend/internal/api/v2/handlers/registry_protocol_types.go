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
