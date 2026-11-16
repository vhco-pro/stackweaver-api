// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package registry

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/security/archive"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

// ModulePublisher handles module publishing operations
type ModulePublisher struct {
	moduleRepo        *repository.ModuleRepository
	moduleVersionRepo *repository.ModuleVersionRepository
	orgRepo           *repository.OrganizationRepository
	vcsConnectionRepo *repository.VCSConnectionRepository
	parser            *ModuleParser
	storage           storage.Client
}

// NewModulePublisher creates a new module publisher
func NewModulePublisher(
	moduleRepo *repository.ModuleRepository,
	moduleVersionRepo *repository.ModuleVersionRepository,
	orgRepo *repository.OrganizationRepository,
	vcsConnectionRepo *repository.VCSConnectionRepository,
	storageClient storage.Client,
) *ModulePublisher {
	return &ModulePublisher{
		moduleRepo:        moduleRepo,
		moduleVersionRepo: moduleVersionRepo,
		orgRepo:           orgRepo,
		vcsConnectionRepo: vcsConnectionRepo,
		parser:            NewModuleParser(),
		storage:           storageClient,
	}
}

// CreateModule creates a new module (VCS-connected or standalone)
func (p *ModulePublisher) CreateModule(
	organizationID uuid.UUID,
	name, provider, description string,
	vcsConnectionID *uuid.UUID,
	vcsRepository string,
	autoPublishTags bool,
	publishedBy uuid.UUID,
) (*models.Module, error) {
	// Validate module name and provider
	if name == "" || provider == "" {
		return nil, fmt.Errorf("module name and provider are required")
	}

	// Check if module already exists
	existing, err := p.moduleRepo.GetByOrganizationAndName(organizationID, name, provider)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("module %s/%s already exists", name, provider)
	}

	module := &models.Module{
		OrganizationID:  organizationID,
		Name:            name,
		Provider:        provider,
		Description:     description,
		VCSConnectionID: vcsConnectionID,
		VCSRepository:   vcsRepository,
		AutoPublishTags: autoPublishTags,
		PublishedBy:     publishedBy,
	}

	if vcsConnectionID != nil {
		vcsConn, err := p.vcsConnectionRepo.GetByID(*vcsConnectionID)
		if err != nil {
			return nil, fmt.Errorf("VCS connection not found: %w", err)
		}
		module.VCSConnection = vcsConn
		module.Source = fmt.Sprintf("https://github.com/%s", vcsRepository) // TODO: Support GitLab
	}

	if err := p.moduleRepo.Create(module); err != nil {
		return nil, fmt.Errorf("failed to create module: %w", err)
	}

	return module, nil
}

// ErrVersionExists is returned when the module already has the version being published.
var ErrVersionExists = errors.New("version already exists for this module")

// PublishVersionFromTarball publishes a module version from an uploaded tarball
func (p *ModulePublisher) PublishVersionFromTarball(
	ctx context.Context,
	moduleID uuid.UUID,
	version string,
	tarballReader io.Reader,
	_ int64,
) (*models.ModuleVersion, error) {
	return p.publish(ctx, moduleID, version, "", tarballReader, nil)
}

// PublishCapturedVersion publishes a module version from the snapshot a module_tag_snapshot work
// item captured at tag and commit (#938). The version records them as its source. authorize runs
// first in the publication's transaction, before storage is written: it holds and checks the work
// item and records the capture's proof there, so the version is published if and only if the
// capture still had the authority to publish it and its proof is recorded.
func (p *ModulePublisher) PublishCapturedVersion(ctx context.Context, moduleID uuid.UUID, tag, commit string, snapshot io.Reader, authorize func(tx *gorm.DB) error) (*models.ModuleVersion, error) {
	return p.publish(ctx, moduleID, ExtractVersionFromTag(tag), models.ModuleTagSource(tag, commit), snapshot, authorize)
}

// publish validates, parses and stores a module version. The archive is built first, with no
// database call; then one transaction that follows ctx takes the lock on the module and the
// normalized version, reads the module, checks the version, writes the archive and inserts the
// row, so of two publishers of one version the second waits and is refused with ErrVersionExists
// before it writes storage, and a caller whose context ends stops waiting for the lock or for a
// connection. A failed attempt deletes nothing (owner decision Q13).
func (p *ModulePublisher) publish(ctx context.Context, moduleID uuid.UUID, version, source string, tarballReader io.Reader, authorize func(tx *gorm.DB) error) (*models.ModuleVersion, error) {
	if err := ValidateSemanticVersion(version); err != nil {
		return nil, err
	}
	version = NormalizeVersion(version)

	tempDir, err := os.MkdirTemp("", "module-*")
	if err != nil {
		return nil, fmt.Errorf("creating a temporary directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Warnf("Failed to remove temp directory %s: %v", tempDir, err)
		}
	}()
	// The module is extracted into its own directory and the archive written beside it, so the
	// walk that builds the archive never reads the archive while it is being written.
	moduleDir := filepath.Join(tempDir, "module")
	if err := os.Mkdir(moduleDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating the module directory: %w", err)
	}
	if err := p.extractTarball(tarballReader, moduleDir); err != nil {
		return nil, fmt.Errorf("extracting the tarball: %w", err)
	}
	metadata, err := p.parser.ParseModule(moduleDir)
	if err != nil {
		return nil, fmt.Errorf("parsing the module: %w", err)
	}
	// Rebuilt from the extracted directory to ensure a clean format.
	tarballPath := filepath.Join(tempDir, "module.tar.gz")
	if err := p.createTarball(moduleDir, tarballPath); err != nil {
		return nil, fmt.Errorf("creating the tarball: %w", err)
	}
	metadataJSONB := models.JSONB(metadata.ConvertToJSONB())
	moduleVersion := &models.ModuleVersion{
		ModuleID:     moduleID,
		Version:      version,
		Source:       source,
		Readme:       metadata.Readme,
		Inputs:       models.JSONB{"inputs": metadataJSONB["inputs"]},
		Outputs:      models.JSONB{"outputs": metadataJSONB["outputs"]},
		Dependencies: models.JSONB{"dependencies": metadataJSONB["dependencies"]},
		Resources:    models.JSONB{"resources": metadataJSONB["resources"]},
		Submodules:   models.JSONB{"submodules": metadataJSONB["submodules"]},
		PublishedAt:  time.Now(),
	}
	err = p.moduleVersionRepo.WithPublishLockContext(ctx, moduleID, version, func(tx *gorm.DB, versions *repository.ModuleVersionRepository) error {
		if authorize != nil {
			if err := authorize(tx); err != nil {
				return err
			}
		}
		module, err := repository.NewModuleRepository(tx).GetByID(moduleID)
		if err != nil {
			return fmt.Errorf("module not found: %w", err)
		}
		if versions.Exists(moduleID, version) {
			return fmt.Errorf("version %s: %w", version, ErrVersionExists)
		}
		// Each publication attempt writes an archive of its own (#938): two publishers of one
		// version never share a key, so an attempt that does not commit never touches the archive
		// a successful attempt published. The version row names its archive.
		storagePath := fmt.Sprintf("modules/%s/%s/%s/%s-%s.tar.gz",
			module.Organization.Name, module.Name, module.Provider, version, strings.ReplaceAll(uuid.NewString(), "-", "")[:12])
		moduleVersion.TarballPath = storagePath
		tarballFile, err := os.Open(tarballPath) //nolint:gosec // tarballPath is validated (in temp directory)
		if err != nil {
			return fmt.Errorf("opening the tarball: %w", err)
		}
		defer func() { _ = tarballFile.Close() }()
		fileInfo, err := tarballFile.Stat()
		if err != nil {
			return fmt.Errorf("reading the tarball size: %w", err)
		}
		if err := p.storage.PutStream(ctx, storagePath, tarballFile, fileInfo.Size()); err != nil {
			return fmt.Errorf("uploading to storage: %w", err)
		}
		moduleVersion.TarballSize = fileInfo.Size()
		if err := versions.Create(moduleVersion); err != nil {
			return fmt.Errorf("creating the module version: %w", err)
		}
		return nil
	})
	if err != nil {
		// A failed attempt deletes nothing (owner decision Q13): its archive has a key of its own,
		// and whether the transaction committed can be unknown when the acknowledgement is lost,
		// so no deletion could be ordered safely against it. The archive stays unreferenced.
		return nil, err
	}
	return moduleVersion, nil
}

// createTarball creates a gzipped tarball from a directory
func (p *ModulePublisher) createTarball(sourceDir, outputPath string) error {
	file, err := os.Create(outputPath) //nolint:gosec // outputPath is validated (in temp directory)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warnf("Failed to close file: %v", err)
		}
	}()

	gzipWriter := gzip.NewWriter(file)
	defer func() {
		if err := gzipWriter.Close(); err != nil {
			logger.Warnf("Failed to close gzip writer: %v", err)
		}
	}()

	tarWriter := tar.NewWriter(gzipWriter)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			logger.Warnf("Failed to close tar writer: %v", err)
		}
	}()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden files and directories
		if strings.HasPrefix(info.Name(), ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip .git, .terraform, *.tfstate, .terraform.lock.hcl
		if info.IsDir() && (info.Name() == ".git" || info.Name() == ".terraform") {
			return filepath.SkipDir
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".tfstate") || strings.HasSuffix(path, ".terraform.lock.hcl")) {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// Write file content if not a directory
		if !info.IsDir() {
			data, err := os.Open(path) //nolint:gosec // path is from filepath.Walk (sourceDir), validated
			if err != nil {
				return err
			}
			defer func() {
				if err := data.Close(); err != nil {
					logger.Warnf("Failed to close data file: %v", err)
				}
			}()

			if _, err := io.Copy(tarWriter, data); err != nil {
				return err
			}
		}

		return nil
	})
}

// extractTarball extracts a gzipped tarball to a directory
func (p *ModulePublisher) extractTarball(reader io.Reader, destDir string) error {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			logger.Warnf("Failed to close gzip reader: %v", err)
		}
	}()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Validate the entry name BEFORE constructing any filesystem path.
		// archive.SafeEntryName uses filepath.IsLocal which CodeQL's
		// go/zipslip query recognises as a sanitiser (Wave 8 / D3).
		safeName, err := archive.SafeEntryName(header.Name)
		if err != nil {
			return fmt.Errorf("invalid file path in archive: %w", err)
		}
		targetPath := filepath.Join(destDir, safeName) //nolint:gosec // safeName validated by archive.SafeEntryName

		// Defence-in-depth: also verify the joined path stays under destDir.
		cleanTargetPath := filepath.Clean(targetPath)
		cleanDestDir := filepath.Clean(destDir)
		if !strings.HasPrefix(cleanTargetPath, cleanDestDir+string(filepath.Separator)) && cleanTargetPath != cleanDestDir {
			return fmt.Errorf("invalid file path in archive (directory traversal attempt): %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Security: Validate directory mode to prevent integer overflow
			dirMode := header.Mode & 0o777 // Only use permission bits
			if dirMode > 0o777 {
				dirMode = 0o750 // Default to safe permissions if invalid
			}
			if err := os.MkdirAll(targetPath, os.FileMode(dirMode)); err != nil { //nolint:gosec // dirMode is validated above
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
				return err
			}
			// Security: Validate file mode to prevent integer overflow
			fileMode := header.Mode & 0o777 // Only use permission bits
			if fileMode > 0o777 {
				fileMode = 0o644 // Default to safe permissions if invalid
			}
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, os.FileMode(fileMode)) //nolint:gosec // fileMode is validated above
			if err != nil {
				return err
			}
			// Security: Limit decompression size to prevent decompression bombs (100MB limit)
			const maxDecompressedSize = 100 * 1024 * 1024 // 100MB
			limitedReader := io.LimitReader(tarReader, maxDecompressedSize)
			if _, err := io.Copy(file, limitedReader); err != nil {
				if closeErr := file.Close(); closeErr != nil {
					logger.Warnf("Failed to close file after copy error: %v", closeErr)
				}
				return err
			}
			if err := file.Close(); err != nil {
				logger.Warnf("Failed to close file: %v", err)
			}
		}
	}

	return nil
}
