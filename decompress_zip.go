package getter

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
)

// ZipDecompressor is an implementation of Decompressor that can
// decompress zip files.
type ZipDecompressor struct{}

// Decompress src into dst
func (d *ZipDecompressor) Decompress(dst, src string, dir bool, umask os.FileMode) error {
	// If we're going into a directory we should make that first
	mkdir := dst
	if !dir {
		mkdir = filepath.Dir(dst)
	}
	if err := os.MkdirAll(mkdir, mode(0755, umask)); err != nil {
		return err
	}

	// Open the zip
	zipR, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zipR.Close()

	// Check the zip integrity
	if len(zipR.File) == 0 {
		// Empty archive
		return fmt.Errorf("empty archive: %s", src)
	}
	if !dir && len(zipR.File) > 1 {
		return fmt.Errorf("expected a single file: %s", src)
	}

	// Go through and unarchive
	for _, f := range zipR.File {
		path := dst
		if dir {
			// Disallow parent traversal
			if containsDotDot(f.Name) {
				return fmt.Errorf("entry contains '..': %s", f.Name)
			}

			path = filepath.Join(path, f.Name)
		}

		if f.FileInfo().IsDir() {
			if !dir {
				return fmt.Errorf("expected a single file: %s", src)
			}

			// A directory, just make the directory and continue unarchiving...
			if err := os.MkdirAll(path, mode(0755, umask)); err != nil {
				return err
			}

			continue
		}

		// Create the enclosing directories if we must. ZIP files aren't
		// required to contain entries for just the directories so this
		// can happen.
		if dir {
			if err := os.MkdirAll(filepath.Dir(path), mode(0755, umask)); err != nil {
				return err
			}
		}

		// Open the file for reading
		srcF, err := f.Open()
		if err != nil {
			srcF.Close()
			return err
		}

		err = copyReader(path, srcF, f.Mode(), umask)
		srcF.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
