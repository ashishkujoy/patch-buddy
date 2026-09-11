package internal

import (
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

// RewriteImports rewrites every Go source file under workdir that imports
// oldPath to import newPath instead. This is the mechanical half of a
// cross-module fix (see patchbot-breaking-upgrade-context.md §5-6): it only
// changes the import path, not call sites - API differences between the two
// modules are left for the breaking-change fix loop to resolve.
func RewriteImports(workdir, oldPath, newPath string) error {
	return filepath.WalkDir(workdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || (d.Name() != "." && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		return rewriteFileImport(path, oldPath, newPath)
	})
}

func rewriteFileImport(path, oldPath, newPath string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}

	if !astutil.RewriteImport(fset, file, oldPath, newPath) {
		return nil
	}

	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to open %s for rewrite: %w", path, err)
	}
	defer func(out *os.File) { _ = out.Close() }(out)

	if err := format.Node(out, fset, file); err != nil {
		return fmt.Errorf("failed to format rewritten %s: %w", path, err)
	}
	return nil
}
