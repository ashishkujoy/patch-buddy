package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RewriteImports_RewritesMatchingImport(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(dir, "middleware.go", `package middleware

import "github.com/dgrijalva/jwt-go"

func Verify(c jwt.MapClaims) {}
`))

	err := RewriteImports(dir, "github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go/v4")
	require.NoError(t, err)

	content := readFile(t, dir, "middleware.go")
	assert.Contains(t, content, `"github.com/dgrijalva/jwt-go/v4"`)
	assert.NotContains(t, content, `"github.com/dgrijalva/jwt-go"`+"\n")
}

func Test_RewriteImports_LeavesUnrelatedImportsUntouched(t *testing.T) {
	dir := t.TempDir()
	original := `package app

import "golang.org/x/text/language"

func Parse(s string) { _, _ = language.Parse(s) }
`
	require.NoError(t, writeFile(dir, "app.go", original))

	err := RewriteImports(dir, "github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go/v4")
	require.NoError(t, err)

	assert.Equal(t, original, readFile(t, dir, "app.go"))
}

func Test_RewriteImports_SkipsVendorDirectory(t *testing.T) {
	dir := t.TempDir()
	original := `package jwtgo

import "github.com/dgrijalva/jwt-go"

var _ = jwt.MapClaims{}
`
	require.NoError(t, writeFile(dir, "vendor/github.com/some/pkg/file.go", original))

	err := RewriteImports(dir, "github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go/v4")
	require.NoError(t, err)

	assert.Equal(t, original, readFile(t, dir, "vendor/github.com/some/pkg/file.go"))
}

func Test_RewriteImports_IgnoresNonGoFiles(t *testing.T) {
	dir := t.TempDir()
	original := `import "github.com/dgrijalva/jwt-go"` + "\n"
	require.NoError(t, writeFile(dir, "notes.txt", original))

	err := RewriteImports(dir, "github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go/v4")
	require.NoError(t, err)

	assert.Equal(t, original, readFile(t, dir, "notes.txt"))
}

func Test_RewriteImports_MultipleFilesOnlyMatchingOnesChange(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(dir, "middleware.go", `package middleware

import "github.com/dgrijalva/jwt-go"

var _ = jwt.MapClaims{}
`))
	unrelated := `package app

import "golang.org/x/text/language"
`
	require.NoError(t, writeFile(dir, "app.go", unrelated))

	err := RewriteImports(dir, "github.com/dgrijalva/jwt-go", "github.com/dgrijalva/jwt-go/v4")
	require.NoError(t, err)

	assert.Contains(t, readFile(t, dir, "middleware.go"), `"github.com/dgrijalva/jwt-go/v4"`)
	assert.Equal(t, unrelated, readFile(t, dir, "app.go"))
}
