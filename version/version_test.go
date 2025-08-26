package version

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	version := Version()
	assert.NotEmpty(t, version)

	// Should be in format X.Y.Z
	parts := strings.Split(version, ".")
	assert.Len(t, parts, 3)

	// Should dynamically match current Major.Minor.Patch values
	expectedVersion := fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
	assert.Equal(t, expectedVersion, version)
}

func TestFullVersion(t *testing.T) {
	fullVersion := FullVersion()
	assert.NotEmpty(t, fullVersion)
	assert.Contains(t, fullVersion, Version())
	assert.Contains(t, fullVersion, "commit:")
	assert.Contains(t, fullVersion, "branch:")
	assert.Contains(t, fullVersion, "built:")
	assert.Contains(t, fullVersion, "go:")
}

func TestInfo(t *testing.T) {
	info := Info()

	// Check required fields exist
	assert.Contains(t, info, "version")
	assert.Contains(t, info, "major")
	assert.Contains(t, info, "minor")
	assert.Contains(t, info, "patch")
	assert.Contains(t, info, "build_time")
	assert.Contains(t, info, "git_commit")
	assert.Contains(t, info, "git_branch")
	assert.Contains(t, info, "go_version")

	// Check values
	assert.Equal(t, Version(), info["version"])
	assert.Equal(t, Major, info["major"])
	assert.Equal(t, Minor, info["minor"])
	assert.Equal(t, Patch, info["patch"])
}
