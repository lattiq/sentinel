package version

import (
	"fmt"
	"runtime"
)

var (
	// Version components - update these for releases
	Major = 0
	Minor = 1
	Patch = 0

	// Build information - can be set via ldflags during build
	BuildTime = "unknown"
	GitCommit = "unknown"
	GitBranch = "unknown"
)

// Version returns the semantic version string
func Version() string {
	return fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
}

// FullVersion returns version with build information
func FullVersion() string {
	return fmt.Sprintf("%s (commit: %s, branch: %s, built: %s, go: %s)",
		Version(), GitCommit, GitBranch, BuildTime, runtime.Version())
}

// Info returns structured version information
func Info() map[string]interface{} {
	return map[string]interface{}{
		"version":    Version(),
		"major":      Major,
		"minor":      Minor,
		"patch":      Patch,
		"build_time": BuildTime,
		"git_commit": GitCommit,
		"git_branch": GitBranch,
		"go_version": runtime.Version(),
	}
}
