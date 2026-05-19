package dirs

import (
	"os"
	"os/user"
	"path/filepath"
)

// appDirs holds the configurable directory naming for this application.
// Defaults match the original inference.sh naming. Consumers should call
// SetAppName() at startup to customize.
var appDirs = struct {
	// hyphenated form, used in system paths: /var/log/<name>, /var/cache/<name>
	system string
	// compact form, used in home paths: ~/.<name>, ~/.config/<name>
	home string
}{
	system: "inference-sh",
	home:   "inferencesh",
}

// SetAppName configures the directory naming convention.
// systemName is the hyphenated form (e.g. "inference-sh") used in /var/log/, /var/cache/.
// homeName is the compact form (e.g. "inferencesh") used in ~/.<name>, ~/.config/<name>.
// Must be called before any Get*Directory() calls (typically in main).
func SetAppName(systemName, homeName string) {
	appDirs.system = systemName
	appDirs.home = homeName
}

func GetRootDir() string {
	if os.Getenv("APP_MODE") == "production" {
		if ex, err := os.Executable(); err == nil {
			return filepath.Dir(ex)
		}
	}
	if currentDir, err := os.Getwd(); err == nil {
		return filepath.Dir(currentDir)
	}
	return "."
}

func GetLogDirectory() string {
	return getDirectory(dirConfig{
		envVar:      "LOG_DIR",
		dockerPath:  "/logs",
		xdgVar:      "XDG_DATA_HOME",
		xdgSubpath:  appDirs.system + "/logs",
		homeSubpath: "." + appDirs.home + "/logs",
		fallback:    "logs",
	})
}

func GetConfigDirectory() string {
	return getDirectory(dirConfig{
		envVar:      "CONFIG_DIR",
		dockerPath:  "/config",
		xdgVar:      "XDG_CONFIG_HOME",
		xdgSubpath:  appDirs.home,
		homeSubpath: ".config/" + appDirs.home,
		fallback:    "config",
	})
}

func GetCacheDirectory() string {
	return getDirectory(dirConfig{
		envVar:      "CACHE_DIR",
		dockerPath:  "/cache",
		xdgVar:      "XDG_CACHE_HOME",
		xdgSubpath:  appDirs.system,
		homeSubpath: ".cache/" + appDirs.home,
		fallback:    "cache",
	})
}

type dirConfig struct {
	envVar      string
	dockerPath  string
	xdgVar      string
	xdgSubpath  string
	homeSubpath string
	fallback    string
}

func getDirectory(cfg dirConfig) string {
	// Docker container
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return cfg.dockerPath
	}
	// Explicit env var
	if dir := os.Getenv(cfg.envVar); dir != "" {
		return dir
	}
	// XDG base directory
	if xdg := os.Getenv(cfg.xdgVar); xdg != "" {
		return filepath.Join(xdg, cfg.xdgSubpath)
	}
	// Home directory (works for both root and non-root)
	if home := GetUserHomeDir(); home != "" {
		return filepath.Join(home, cfg.homeSubpath)
	}
	return cfg.fallback
}

// GetUserHomeDir returns the user's home directory, trying multiple methods.
// Works even when $HOME is not set (e.g., in systemd services).
func GetUserHomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return ""
}

// ExpandTilde expands ~ at the start of a path to the user's home directory.
func ExpandTilde(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home := GetUserHomeDir()
	if home == "" {
		return path
	}
	if len(path) == 1 {
		return home
	}
	if path[1] == '/' || path[1] == filepath.Separator {
		return filepath.Join(home, path[2:])
	}
	return path // ~user syntax not supported
}
