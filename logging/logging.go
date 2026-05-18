// Package logging provides structured logging via zerolog.
//
// Call Init() in main() to set up file rotation and console output.
// Then use the level functions with a component name:
//
//	logging.Info("api").Str("key", k).Msg("secret revealed")
//	logging.Error("scheduler").Err(err).Msg("job failed")
//
// For package-level constants to avoid typos:
//
//	const component = "api"
//	logging.Info(component).Msg("started")
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ConsoleMode defines how logs are output to console.
type ConsoleMode int

const (
	ConsoleQuiet  ConsoleMode = iota // No console output
	ConsoleNormal                    // Colored console output to stderr
	ConsoleTUI                       // Route through TUI handler
)

// Config holds initialization parameters for the logging system.
type Config struct {
	Dir        string      // Log file directory
	Filename   string      // Log file name
	MaxSize    int         // Max size in MB before rotation
	MaxBackups int         // Number of rotated files to keep
	MaxAge     int         // Days to retain old files
	Compress   bool        // Compress rotated files
	Console    ConsoleMode // Console output mode
	Level      zerolog.Level
}

// Root is the global logger. Set by Init(), defaults to stderr.
var Root = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).
	With().Timestamp().Logger().Level(zerolog.InfoLevel)

var tuiHandler io.Writer

// SetTUIHandler sets a custom writer for TUI mode console output.
// Must be called before Init.
func SetTUIHandler(w io.Writer) {
	tuiHandler = w
}

// Init sets up the global root logger with file rotation and optional console output.
// Must be called once from main(), before spawning goroutines.
func Init(cfg Config) error {
	if cfg.Dir != "" {
		if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
			return fmt.Errorf("logging: create dir: %w", err)
		}
	}

	rotator := &lumberjack.Logger{
		Filename:   filepath.Join(cfg.Dir, cfg.Filename),
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	writers := []io.Writer{rotator}

	switch cfg.Console {
	case ConsoleNormal:
		writers = append(writers, newConsoleWriter(os.Stderr))
	case ConsoleTUI:
		if tuiHandler != nil {
			writers = append(writers, newConsoleWriter(tuiHandler))
		}
	}

	zerolog.TimeFieldFormat = time.RFC3339Nano
	Root = zerolog.New(zerolog.MultiLevelWriter(writers...)).
		With().Timestamp().Logger().
		Level(cfg.Level)
	return nil
}

// Level functions — return a *zerolog.Event tagged with the component name.

func Trace(component string) *zerolog.Event { return Root.Trace().Str("component", component) }
func Debug(component string) *zerolog.Event { return Root.Debug().Str("component", component) }
func Info(component string) *zerolog.Event  { return Root.Info().Str("component", component) }
func Warn(component string) *zerolog.Event  { return Root.Warn().Str("component", component) }
func Error(component string) *zerolog.Event { return Root.Error().Str("component", component) }
func Fatal(component string) *zerolog.Event { return Root.Fatal().Str("component", component) }

// newConsoleWriter creates a colored console writer.
func newConsoleWriter(out io.Writer) zerolog.ConsoleWriter {
	return zerolog.ConsoleWriter{
		Out:        out,
		TimeFormat: "2006/01/02 15:04:05.000",
		NoColor:    false,
		PartsOrder: []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			"component",
			zerolog.MessageFieldName,
		},
		FieldsExclude: []string{"component"},
		FormatLevel: func(i any) string {
			if ll, ok := i.(string); ok {
				switch ll {
				case "info":
					return "\033[36mINF\033[0m"
				case "warn":
					return "\033[33mWRN\033[0m"
				case "error":
					return "\033[31mERR\033[0m"
				case "debug":
					return "\033[35mDBG\033[0m"
				default:
					return ll
				}
			}
			return "???"
		},
		FormatFieldName: func(i any) string {
			return fmt.Sprintf("\033[2m%s=\033[0m", i)
		},
		FormatFieldValue: func(i any) string {
			return fmt.Sprintf("%s", i)
		},
	}
}
