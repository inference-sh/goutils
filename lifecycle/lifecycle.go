package lifecycle

import (
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/inference-sh/goutils/logging"
)

type PanicHandler func(reason any)
type ShutdownHandler func()

// GracefulShutdown handles two-phase signal shutdown:
// First SIGINT/SIGTERM calls drainFn (if non-nil), second calls shutdownFn and exits.
// If drainFn is nil, the first signal triggers shutdownFn immediately.
func GracefulShutdown(drainFn func(), shutdownFn ShutdownHandler, onExit func()) {
	sigChan := make(chan os.Signal, 1)
	done := make(chan struct{})

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logging.Warn("lifecycle").Msgf("Received signal: %s", sig.String())

		if drainFn != nil {
			drainFn()
			// Wait for second signal to force shutdown
			sig = <-sigChan
			logging.Warn("lifecycle").Msgf("Received second signal: %s — forcing shutdown", sig.String())
		}

		shutdownFn()
		if onExit != nil {
			onExit()
		}
		flush()
		exit(0)
		close(done)
	}()

	<-done
}

// PanicExit calls optional handler then exits.
func PanicExit(r any, handler PanicHandler) {
	flush()
	logging.Error("lifecycle").Msgf("Fatal panic: %v", r)
	logging.Error("lifecycle").Msgf("Stack trace:\n%s", string(debug.Stack()))
	if handler != nil {
		handler(r)
	}
	flush()
	exit(1)
}

// RecoverOrPanicExit runs recover() and routes through PanicExit with handler.
func RecoverOrPanicExit(handler PanicHandler) {
	if r := recover(); r != nil {
		PanicExit(r, handler)
	}
}

// SafeGo runs fn in a goroutine with panic recovery + optional handler.
func SafeGo(fn func(), handler PanicHandler) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				PanicExit(r, handler)
			}
		}()
		fn()
	}()
}

func flush() {
	_ = os.Stderr.Sync()
	_ = os.Stdout.Sync()
}

func exit(code int) {
	time.Sleep(100 * time.Millisecond)
	os.Exit(code)
}
