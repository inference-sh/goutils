package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Another process rotating the shared log file (a rolling deploy runs two of
// the same instance) must not leave this one writing to the renamed copy.
func TestReopenIfMoved_followsThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.txt")
	f := &lumberjack.Logger{Filename: path, MaxSize: 10}
	t.Cleanup(func() { _ = f.Close() })

	_, err := f.Write([]byte("one\n"))
	require.NoError(t, err)
	seen := reopenIfMoved(f, nil)
	require.NotNil(t, seen)

	// Nothing moved: the file is left open.
	same := reopenIfMoved(f, seen)
	require.True(t, os.SameFile(seen, same))

	// The other process rotates: the live file is renamed and a new one
	// created at the path.
	require.NoError(t, os.Rename(path, filepath.Join(dir, "app-rotated.txt")))
	require.NoError(t, os.WriteFile(path, []byte("theirs\n"), 0o644))

	moved := reopenIfMoved(f, seen)
	require.NotNil(t, moved)
	assert.False(t, os.SameFile(seen, moved))

	_, err = f.Write([]byte("two\n"))
	require.NoError(t, err)
	live, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "theirs\ntwo\n", string(live), "the write lands on the file now at the path")
	rotated, err := os.ReadFile(filepath.Join(dir, "app-rotated.txt"))
	require.NoError(t, err)
	assert.Equal(t, "one\n", string(rotated))
}

// A path that is gone (renamed, not yet recreated) is reopened on the next
// write as well.
func TestReopenIfMoved_recreatesAMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.txt")
	f := &lumberjack.Logger{Filename: path, MaxSize: 10}
	t.Cleanup(func() { _ = f.Close() })

	_, err := f.Write([]byte("one\n"))
	require.NoError(t, err)
	seen := reopenIfMoved(f, nil)
	require.NoError(t, os.Rename(path, filepath.Join(dir, "app-rotated.txt")))

	assert.Nil(t, reopenIfMoved(f, seen))
	_, err = f.Write([]byte("two\n"))
	require.NoError(t, err)
	live, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "two\n", string(live))
}
