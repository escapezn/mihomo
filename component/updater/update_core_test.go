package updater

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreBaseName(t *testing.T) {
	fmt.Println("Core base name =", DefaultCoreUpdater.CoreBaseName())
}

func TestInstallKeepsCurrentOnFailure(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(current, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := &CoreUpdater{}
	if err := u.install(filepath.Join(dir, "missing"), current); err == nil {
		t.Fatal("install of a missing binary succeeded")
	}
	if got, err := os.ReadFile(current); err != nil || string(got) != "old" {
		t.Fatalf("failed install changed the current binary: %q, %v", got, err)
	}
	if _, err := os.Stat(current + ".new"); !os.IsNotExist(err) {
		t.Fatalf("failed install left its temp file: %v", err)
	}

	update := filepath.Join(dir, "update")
	if err := os.WriteFile(update, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := u.install(update, current); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(current); string(got) != "new" {
		t.Fatalf("install wrote %q", got)
	}
}

func TestInstallRetriesTransientRename(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "mihomo")
	update := filepath.Join(dir, "update")
	if err := os.WriteFile(update, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldRename, oldAttempts, oldDelay := renameFile, renameAttempts, renameRetryDelay
	t.Cleanup(func() { renameFile, renameAttempts, renameRetryDelay = oldRename, oldAttempts, oldDelay })
	renameAttempts, renameRetryDelay = 3, 0

	// A scanner holding the new file fails the first renames.
	calls := 0
	renameFile = func(from, to string) error {
		calls++
		if calls < 3 {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: errors.New("being used by another process")}
		}
		return os.Rename(from, to)
	}
	if err := (&CoreUpdater{}).install(update, current); err != nil {
		t.Fatalf("install after %d renames: %v", calls, err)
	}
	if got, _ := os.ReadFile(current); string(got) != "new" {
		t.Fatalf("install wrote %q", got)
	}

	// A rename that keeps failing gives up after renameAttempts tries.
	calls = 0
	renameFile = func(from, to string) error {
		calls++
		return errors.New("still locked")
	}
	if err := (&CoreUpdater{}).install(update, current); err == nil || calls != 3 {
		t.Fatalf("persistent failure: err=%v after %d renames", err, calls)
	}
	if _, err := os.Stat(current + ".new"); !os.IsNotExist(err) {
		t.Fatalf("failed install left its temp file: %v", err)
	}
}

func TestInstallThroughSymlinkKeepsLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Cellar-mihomo")
	link := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	update := filepath.Join(dir, "update")
	if err := os.WriteFile(update, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&CoreUpdater{}).install(update, resolveExePath(link)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(link); string(got) != "new" {
		t.Fatalf("link target holds %q", got)
	}
}

func TestRestorePutsBackupBack(t *testing.T) {
	u := &CoreUpdater{}
	// The current binary missing (the Windows backup renamed it away) and
	// present (the new binary was installed) must both restore.
	for _, existing := range []bool{false, true} {
		dir := t.TempDir()
		current := filepath.Join(dir, "mihomo")
		backup := filepath.Join(dir, "backup")
		if err := os.WriteFile(backup, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
		if existing {
			if err := os.WriteFile(current, []byte("new"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := u.restore(backup, current); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(current); string(got) != "old" {
			t.Fatalf("existing=%v: restored %q", existing, got)
		}
	}
}
