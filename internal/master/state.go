// state.go handles persistence of master state: saving and loading the instance
// registry to/from disk using GOB serialization for crash recovery.
package master

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveState saves the current master state to disk using GOB serialization.
//
// Delegates to SaveStateToPath using the master's configured state file path.
// This is a convenience wrapper that centralizes state file management.
func (m *Master) SaveState() error {
	return m.SaveStateToPath(m.StatePath)
}

// SaveStateToPath saves the master state to a specific file path with atomic write semantics.
// It uses a temporary file to ensure data integrity during the save operation.
//
// Extracts all instances from the sync.Map and encodes them using GOB format. If the
// instance map is empty, removes the state file (if it exists). Otherwise, creates the
// directory structure if needed, writes to a temporary file first, then atomically
// renames it to the target path. This prevents corruption if the process crashes during
// write. All errors (mkdir, temp creation, encoding, file operations) are wrapped with
// context. The StateMu mutex ensures exclusive access during the save operation.
//
// Parameters:
//   - filePath: Full path where the state file should be saved
//
// Returns an error if any step of the save process fails.
func (m *Master) SaveStateToPath(filePath string) error {
	m.StateMu.Lock()
	defer m.StateMu.Unlock()

	persistentData := make(map[string]*Instance)

	m.Instances.Range(func(key, value any) bool {
		instance := value.(*Instance)
		persistentData[key.(string)] = instance
		return true
	})

	if len(persistentData) == 0 {
		if _, err := os.Stat(filePath); err == nil {
			return os.Remove(filePath)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("SaveStateToPath: mkdirAll failed: %w", err)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(filePath), "np-*.tmp")
	if err != nil {
		return fmt.Errorf("SaveStateToPath: createTemp failed: %w", err)
	}
	tempPath := tempFile.Name()

	removeTemp := func() {
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}

	encoder := gob.NewEncoder(tempFile)
	if err := encoder.Encode(persistentData); err != nil {
		tempFile.Close()
		removeTemp()
		return fmt.Errorf("SaveStateToPath: encode failed: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		removeTemp()
		return fmt.Errorf("SaveStateToPath: close temp file failed: %w", err)
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		removeTemp()
		return fmt.Errorf("SaveStateToPath: rename temp file failed: %w", err)
	}

	return nil
}

// LoadState loads the master state from disk, initializes instances, and optionally auto-starts them.
// It cleans up any temporary files and handles state file deserialization.
//
// First cleans up any leftover temporary files (*.tmp) from previous failed saves. If the
// state file does not exist, returns silently (no instances to restore). Otherwise, opens
// the state file and decodes instances using GOB format. For each loaded instance, the
// "stopped" channel is re-initialized (since channels cannot be serialized). Non-API-key
// instances are set to "stopped" status. Missing configuration URLs are regenerated based
// on current master settings. If an instance has the Restart flag set, it is automatically
// started with a brief delay between starts. A summary log message reports how many
// instances were loaded.
func (m *Master) LoadState() {
	if tmpFiles, _ := filepath.Glob(filepath.Join(filepath.Dir(m.StatePath), "np-*.tmp")); tmpFiles != nil {
		for _, f := range tmpFiles {
			os.Remove(f)
		}
	}

	if _, err := os.Stat(m.StatePath); os.IsNotExist(err) {
		return
	}

	file, err := os.Open(m.StatePath)
	if err != nil {
		m.Logger.Error("LoadState: open file failed: %v", err)
		return
	}
	defer file.Close()

	var persistentData map[string]*Instance
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&persistentData); err != nil {
		m.Logger.Error("LoadState: decode file failed: %v", err)
		return
	}

	for id, instance := range persistentData {
		instance.stopped = make(chan struct{})

		if instance.ID != APIKeyID {
			instance.Status = "stopped"
		}

		if instance.Config == "" && instance.ID != APIKeyID {
			instance.Config = m.GenerateConfigURL(instance)
		}

		if instance.Meta.Tags == nil {
			instance.Meta.Tags = make(map[string]string)
		}

		m.Instances.Store(id, instance)

		if instance.Restart {
			m.Logger.Info("Auto-starting instance: %v [%v]", instance.URL, instance.ID)
			m.StartInstance(instance)
			time.Sleep(BaseDuration)
		}
	}

	m.Logger.Info("Loaded %v instances from %v", len(persistentData), m.StatePath)
}
