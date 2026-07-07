// periodic.go runs background maintenance tasks for the master: periodic state
// backup, instance cleanup (removing stopped/errored instances), and scheduled
// instance restarts.
package master

import (
	"fmt"
	"time"

	"github.com/NodePassProject/nodepass/internal/common"
)

// StartPeriodicTasks starts the periodic maintenance tasks loop for backup, cleanup, and restart operations.
//
// Runs indefinitely at an interval defined by common.ReloadInterval. On each tick, executes:
//   - PerformPeriodicBackup: Saves a backup copy of the state file
//   - PerformPeriodicCleanup: Removes duplicate instances, keeping the one in "running" status
//   - PerformPeriodicRestart: Restarts instances that are in "error" status
//
// Returns when the PeriodicDone channel is closed (signaling master shutdown).
// This function should be started as a goroutine during master initialization.
func (m *Master) StartPeriodicTasks() {
	ticker := time.NewTicker(common.ReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.PerformPeriodicBackup()
			m.PerformPeriodicCleanup()
			m.PerformPeriodicRestart()
		case <-m.PeriodicDone:
			ticker.Stop()
			return
		}
	}
}

// PerformPeriodicBackup creates a backup of the current master state to disk.
//
// Saves a copy of the instance registry to a backup file (StatePath + ".backup") using
// the same GOB format as the main state file. This provides a recovery point in case
// the primary state file becomes corrupted. Errors are logged but do not prevent
// other periodic tasks from continuing. The backup runs at regular intervals
// (common.ReloadInterval) to ensure recent data can be recovered.
func (m *Master) PerformPeriodicBackup() {
	backupPath := fmt.Sprintf("%s.backup", m.StatePath)

	if err := m.SaveStateToPath(backupPath); err != nil {
		m.Logger.Error("PerformPeriodicBackup: backup state failed: %v", err)
	} else {
		m.Logger.Info("State backup saved: %v", backupPath)
	}
}

// PerformPeriodicCleanup performs housekeeping tasks on managed instances, cleaning up redundant entries.
//
// Identifies duplicate instances (same ID but different entries in the registry, which can
// occur due to race conditions or bugs). For instances with duplicates, keeps the one in
// "running" status and removes the others. Stopped duplicates are shut down gracefully
// before removal. This ensures the instance registry remains consistent and prevents
// stale entries from accumulating. Runs periodically to maintain registry health.
func (m *Master) PerformPeriodicCleanup() {
	idInstances := make(map[string][]*Instance)
	m.Instances.Range(func(key, value any) bool {
		if id := key.(string); id != APIKeyID {
			idInstances[id] = append(idInstances[id], value.(*Instance))
		}
		return true
	})

	for _, instances := range idInstances {
		if len(instances) <= 1 {
			continue
		}

		keepIdx := 0
		for i, inst := range instances {
			if inst.Status == "running" && instances[keepIdx].Status != "running" {
				keepIdx = i
			}
		}

		for i, inst := range instances {
			if i == keepIdx {
				continue
			}
			inst.deleted = true
			if inst.Status != "stopped" {
				m.StopInstance(inst)
			}
			m.Instances.Delete(inst.ID)
		}
	}
}

// PerformPeriodicRestart automatically restarts instances that have encountered errors during operation.
//
// Scans the instance registry for instances in "error" status (not deleted). For each
// errored instance, stops it gracefully, waits BaseDuration (100ms), and restarts it.
// This self-healing mechanism helps instances recover from transient failures without
// manual intervention. Runs periodically as part of the maintenance loop.
func (m *Master) PerformPeriodicRestart() {
	var errorInstances []*Instance
	m.Instances.Range(func(key, value any) bool {
		if id := key.(string); id != APIKeyID {
			instance := value.(*Instance)
			if instance.Status == "error" && !instance.deleted {
				errorInstances = append(errorInstances, instance)
			}
		}
		return true
	})

	for _, instance := range errorInstances {
		m.StopInstance(instance)
		time.Sleep(BaseDuration)
		m.StartInstance(instance)
	}
}
