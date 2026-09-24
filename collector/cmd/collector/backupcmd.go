// Backup/restore/prune command wiring: thin translation from CLI and
// config into the internal/backup engine. No logic lives here beyond
// flag handling; failures propagate with the engine's bounded errors.
package main

import (
	"context"
	"fmt"
	"time"

	"blueveil/collector/internal/backup"
)

func runBackup(configFile string, f serveFlags, outParent string) error {
	cfg, err := serveConfig(configFile, f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	dir, m, err := backup.Backup(ctx, cfg, outParent)
	if err != nil {
		return err
	}
	fmt.Printf("backup %s backend=%s schema=%d tables=%d\n", dir, m.Backend, m.SchemaVersion, len(m.Tables))
	return nil
}

func runRestore(configFile string, f serveFlags, from, dbname string, force bool) error {
	cfg, err := serveConfig(configFile, f)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	counts, err := backup.Restore(ctx, cfg, from, backup.RestoreTarget{Database: dbname, Force: force})
	if err != nil {
		return err
	}
	total := int64(0)
	for _, n := range counts {
		total += n
	}
	fmt.Printf("restore verified: %d tables, %d rows\n", len(counts), total)
	return nil
}

func runPrune(dir string, keep int) error {
	removed, err := backup.Prune(dir, keep)
	if err != nil {
		return err
	}
	fmt.Printf("prune removed %d backup(s)\n", removed)
	return nil
}
