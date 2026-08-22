// The example program — §6's walkthrough vehicle. Run the backend stack locally
// (make db-up migrate seed dev in FortressFlag_Backend), then, with no configuration at
// all:
//
//	go run ./cmd/example
//
// It connects with the committed seed server key (low-entropy on purpose — it authenticates
// against a laptop database and nothing else), prints the three seeded flags for two
// evaluation contexts every ten seconds, and prints Diagnostics on Ctrl-C. Environment:
// FF_SERVER_KEY, FF_BASE_URL, FF_CACHE_PATH override the defaults.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	fortressflag "github.com/FortressFlag/FortressFlag_SDK_go"
)

const seedKey = "ffs_dev_seedseedseedseedseedseedseedseedseedseed000"

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	client, err := fortressflag.New(fortressflag.Configuration{
		Key:       env("FF_SERVER_KEY", seedKey),
		BaseURL:   env("FF_BASE_URL", "http://localhost:8080"),
		CachePath: os.Getenv("FF_CACHE_PATH"),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(1)
	}
	defer client.Close()

	startCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	outcome := client.Start(startCtx)
	cancel()
	fmt.Println("start:", outcome)

	contexts := []fortressflag.Context{
		{Key: "user-1", Tags: map[string]string{"cohort": "beta"}},
		{Key: "user-3", Tags: map[string]string{"cohort": "beta"}},
	}
	flags := []string{"new-checkout-flow", "dark-mode", "beta-analytics"}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	print := func() {
		diagnostics := client.Diagnostics()
		fmt.Printf("%s  fetch=%s failures=%d source=%s flags=%d\n",
			time.Now().Format("15:04:05"), diagnostics.LastFetchStatus,
			diagnostics.ConsecutiveFailures, diagnostics.SnapshotSource, diagnostics.FlagCount)
		for _, evaluation := range contexts {
			for _, key := range flags {
				fmt.Printf("  %-18s %-8s (boolean) = %v\n", key, evaluation.Key,
					client.Bool(key, evaluation, false))
			}
		}
	}

	print()
	for {
		select {
		case <-ticker.C:
			print()
		case <-interrupt:
			fmt.Printf("\ndiagnostics: %+v\n", client.Diagnostics())
			return
		}
	}
}
