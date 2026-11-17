// Command inventory-server runs the Inventory server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // honour TZ without system zoneinfo

	"github.com/commifreak/inventory/internal/server"
)

// version is set at build time.
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version)
			return
		case "healthcheck":
			// Used by the Docker HEALTHCHECK (the image has no shell or curl).
			os.Exit(healthcheck())
		}
	}
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := server.LoadConfig(version)
	if err != nil {
		log.Error("configuration", "err", err)
		os.Exit(2)
	}
	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func healthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
