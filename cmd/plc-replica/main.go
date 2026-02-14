package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"

	"github.com/did-method-plc/go-didplc/replica"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v3"
	"golang.org/x/sync/errgroup"
)

func main() {
	cmd := &cli.Command{
		Name:  "plc-replica",
		Usage: "PLC directory replica server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "db-url",
				Usage:   "Database URL (e.g. sqlite://replica.db?_journal_mode=WAL, postgres://user:pass@host/db)",
				Value:   "sqlite://replica.db?mode=rwc&cache=shared&_journal_mode=WAL",
				Sources: cli.EnvVars("DATABASE_URL"),
			},
			&cli.StringFlag{
				Name:    "bind",
				Usage:   "HTTP server listen address",
				Value:   ":6780",
				Sources: cli.EnvVars("REPLICA_BIND"),
			},
			&cli.StringFlag{
				Name:    "metrics-addr",
				Usage:   "Metrics HTTP server listen address",
				Value:   ":9464",
				Sources: cli.EnvVars("METRICS_ADDR"),
			},
			&cli.BoolFlag{
				Name:    "no-ingest",
				Usage:   "Disable ingestion from upstream directory",
				Sources: cli.EnvVars("NO_INGEST"),
			},
			&cli.StringFlag{
				Name:    "upstream-directory-url",
				Usage:   "Upstream PLC directory base URL",
				Value:   "https://plc.directory",
				Sources: cli.EnvVars("UPSTREAM_DIRECTORY_URL"),
			},
			&cli.Int64Flag{
				Name:    "cursor-override",
				Usage:   "Initial cursor value used to sync from the upstream host. May be useful when switching the upstream host",
				Value:   -1,
				Sources: cli.EnvVars("CURSOR_OVERRIDE"),
			},
			&cli.IntFlag{
				Name:    "num-workers",
				Usage:   "Number of validation worker threads (0 = auto)",
				Value:   0,
				Sources: cli.EnvVars("NUM_WORKERS"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "Log level (debug, info, warn, error)",
				Value:   "info",
				Sources: cli.EnvVars("LOG_LEVEL"),
			},
			&cli.BoolFlag{
				Name:    "log-json",
				Usage:   "Output logs in JSON format",
				Sources: cli.EnvVars("LOG_JSON"),
			},
		},
		Action: run,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	// Parse configuration
	dbURL := cmd.String("db-url")
	httpAddr := cmd.String("bind")
	metricsAddr := cmd.String("metrics-addr")
	noIngest := cmd.Bool("no-ingest")
	directoryURL := cmd.String("upstream-directory-url")
	cursorOverride := cmd.Int64("cursor-override")
	numWorkers := cmd.Int("num-workers")
	logLevel := cmd.String("log-level")
	logJSON := cmd.Bool("log-json")

	// Initialize logger
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}
	if logJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	otelShutdown, err := setupOTel(ctx)
	if err != nil {
		return fmt.Errorf("otel setup: %w", err)
	}
	defer otelShutdown(context.Background())

	store, err := replica.NewGormOpStore(dbURL, logger)
	if err != nil {
		return fmt.Errorf("failed to create store: %w", err)
	}

	state := replica.NewReplicaState()
	server := replica.NewServer(store, state, httpAddr, logger)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return server.Run(gctx)
	})

	g.Go(func() error {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{Addr: metricsAddr, Handler: mux}
		go func() {
			<-gctx.Done()
			srv.Shutdown(context.Background())
		}()
		slog.Info("metrics server listening", "addr", metricsAddr)
		err := srv.ListenAndServe()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	})

	if !noIngest {
		ingestor, err := replica.NewIngestor(store, state, directoryURL, cursorOverride, numWorkers, logger)
		if err != nil {
			return err
		}
		g.Go(func() error {
			return ingestor.Run(gctx)
		})
	}

	return g.Wait()
}
