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
				Name:    "postgres-url",
				Usage:   "PostgreSQL connection string (if set, uses Postgres instead of SQLite)",
				Sources: cli.EnvVars("POSTGRES_URL"),
			},
			&cli.StringFlag{
				Name:    "sqlite-path",
				Usage:   "SQLite database file path (used when --postgres-url is not set)",
				Value:   "replica.db",
				Sources: cli.EnvVars("SQLITE_PATH"),
			},
			&cli.StringFlag{
				Name:    "bind",
				Usage:   "HTTP server listen address",
				Value:   ":8080",
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
				Usage:   "Starting cursor (sequence number) for ingestion",
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
	postgresURL := cmd.String("postgres-url")
	sqlitePath := cmd.String("sqlite-path")
	httpAddr := cmd.String("http-addr")
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

	var store *replica.GormOpStore

	if postgresURL != "" {
		slog.Info("using database", "type", "postgres", "url", postgresURL)
		store, err = replica.NewDBOpStoreWithPostgres(postgresURL, logger)
		if err != nil {
			return fmt.Errorf("failed to create postgres store: %w", err)
		}
	} else {
		slog.Info("using database", "type", "sqlite", "path", sqlitePath)
		store, err = replica.NewDBOpStoreWithSqlite(sqlitePath, logger)
		if err != nil {
			return fmt.Errorf("failed to create sqlite store: %w", err)
		}
	}

	server := replica.NewServer(store, httpAddr, logger)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(server.Run)

	g.Go(func() error {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		slog.Info("metrics server listening", "addr", metricsAddr)
		return http.ListenAndServe(metricsAddr, mux)
	})

	if !noIngest {
		ingestor, err := replica.NewIngestor(store, directoryURL, cursorOverride, numWorkers, logger)
		if err != nil {
			return err
		}
		g.Go(func() error {
			return ingestor.Run(gctx)
		})
	}

	return g.Wait()
}
