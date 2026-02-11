package replica

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"github.com/did-method-plc/go-didplc/didplc"
	"github.com/gorilla/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ExportEntry represents a single entry from the /export endpoint, which includes
// the LogEntry fields plus a sequence number.
type ExportEntry struct {
	DID       string        `json:"did"`
	CID       string        `json:"cid"`
	Seq       int64         `json:"seq"`
	CreatedAt string        `json:"createdAt"`
	Operation didplc.OpEnum `json:"operation"`
	Type      string        `json:"type"`
	Nullified bool          `json:"nullified,omitempty"`
}

// toSequencedOp converts an ExportEntry into a SequencedOp, parsing the
// timestamp and resolving the concrete operation type. Returns nil if the
// entry should be skipped (non-sequenced_op type or invalid operation).
func (e *ExportEntry) toSequencedOp(logger *slog.Logger) (*SequencedOp, error) {
	if e.Type != "sequenced_op" {
		logger.Warn("skipping entry with unexpected type", "type", e.Type)
		return nil, nil
	}

	op := e.Operation.AsOperation()
	if op == nil {
		return nil, nil
	}

	createdAt, err := time.Parse(time.RFC3339, e.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp for %s: %w", e.DID, err)
	}

	return &SequencedOp{
		DID:       e.DID,
		CID:       e.CID,
		Operation: op,
		CreatedAt: createdAt,
		Seq:       e.Seq,
	}, nil
}

const (
	// caughtUpThreshold is how close to real-time the latest entry must be
	// before ingestPaginated switches to streaming.
	caughtUpThreshold = 1 * time.Hour

	// retryDelay is the delay before retrying after an ingestion error.
	retryDelay = 1 * time.Second

	// cursorPersistInterval is how often the resume cursor is persisted.
	cursorPersistInterval = 1 * time.Second

	// If this timeout is reached, we'll retry the request.
	// Also used as the timeout for websocket reads, triggering a reconnect.
	httpClientTimeout = 30 * time.Second
)

var (
	// errOutdatedCursor is returned by ingestStream when the server sends an
	// OutdatedCursor close reason, indicating the cursor is too old for the
	// streaming endpoint and paginated catch-up is needed.
	errOutdatedCursor = errors.New("outdated cursor")

	// errCaughtUp is returned by ingestPaginated when the latest entry
	// timestamp is within 1 hour of now, indicating we're close enough to
	// real-time to switch to streaming.
	errCaughtUp = errors.New("caught up to near real-time")
)

// Ingestor streams operations from a PLC directory export endpoint,
// validates them, and commits them to the local store.
type Ingestor struct {
	store              *GormOpStore
	directoryURL       string
	parsedDirectoryURL *url.URL
	cursorHost         string
	numWorkers         int
	startCursor        int64
	userAgent          string
	httpClient         *http.Client
	wsDialer           *websocket.Dialer
	logger             *slog.Logger
}

// NewIngestor creates a new Ingestor. Pass startCursor == -1 to resume from
// the cursor stored in the database.
func NewIngestor(store *GormOpStore, directoryURL string, startCursor int64, numWorkers int, logger *slog.Logger) (*Ingestor, error) {
	parsedDirectoryURL, err := url.Parse(directoryURL)
	if err != nil {
		return nil, err
	}
	return &Ingestor{
		store:              store,
		directoryURL:       directoryURL,
		parsedDirectoryURL: parsedDirectoryURL,
		cursorHost:         parsedDirectoryURL.Host, // "host" or "host:port"
		numWorkers:         numWorkers,
		startCursor:        startCursor,
		userAgent:          fmt.Sprintf("go-didplc-replica/%s", versioninfo.Short()),
		httpClient: &http.Client{
			Timeout:   httpClientTimeout,
			Transport: otelhttp.NewTransport(http.DefaultTransport),
		},
		wsDialer: websocket.DefaultDialer,
		logger:   logger.With("component", "ingestor"),
	}, nil
}

// Run executes the full ingestion pipeline: resolving the cursor, spawning
// validate/commit workers, streaming operations from the directory, and
// dispatching them through the pipeline.
func (i *Ingestor) Run(ctx context.Context) error {
	cursor := i.startCursor
	if cursor == -1 {
		var err error
		cursor, err = i.store.GetCursor(ctx, i.cursorHost)
		if err != nil {
			return err
		}
	}

	infl := NewInFlight(cursor)

	/*

		ingest reads operations from the upstream PLC directory, and puts them into
		the ingestedOps channel (in seq order).

		one of the loops below reads from ingestedOps and forwards them into seqops, *but*, importantly,
		it ensures that there are never two operations for the same DID in-flight at once.

		ValidateWorker threads each sit in a loop reading from seqops, validating operations, and
		writing the validated ops into the validatedOps channel.

		Finally, the CommitWorker loop reads from validatedOps and commits them to the db in batches.

	*/

	ingestedOps := make(chan *SequencedOp, 10000)
	seqops := make(chan *SequencedOp, 100)
	validatedOps := make(chan ValidatedOp, 1000)

	// Start multiple validateWorker goroutines
	for range i.numWorkers {
		go ValidateWorker(ctx, seqops, validatedOps, infl, i.store)
	}

	// Start single commit worker
	flushCh := make(chan chan struct{})
	go CommitWorker(ctx, validatedOps, infl, i.store, flushCh)

	// Periodically persist the resume cursor and record queue metrics
	go func() {
		ticker := time.NewTicker(cursorPersistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resumeCursor := infl.GetResumeCursor()
				if err := i.store.PutCursor(ctx, i.cursorHost, resumeCursor); err != nil {
					i.logger.Error("failed to persist cursor", "error", err)
				} else {
					i.logger.Info("persisted cursor", "cursor", resumeCursor, "host", i.cursorHost)
				}
				IngestCursorGauge.Record(ctx, resumeCursor)
				IngestedOpsQueueGauge.Record(ctx, int64(len(ingestedOps)))
				SeqOpsQueueGauge.Record(ctx, int64(len(seqops)))
				ValidatedOpsQueueGauge.Record(ctx, int64(len(validatedOps)))
			}
		}
	}()

	// Start ingestion state machine in a goroutine
	go i.ingestLoop(ctx, &cursor, ingestedOps)

	// Process operations from ingestion channel and add to InFlight before sending to workers
	for seqop := range ingestedOps {

		// If the DID is already in-flight, ask the committer to flush its
		// batch so the previous op for this DID hopefully gets committed and removed
		// from in-flight tracking. (it might still be in a queue but we'll get there eventually)
		for !infl.AddInFlight(seqop.DID, seqop.Seq) {
			done := make(chan struct{})
			flushCh <- done
			<-done
		}

		seqops <- seqop

		// Note: we're recording this timestamp when the op is in-flight, not yet validated/committed
		LastIngestedOpTsGauge.Record(ctx, seqop.CreatedAt.Unix())
	}

	return nil
}

// ingestLoop is the state machine that orchestrates ingestion, switching between
// websocket streaming (/export/stream) and paginated HTTP (/export) as needed.
//
// It starts by attempting a websocket stream. If the server reports an outdated
// cursor, it falls back to paginated ingestion until caught up, then switches
// back to streaming. Other errors trigger a retry after a fixed delay.
func (i *Ingestor) ingestLoop(ctx context.Context, cursor *int64, ops chan<- *SequencedOp) {
	recordState := func(attr attribute.KeyValue) {
		// Record 1 for the active state, 0 for the other
		if attr == IngestStateStream {
			IngestStateGauge.Record(ctx, 1, metric.WithAttributes(IngestStateStream))
			IngestStateGauge.Record(ctx, 0, metric.WithAttributes(IngestStatePaginated))
		} else {
			IngestStateGauge.Record(ctx, 1, metric.WithAttributes(IngestStatePaginated))
			IngestStateGauge.Record(ctx, 0, metric.WithAttributes(IngestStateStream))
		}
	}

	for {
		recordState(IngestStateStream)
		i.logger.Info("starting stream ingestion", "cursor", *cursor)
		err := i.ingestStream(ctx, cursor, ops)
		if err == nil {
			continue
		}

		if errors.Is(err, errOutdatedCursor) {
			i.logger.Info("cursor outdated for stream, falling back to paginated", "cursor", *cursor)
			recordState(IngestStatePaginated)
			for {
				i.logger.Info("starting paginated ingestion", "cursor", *cursor)
				perr := i.ingestPaginated(ctx, cursor, ops)
				if perr == nil {
					continue
				}
				if errors.Is(perr, errCaughtUp) {
					i.logger.Info("caught up, switching to stream", "cursor", *cursor)
					break // back to outer loop -> try stream again
				}
				i.logger.Error("paginated ingestion error, retrying", "error", perr)
				if !sleepCtx(ctx, retryDelay) {
					return
				}
			}
			continue
		}

		if ctx.Err() != nil {
			return
		}

		i.logger.Error("stream ingestion error, retrying", "error", err)
		if !sleepCtx(ctx, retryDelay) {
			return
		}
	}
}

// ingestStream connects to the /export/stream websocket endpoint and reads
// operations until an error occurs. Returns errOutdatedCursor if the server
// closes the connection with an OutdatedCursor reason.
func (i *Ingestor) ingestStream(ctx context.Context, cursor *int64, ops chan<- *SequencedOp) error {
	wsURL := buildStreamURL(i.parsedDirectoryURL, *cursor)
	i.logger.Debug("websocket connecting", "url", wsURL)

	header := http.Header{}
	header.Set("User-Agent", i.userAgent)

	conn, _, err := i.wsDialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	// Close the connection when ctx is cancelled. ReadMessage doesn't accept
	// a context, so we need this goroutine to interrupt it.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer conn.Close()

	i.logger.Info("websocket connected", "url", wsURL)

	for {
		conn.SetReadDeadline(time.Now().Add(httpClientTimeout))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			// Check for OutdatedCursor close reason
			var closeErr *websocket.CloseError
			if errors.As(err, &closeErr) && closeErr.Text == "OutdatedCursor" {
				return errOutdatedCursor
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("websocket read error: %w", err)
		}

		var entry ExportEntry
		if err := json.Unmarshal(msg, &entry); err != nil {
			return fmt.Errorf("failed to parse websocket message: %w", err)
		}

		seqop, err := entry.toSequencedOp(i.logger)
		if err != nil {
			return err
		}
		if seqop == nil {
			continue
		}

		select {
		case ops <- seqop:
		case <-ctx.Done():
			return ctx.Err()
		}

		if entry.Seq > *cursor {
			*cursor = entry.Seq
		}
	}
}

// ingestPaginated fetches operations from the paginated /export HTTP endpoint.
// It loops through pages until it encounters an error or determines the cursor
// is within 1 hour of real-time (returns errCaughtUp).
func (i *Ingestor) ingestPaginated(ctx context.Context, cursor *int64, ops chan<- *SequencedOp) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		reqURL := fmt.Sprintf("%s/export?after=%d", i.directoryURL, *cursor)
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", i.userAgent)

		i.logger.Debug("http request starting", "method", "GET", "url", reqURL)
		resp, err := i.httpClient.Do(req)
		if err != nil {
			i.logger.Error("http request failed", "error", err)
			return fmt.Errorf("failed to fetch export: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			i.logger.Error("http request failed", "status", resp.StatusCode)
			return fmt.Errorf("export endpoint returned status %d: %s", resp.StatusCode, string(body))
		}

		var latestCreatedAt time.Time
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(nil, 10000000) // Set a reasonable max size for large operations

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				resp.Body.Close()
				return ctx.Err()
			default:
			}

			var entry ExportEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				resp.Body.Close()
				i.logger.Error("http request failed", "error", "JSON parse error", "details", err)
				return fmt.Errorf("failed to parse export entry: %w", err)
			}

			seqop, err := entry.toSequencedOp(i.logger)
			if err != nil {
				resp.Body.Close()
				return err
			}
			if seqop == nil {
				continue
			}

			select {
			case ops <- seqop:
			case <-ctx.Done():
				resp.Body.Close()
				return ctx.Err()
			}

			if entry.Seq > *cursor {
				*cursor = entry.Seq
			}
			if seqop.CreatedAt.After(latestCreatedAt) {
				latestCreatedAt = seqop.CreatedAt
			}
		}

		if err := scanner.Err(); err != nil {
			resp.Body.Close()
			i.logger.Error("http request failed", "error", "stream read error", "details", err)
			return fmt.Errorf("error reading export stream: %w", err)
		}

		resp.Body.Close()

		// Check if we're close enough to real-time to switch to streaming
		if !latestCreatedAt.IsZero() && time.Since(latestCreatedAt) < caughtUpThreshold {
			return errCaughtUp
		}
	}
}

// buildStreamURL converts an HTTP directory URL to a websocket /export/stream URL.
// e.g. "https://host" -> "wss://host/export/stream?cursor=N"
func buildStreamURL(u *url.URL, cursor int64) string {
	copy := *u

	switch copy.Scheme {
	case "https":
		copy.Scheme = "wss"
	case "http":
		copy.Scheme = "ws"
	}

	copy.Path = "/export/stream"
	q := copy.Query()
	q.Set("cursor", fmt.Sprintf("%d", cursor))
	copy.RawQuery = q.Encode()
	return copy.String()
}

// sleepCtx sleeps for the given duration or until the context is cancelled.
// Returns true if the sleep completed, false if the context was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
