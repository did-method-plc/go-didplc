package replica

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/did-method-plc/go-didplc/didplc"
)

type SequencedOp struct {
	DID       string
	CID       string
	Operation didplc.Operation
	CreatedAt time.Time
	Seq       int64
}

const batchSize = 1000

type ValidatedOp struct {
	Seq    int64
	PrepOp *didplc.PreparedOperation
}

// ValidateWorker validates operations from seqops channel and sends validated
// operations to validatedOps channel. Multiple workers can run in parallel.
// Note: caller is responsible for inserting into inflight, but we are responsible for removal on validation failure
func ValidateWorker(ctx context.Context, seqops chan *SequencedOp, validatedOps chan<- ValidatedOp, infl *InFlight, store didplc.OpStore) {
	for {
		select {
		case <-ctx.Done():
			return
		case seqop, ok := <-seqops:
			if !ok {
				return
			}

			prepOp, err := validateInner(ctx, seqop, store)
			if err != nil {
				// Validation failed - remove from InFlight and skip
				slog.Warn("validation failed", "did", seqop.DID, "seq", seqop.Seq, "cid", seqop.CID, "error", err)
				infl.RemoveInFlight(seqop.DID, seqop.Seq)
				continue
			}

			// Send validated operation to commit worker
			validatedOps <- ValidatedOp{
				Seq:    seqop.Seq,
				PrepOp: prepOp,
			}
		}
	}
}

// CommitWorker receives validated operations and commits them to the database in batches.
// Only a single commit worker should run to avoid database contention.
// Note: responsible for removing from InFlight after commit
func CommitWorker(ctx context.Context, validatedOps <-chan ValidatedOp, infl *InFlight, store didplc.OpStore, flushCh <-chan chan struct{}) {
	batch := make([]ValidatedOp, 0, batchSize)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	commitBatch := func() {
		if len(batch) == 0 {
			return
		}

		// Extract PreparedOperations for commit
		prepOps := make([]*didplc.PreparedOperation, len(batch))
		for i, vop := range batch {
			prepOps[i] = vop.PrepOp
		}

		// Commit the batch
		for {
			err := store.CommitOperations(ctx, prepOps)
			if err == nil {
				break
			}
			slog.Error("failed to commit batch", "batch_size", len(batch), "error", err)

			// This is pretty bad. If it's a transient db issue, hopefully we can retry.
			// If it's some other kind of failure... we're stuck here forever. But at least the server can stay up.

			// TODO: try committing each element of the batch individually, to limit the blast radius.

			if !sleepCtx(ctx, 1*time.Second) {
				return
			}
		}

		// Remove all from InFlight
		for _, vop := range batch {
			infl.RemoveInFlight(vop.PrepOp.DID, vop.Seq)
		}

		// Clear the batch
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			commitBatch()
			return
		case vop, ok := <-validatedOps:
			if !ok {
				// Channel closed, commit remaining and exit
				commitBatch()
				return
			}

			// Add to batch
			batch = append(batch, vop)

			// Commit if batch is full
			if len(batch) >= batchSize {
				commitBatch()
			}

		case <-ticker.C:
			// Periodically flush partial batches to prevent deadlock
			commitBatch()

		case done := <-flushCh:
			commitBatch()
			close(done)
		}
	}
}

func validateInner(ctx context.Context, seqop *SequencedOp, store didplc.OpStore) (*didplc.PreparedOperation, error) {
	var prepOp *didplc.PreparedOperation
	var opIsInvalid bool
	var err error

	for {
		prepOp, opIsInvalid, err = didplc.VerifyOperation(ctx, store, seqop.DID, seqop.Operation, seqop.CreatedAt)
		if err != nil {
			if opIsInvalid {
				// Operation is definitely invalid - don't retry
				return nil, fmt.Errorf("failed verifying op %s, %s: %w", seqop.DID, seqop.CID, err)
			}

			// Transient error (hopefully) - retry with sleep.
			// If the db is down then waiting for it to come back is all we can do.
			slog.Warn("failed verifying op, retrying", "did", seqop.DID, "cid", seqop.CID, "error", err)
			if !sleepCtx(ctx, 1*time.Second) {
				return nil, fmt.Errorf("context cancelled while retrying verification: %w", err)
			}
			continue
		}

		break // success
	}

	if prepOp.OpCid != seqop.CID {
		return nil, fmt.Errorf("inconsistent CID for %s %s", seqop.DID, seqop.CID)
	}

	return prepOp, nil
}
