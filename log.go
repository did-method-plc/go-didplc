package didplc

import (
	"context"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

type LogEntry struct {
	DID       string `json:"did"`
	Operation OpEnum `json:"operation"`
	CID       string `json:"cid"`
	Nullified bool   `json:"nullified"`
	CreatedAt string `json:"createdAt"`
}

// Checks self-consistency of this log entry in isolation. Does not access other context or log entries.
func (le *LogEntry) Validate() error {
	op := le.Operation.AsOperation()
	if op == nil {
		return fmt.Errorf("invalid operation type")
	}
	if op.CID().String() != le.CID {
		return fmt.Errorf("log entry CID didn't match computed operation CID")
	}
	if !op.IsSigned() {
		return fmt.Errorf("log entry was not signed")
	}
	if op.IsGenesis() {
		did, err := op.DID()
		if err != nil {
			return err
		}
		if le.DID != did {
			return fmt.Errorf("log entry DID didn't match computed genesis operation DID")
		}
		if _, err := VerifySignatureAny(op, op.EquivalentRotationKeys()); err != nil {
			return fmt.Errorf("failed to validate op genesis signature: %v", err)
		}
	}
	return nil
}

// Verifies an ordered list of log operations for a single DID.
//
// Can be a full audit log (with nullified entries), or a simple log (only "active" entries).
func VerifyOpLog(entries []LogEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("can't verify empty operation log")
	}

	did := entries[0].DID
	os := NewInMemoryOpStore()
	ctx := context.Background()

	for _, oe := range entries {
		if oe.DID != did {
			return fmt.Errorf("inconsistent DID")
		}
		// NOTE: we do not call oe.Validate() here because we'd end up verifying
		// genesis op signatures twice.
		// We check for CID consistency here, and will verify signatures (for all op types) later.
		op := oe.Operation.AsOperation()
		if op == nil {
			return fmt.Errorf("invalid operation type")
		}
		if op.CID().String() != oe.CID {
			return fmt.Errorf("inconsistent CID")
		}

		datetime, err := syntax.ParseDatetime(oe.CreatedAt)
		if err != nil {
			return err
		}
		timestamp := datetime.Time()

		po, err := VerifyOperation(ctx, os, did, op, timestamp)
		if err != nil {
			return err
		}

		err = os.CommitOperations(ctx, []*PreparedOperation{po})
		if err != nil {
			return err
		}
	}

	// check consistency of `nullified` fields
	// Note: This has to be a separate loop because an op's eventual nullification status can't be known until after we've processed all operations
	for idx, oe := range entries {
		if idx == 0 {
			if oe.Nullified {
				return fmt.Errorf("genesis op cannot be nullified")
			}
		}
		status, err := os.GetMetadata(ctx, did, oe.CID)
		if err != nil {
			return err
		}
		if status.Nullified != oe.Nullified {
			return fmt.Errorf("inconsistent nullification status for %s %s", did, oe.CID)
		}
	}

	return nil
}
