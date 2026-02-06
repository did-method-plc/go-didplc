package didplc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// May be returned by GetAllEntries if unsupported by an implementation
	ErrNotImplemented = errors.New("not implemented")

	// May be returned by VerifyOperation (as a wrapped error)
	ErrInvalidOperation = errors.New("invalid PLC operation")

	// May be returned by CommitOperations (as a wrapped error)
	ErrHeadMismatch = errors.New("head mismatch")
)

type OpEntry struct {
	DID         string
	CreatedAt   time.Time
	Nullified   bool
	LastChild   string   // CID of most recent operation with `prev` referencing this op
	AllowedKeys []string // the set of public did:keys currently allowed to update from this op
	Op          Operation
	OpCid       string
}

// PreparedOperation contains all the information needed to commit a validated operation.
type PreparedOperation struct {
	DID          string
	PrevHead     string
	NullifiedOps []string // CIDs of any operations being nullified
	KeyIndex     int
	CreatedAt    time.Time
	Op           Operation
	OpCid        string
}

type OpStore interface {
	// GetEntry returns metadata about a specific operation, plus the operation itself.
	// Returns nil if the DID does not exist.
	GetEntry(ctx context.Context, did string, cid string) (*OpEntry, error)

	// Like GetEntry, but returns the data for the most recent valid operation for a DID.
	// Returns nil if the DID does not exist.
	GetLatest(ctx context.Context, did string) (*OpEntry, error)

	// Returns all entries for a given DID, including those which are nullified.
	// Returns nil or empty slice if the DID does not exist.
	// An implementation may choose not to implement this method, returning ErrNotImplemented if so.
	GetAllEntries(ctx context.Context, did string) ([]*OpEntry, error)

	// CommitOperations atomically commits a batch of prepared operations to the store.
	// All operations in the batch are committed, or none are (all-or-nothing).
	// It is invalid to have multiple operations for the same DID in the same batch.
	//
	// For each PreparedOperation, `PrevHead` MUST match the `OpCid` value returned by an earlier call to GetLatest (Or "" if GetLatest returned nil).
	// PreparedOperations returned by VerifyOperation() will always have `PrevHead` set appropriately.
	//
	// If any updates are made to a particular DID in the time between VerifyOperation() and a corresponding call to CommitOperations(),
	// then CommitOperations() will error due to head mismatch (ErrHeadMismatch).
	CommitOperations(ctx context.Context, ops []*PreparedOperation) error
}

// VerifyOperation validates and prepares a single operation for commit.
// It verifies the signature, validates timestamp consistency, and computes the nullification list.
// On success, returns a PreparedOperation ready to be committed to the store.
// Errors wrapping ErrInvalidOperation indicate the operation is *definitely* invalid.
// Other errors are OpStore-related (e.g. transient database connection issue) and *may* be resolved by retrying.
func VerifyOperation(ctx context.Context, store OpStore, did string, op Operation, createdAt time.Time) (*PreparedOperation, error) {
	head, prevStatus, err := getValidationContext(ctx, store, did, op.PrevCIDStr())
	if err != nil {
		return nil, err
	}

	// Determine allowed keys for signature verification
	var allowedKeys []string
	if op.IsGenesis() {
		calcDid, err := op.DID()
		if err != nil {
			return nil, fmt.Errorf("%w: failed to calculate DID string: %v", ErrInvalidOperation, err)
		}
		if calcDid != did {
			return nil, fmt.Errorf("%w: genesis DID does not match", ErrInvalidOperation)
		}
		allowedKeys = op.EquivalentRotationKeys()
	} else {
		if prevStatus == nil {
			return nil, fmt.Errorf("%w: prevStatus required for non-genesis operation", ErrInvalidOperation)
		}
		allowedKeys = prevStatus.AllowedKeys
	}

	// Verify signature
	keyIdx, err := VerifySignatureAny(op, allowedKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidOperation, err)
	}

	// Create the prepared operation
	prepOp := PreparedOperation{
		DID:       did,
		PrevHead:  head,
		KeyIndex:  keyIdx,
		CreatedAt: createdAt,
		Op:        op,
		OpCid:     op.CID().String(),
	}

	// Genesis operations don't have nullifications or timestamp constraints
	if head == "" {
		prepOp.NullifiedOps = nil
		return &prepOp, nil
	}

	if prevStatus.Nullified {
		return nil, fmt.Errorf("%w: prev CID is nullified", ErrInvalidOperation)
	}

	if prevStatus.LastChild == "" {
		// Regular update (not a nullification)
		// Validate timestamp order
		if createdAt.Sub(prevStatus.CreatedAt) <= 0 {
			return nil, fmt.Errorf("%w: invalid operation timestamp order", ErrInvalidOperation)
		}
		prepOp.NullifiedOps = nil
	} else {
		// This is a nullification - validate timestamp against head
		headStatus, err := store.GetEntry(ctx, did, head)
		if err != nil {
			return nil, err
		}
		if headStatus == nil { // should be unreachable, implies invalid db state
			return nil, fmt.Errorf("failed to retrieve head")
		}
		if createdAt.Sub(headStatus.CreatedAt) <= 0 {
			return nil, fmt.Errorf("%w: invalid operation timestamp order", ErrInvalidOperation)
		}

		// Validate 72h constraint and build nullification list
		nullifiedOps := []string{}
		currentCid := prevStatus.LastChild

		for currentCid != "" {
			status, err := store.GetEntry(ctx, did, currentCid)
			if err != nil {
				return nil, err
			}
			if status == nil { // should be unreachable, implies invalid db state
				return nil, fmt.Errorf("failed to walk nullification chain")
			}

			// Check 72h constraint
			// (this check is only relevant on the first iteration, since each
			// subsequent iteration should be even more recent)
			if createdAt.Sub(status.CreatedAt) > 72*time.Hour {
				return nil, fmt.Errorf("%w: cannot nullify op after 72h (%s - %s = %s)",
					ErrInvalidOperation, createdAt, status.CreatedAt, createdAt.Sub(status.CreatedAt))
			}

			nullifiedOps = append(nullifiedOps, currentCid)
			currentCid = status.LastChild
		}

		prepOp.NullifiedOps = nullifiedOps
	}

	return &prepOp, nil
}

// getValidationContext retrieves the initial information required to validate a signature for a particular operation.
// `cidStr` corresponds to the `prev` field of the operation you're trying to validate.
// For genesis ops (i.e. prev==nil), pass cidStr=="".
//
// Returns the current "head" CID of the passed DID and the OpStatus for the previous operation.
func getValidationContext(ctx context.Context, store OpStore, did string, cidStr string) (string, *OpEntry, error) {
	head, err := store.GetLatest(ctx, did)
	if err != nil {
		return "", nil, err
	}

	if head == nil {
		if cidStr != "" {
			return "", nil, fmt.Errorf("%w: DID not found", ErrInvalidOperation)
		}
		return "", nil, nil // Not an error condition! just means DID is not created yet
	}

	if cidStr == "" {
		return "", nil, fmt.Errorf("%w: expected genesis op but DID already exists", ErrInvalidOperation)
	}

	if head.OpCid == cidStr {
		// shortcut: prev == head
		return head.OpCid, head, nil
	}

	status, err := store.GetEntry(ctx, did, cidStr)
	if err != nil {
		return "", nil, err
	}
	if status == nil {
		return "", nil, fmt.Errorf("%w: prev cid does not exist %s", ErrInvalidOperation, cidStr)
	}

	return head.OpCid, status, nil
}

// MemOpStore is an in-memory implementation of the OpStore interface
type MemOpStore struct {
	head    map[string]string   // DID -> CID (head)
	entries map[string]*OpEntry // CID -> OpEntry
	lock    sync.RWMutex
}

var _ OpStore = (*MemOpStore)(nil)

func NewMemOpStore() *MemOpStore {
	return &MemOpStore{
		head:    make(map[string]string),
		entries: make(map[string]*OpEntry),
	}
}

// GetLatest returns the entry for the most recent valid operation for a DID.
// Returns nil if the DID does not exist.
func (store *MemOpStore) GetLatest(ctx context.Context, did string) (*OpEntry, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	head, exists := store.head[did]
	if !exists {
		return nil, nil
	}
	return store.GetEntry(ctx, did, head)
}

// GetEntry returns the entry for a specific operation.
// Returns nil if the operation does not exist.
func (store *MemOpStore) GetEntry(ctx context.Context, did string, cid string) (*OpEntry, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	status, exists := store.entries[cid]
	if !exists {
		return nil, fmt.Errorf("operation not found")
	}

	if status.DID != did {
		// This implies an implementation bug, should be unreachable
		return nil, fmt.Errorf("operation belongs to a different DID")
	}

	return status, nil
}

func (store *MemOpStore) GetAllEntries(ctx context.Context, did string) ([]*OpEntry, error) {
	// MemOpStore's storage format is not suited to implementing this method
	return nil, ErrNotImplemented
}

// CommitOperations atomically commits a batch of prepared operations to the store.
// All operations in the batch are committed or none are (all-or-nothing).
func (store *MemOpStore) CommitOperations(ctx context.Context, ops []*PreparedOperation) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	// Verify all heads upfront before making any modifications
	// (a db implementation can do this in the main loop and roll back the tx on mismatch)
	for _, prepOp := range ops {
		currentHead := store.head[prepOp.DID]
		if currentHead != prepOp.PrevHead {
			return fmt.Errorf("%w: head CID mismatch for DID %s", ErrHeadMismatch, prepOp.DID)
		}
	}

	// Now apply all modifications
	for _, prepOp := range ops {
		// Handle nullifications
		for _, nullifiedCid := range prepOp.NullifiedOps {
			status := store.entries[nullifiedCid]
			if status == nil {
				// This implies an implementation bug, should be unreachable
				return fmt.Errorf("operation not found during nullification: %s", nullifiedCid)
			}
			if status.DID != prepOp.DID {
				// This implies an implementation bug, should be unreachable
				return fmt.Errorf("operation belongs to different DID during nullification")
			}
			status.Nullified = true
		}

		// Update previous operation's metadata if not a genesis op
		if prepOp.PrevHead != "" {
			prevCidStr := prepOp.Op.PrevCIDStr()
			prevStatus := store.entries[prevCidStr]
			if prevStatus == nil {
				// This implies an implementation bug, should be unreachable
				return fmt.Errorf("previous operation not found: %s", prevCidStr)
			}

			// Trim allowed keys and set last child
			prevStatus.AllowedKeys = prevStatus.AllowedKeys[:prepOp.KeyIndex]
			prevStatus.LastChild = prepOp.OpCid
		}

		store.entries[prepOp.OpCid] = &OpEntry{
			DID:         prepOp.DID,
			CreatedAt:   prepOp.CreatedAt,
			Nullified:   false,
			LastChild:   "",
			AllowedKeys: prepOp.Op.EquivalentRotationKeys(),
			Op:          prepOp.Op,
			OpCid:       prepOp.OpCid,
		}

		// Update head
		store.head[prepOp.DID] = prepOp.OpCid
	}

	return nil
}
