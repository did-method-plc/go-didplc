package didplc

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

type opStatus struct {
	DID         string
	CreatedAt   time.Time // fields below this line may be mutated
	Nullified   bool
	LastChild   string   // CID
	AllowedKeys []string // the set of public did:keys currently allowed to update from this op
}

// Note: logValidationContext is designed such that it could later be turned into an interface,
// optionally backed by a db rather than in-memory
// Note: ops are globally unique by CID, so opStatus map can be shared across all DIDs
type logValidationContext struct {
	head     map[string]string    // DID -> CID, tracks most recent valid op for a particular DID
	opStatus map[string]*opStatus // CID -> OpStatus
	lock     sync.RWMutex
}

var errLogValidationUnrecoverableInternalError = errors.New("logValidationContext internal state has become inconsistent. This is very bad and should be impossible")

func NewLogValidationContext() *logValidationContext {
	return &logValidationContext{
		head:     make(map[string]string),
		opStatus: make(map[string]*opStatus),
	}
}

// Retrieve the information required to validate a signature for a particular operation, where `cidStr`
// corresponds to the `prev` field of the operation you're trying to validate.
// If you're validating a genesis op (i.e. prev==nil), pass cidStr==""
//
// The returned string is the current "head" CID of the passed DID.
// Any subsequent calls to CommitValidOperation must pass the corresponding head, opStatus values.
//
// This method may also be used to inspect the nullification status and/or createdAt timestamp for a particular op (by did+cid)
func (lvc *logValidationContext) GetValidationContext(did string, cidStr string) (string, *opStatus, error) {
	lvc.lock.RLock()
	defer lvc.lock.RUnlock()

	head, exists := lvc.head[did]
	if !exists {
		if cidStr != "" {
			return "", nil, fmt.Errorf("DID not found")
		}
		return head, nil, nil // Not an error condition! just means DID is not created yet
	}
	status := lvc.opStatus[cidStr]
	if status == nil {
		return "", nil, fmt.Errorf("CID not found")
	}
	if status.DID != did {
		return "", nil, fmt.Errorf("op belongs to a different DID")
	}

	// make a deep copy of the status struct so that concurrent mutations are safe
	statusCopy := *status
	statusCopy.AllowedKeys = make([]string, len(status.AllowedKeys))
	copy(statusCopy.AllowedKeys, status.AllowedKeys)

	return head, &statusCopy, nil
}

// `head` and `prevStatus` MUST be values that were returned from a previous call to GetValidationContext, with the same `did`.
// The caller is responsible for syntax validation and signature verification of the Operation.
// CommitValidOperation will ensure that:
//  1. If this is the first operation for a particular DID, it must be a genesis operation
//  2. Else, it must not be a genesis operation.
//  3. The passed `createdAt` timestamp is greater than that of the current `head` op
//  4. If the operation nullifies a previous operation, the nullified op is less than (or exactly equal to) 72h old
//  5. This DID has not been updated since the corresponding GetValidationContext call
//
// Additionally, the lvc head+opStatus maps are updated to reflect the changes (including updating nullification status if applicable).
//
// Although it should be unreachable, errLogValidationUnrecoverableInternalError
// may be returned if the logValidationContext internal state has become inconsistent.
// This could happen due to an implementation bug, or if an invalid prevStatus is passed
// (one not produced by an earlier call to GetValidationContext).
func (lvc *logValidationContext) CommitValidOperation(did string, head string, prevStatus *opStatus, op Operation, createdAt time.Time, keyIndex int) error {
	thisCid := op.CID().String() // CID() involves expensive-ish serialisation/hashing, best to keep out of the critical section

	lvc.lock.Lock()
	defer lvc.lock.Unlock()

	if head != lvc.head[did] {
		return fmt.Errorf("head CID mismatch")
	}
	if head == "" {
		if !op.IsGenesis() {
			return fmt.Errorf("expected genesis op")
		}
	} else {
		if op.IsGenesis() {
			return fmt.Errorf("unexpected genesis op")
		}
		if prevStatus == nil {
			return fmt.Errorf("invalid prevStatus")
		}
		if prevStatus.Nullified {
			return fmt.Errorf("prev CID is nullified")
		}
		if prevStatus.LastChild == "" { // regular update (not a nullification)
			// note: prevStatus == c.opStatus[head]
			if createdAt.Sub(prevStatus.CreatedAt) <= 0 {
				return fmt.Errorf("invalid operation timestamp order")
			}
		} else { // this is a nullification. prevStatus.LastChild is the CID of the op being nullified
			// note: prevStatus != c.opStatus[head]
			headStatus := lvc.opStatus[head]
			if headStatus == nil {
				return errLogValidationUnrecoverableInternalError
			}
			if createdAt.Sub(headStatus.CreatedAt) <= 0 {
				return fmt.Errorf("invalid operation timestamp order")
			}
			lastChildStatus := lvc.opStatus[prevStatus.LastChild]
			if lastChildStatus == nil {
				return errLogValidationUnrecoverableInternalError
			}
			if createdAt.Sub(lastChildStatus.CreatedAt) > 72*time.Hour {
				return fmt.Errorf("cannot nullify op after 72h (%s - %s = %s)", createdAt, prevStatus.CreatedAt, createdAt.Sub(prevStatus.CreatedAt))
			}
			err := lvc.markNullifiedOp(did, prevStatus.LastChild) // recursive
			if err != nil {
				return err // should never happen, if it does we're in a broken state
			}
		}
		prevStatus.AllowedKeys = prevStatus.AllowedKeys[:keyIndex]
		prevStatus.LastChild = thisCid
		lvc.opStatus[op.PrevCIDStr()] = prevStatus // prevStatus was a copy so we need to write it back
	}
	lvc.head[did] = thisCid
	lvc.opStatus[thisCid] = &opStatus{
		DID:         did,
		CreatedAt:   createdAt,
		Nullified:   false,
		LastChild:   "",
		AllowedKeys: op.EquivalentRotationKeys(),
	}
	return nil
}

// Recurses if more than one op needs to be nullified (if the nullified op has descendents)
// Note: lvc.lock is expected to be held by caller
func (lvc *logValidationContext) markNullifiedOp(did string, cidStr string) error {
	if cidStr == "" {
		return nil
	}
	op := lvc.opStatus[cidStr]
	if op == nil { // this *should* be unreachable
		return errLogValidationUnrecoverableInternalError
	}
	if op.DID != did { // likewise
		return errLogValidationUnrecoverableInternalError
	}
	if op.Nullified {
		return nil
	}
	op.Nullified = true
	return lvc.markNullifiedOp(did, op.LastChild)
}

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

// checks and ordered list of operations for a single DID.
//
// can be a full audit log (with nullified entries), or a simple log (only "active" entries)
func VerifyOpLog(entries []LogEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("can't verify empty operation log")
	}

	did := entries[0].DID
	lvc := NewLogValidationContext()

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

		head, prevStatus, err := lvc.GetValidationContext(did, op.PrevCIDStr())
		if err != nil {
			return err
		}

		var allowedKeys *[]string
		if op.IsGenesis() {
			calcDid, err := op.DID()
			if err != nil {
				return err
			}
			if calcDid != did {
				return fmt.Errorf("genesis DID does not match")
			}
			rotationKeys := op.EquivalentRotationKeys()
			allowedKeys = &rotationKeys
		} else { // not-genesis
			allowedKeys = &prevStatus.AllowedKeys
		}
		keyIdx, err := VerifySignatureAny(op, *allowedKeys)
		if err != nil {
			return err
		}
		err = lvc.CommitValidOperation(did, head, prevStatus, op, timestamp, keyIdx)
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
		_, status, err := lvc.GetValidationContext(did, oe.CID)
		if err != nil {
			return err
		}
		if status.Nullified != oe.Nullified {
			return fmt.Errorf("inconsistent nullification status for %s %s", did, oe.CID)
		}
	}

	return nil
}
