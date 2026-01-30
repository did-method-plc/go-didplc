package replica

import (
	"sync"

	"github.com/emirpasic/gods/sets/hashset"
	"github.com/emirpasic/gods/sets/treeset"
)

/*

Constraints:

- AddInFlight is always called in order of ascending seq

*/

type InFlight struct {
	resumeCursor int64 // all seqs <= this value have already been processed and committed to db
	dids         *hashset.Set
	seqs         *treeset.Set // treeset means we can find the minimum efficiently
	removed      *treeset.Set // seqs that have been removed but are ahead of the cursor
	lock         sync.RWMutex
}

func int64Comparator(a, b interface{}) int {
	aInt := a.(int64)
	bInt := b.(int64)
	if aInt < bInt {
		return -1
	} else if aInt > bInt {
		return 1
	}
	return 0
}

func NewInFlight(resumeCursor int64) *InFlight {
	return &InFlight{
		resumeCursor: resumeCursor,
		dids:         hashset.New(),
		seqs:         treeset.NewWith(int64Comparator),
		removed:      treeset.NewWith(int64Comparator),
	}
}

func (infl *InFlight) GetResumeCursor() int64 {
	infl.lock.RLock()
	defer infl.lock.RUnlock()
	return infl.resumeCursor
}

// returns true on success, does nothing and returns false if the DID was already in-flight
func (infl *InFlight) AddInFlight(did string, seq int64) bool {
	infl.lock.Lock()
	defer infl.lock.Unlock()

	if infl.dids.Contains(did) {
		return false
	}

	infl.dids.Add(did)
	infl.seqs.Add(seq)

	return true
}

// always succeeds, and updates resumeCursor if appropriate
func (infl *InFlight) RemoveInFlight(did string, seq int64) {
	infl.lock.Lock()
	defer infl.lock.Unlock()

	// just for extra safety, do nothing if it's already been removed
	if !infl.dids.Contains(did) {
		// if you reached here you're using the API wrong
		return
	}

	infl.dids.Remove(did)
	infl.seqs.Remove(seq)
	infl.removed.Add(seq)

	// drain: advance cursor past completed seqs below the lowest inflight
	for {
		it := infl.removed.Iterator()
		if !it.First() {
			break
		}
		minRemoved := it.Value().(int64)

		inflIt := infl.seqs.Iterator()
		if inflIt.First() {
			minInflight := inflIt.Value().(int64)
			if minRemoved >= minInflight {
				break
			}
		}

		// minRemoved is below all inflight items (or inflight is empty), advance cursor
		infl.resumeCursor = minRemoved
		infl.removed.Remove(minRemoved)
	}
}
