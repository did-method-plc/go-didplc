package replica

import (
	"sync"
	"time"
)

// ReplicaState holds shared state between the Ingestor and Server components.
type ReplicaState struct {
	mu                  sync.RWMutex
	lastCommittedOpTime time.Time
}

func NewReplicaState() *ReplicaState {
	return &ReplicaState{}
}

func (s *ReplicaState) SetLastCommittedOpTime(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCommittedOpTime = t
}

func (s *ReplicaState) GetLastCommittedOpTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCommittedOpTime
}
