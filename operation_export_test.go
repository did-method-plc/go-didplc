package didplc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func loadJSONStringArray(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fileBytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var arr []string
	err = json.Unmarshal(fileBytes, &arr)
	if err != nil {
		return nil, err
	}
	return arr, nil
}

/*
Only tests invididual log entries in isolation - does not look at `prev` etc.,
and cannot verify signatures on non-genesis ops

Takes a long time (~1 hour) to complete and should be run via:

go test -run TestExportLogEntryValidate -timeout 0
*/
func TestExportLogEntryValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	fmt.Println("NOTE: Running TestExportLogEntryValidate. This is slow. You may want `go test -short`")

	assert := assert.New(t)

	knownBadCIDsList, err := loadJSONStringArray("testdata/known_bad_cids.json")
	if err != nil {
		t.Fatal(err)
	}
	isKnownBadCID := make(map[string]bool)
	for _, cidStr := range knownBadCIDsList {
		isKnownBadCID[cidStr] = true
	}

	// "out.jsonlines" is data from `plc.directory/export`
	f, err := os.Open("../plc_scrape/out.jsonlines")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	lines := make(chan []byte, 8192)
	timestamps := make(chan string, 8192)

	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU()
	wg.Add(numWorkers)
	for range numWorkers {
		go func() {
			defer wg.Done()
			for line := range lines {
				var entry LogEntry
				assert.NoError(json.Unmarshal(line, &entry))
				if isKnownBadCID[entry.CID] {
					// we expect this to fail
					assert.Error(entry.Validate(), entry.DID+" "+entry.CID)
				} else {
					// we expect this to not fail
					assert.NoError(entry.Validate(), entry.DID+" "+entry.CID)
				}
				timestamps <- entry.CreatedAt
			}
		}()
	}

	go func() {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var line = scanner.Bytes()
			tmp := make([]byte, len(line))
			copy(tmp, line)
			lines <- tmp
		}
		assert.NoError(scanner.Err())
		close(lines)
	}()

	go func() {
		wg.Wait()
		close(timestamps)
	}()

	var i = 0
	for ts := range timestamps {
		if i%10000 == 0 {
			fmt.Println(ts)
		}
		i++
	}
}

/*
Tests "audit logs" in bulk.

Each line of "plc_audit_log.jsonlines" is an array of operation logs for a particular DID, in chronological order.

i.e. each line is the same data you would expect from `/<DID>/log/audit`

It was produced by processing an `/export` dump to group by DID.

go test -run TestExportAuditLogEntryValidate -timeout 0
*/
func TestExportAuditLogEntryValidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	fmt.Println("NOTE: Running TestExportAuditLogEntryValidate. This is slow. You may want `go test -short`")

	assert := assert.New(t)

	knownBadDIDsList, err := loadJSONStringArray("testdata/known_bad_dids.json")
	if err != nil {
		t.Fatal(err)
	}
	isKnownBadDID := make(map[string]bool)
	for _, did := range knownBadDIDsList {
		isKnownBadDID[did] = true
	}

	f, err := os.Open("../plc_scrape/plc_audit_log.jsonlines")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	lines := make(chan []byte, 8192)
	progressDIDs := make(chan string, 8192)

	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU()
	wg.Add(numWorkers)
	for range numWorkers {
		go func() {
			defer wg.Done()
			for line := range lines {
				var entries []LogEntry
				assert.NoError(json.Unmarshal(line, &entries))
				thisDID := entries[0].DID
				if isKnownBadDID[thisDID] {
					// we expect this to fail
					assert.Error(VerifyOpLog(entries), thisDID)
				} else {
					// we expect this to not fail
					assert.NoError(VerifyOpLog(entries), thisDID)
				}
				progressDIDs <- thisDID
			}
		}()
	}

	go func() {
		scanner := bufio.NewScanner(f)
		scanner.Buffer(nil, 10000000) // reasonable max size. may need to be bumped if very long logs exist
		for scanner.Scan() {
			var line = scanner.Bytes()
			tmp := make([]byte, len(line))
			copy(tmp, line)
			lines <- tmp
		}
		assert.NoError(scanner.Err())
		close(lines)
	}()

	go func() {
		wg.Wait()
		close(progressDIDs)
	}()

	var i = 0
	for ts := range progressDIDs {
		if i%10000 == 0 {
			fmt.Println(ts)
		}
		i++
	}
}
