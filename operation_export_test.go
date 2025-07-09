package didplc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
				assert.NoError(entry.Validate(), entry.DID+" "+entry.CreatedAt)
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
