package replica

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("github.com/did-method-plc/go-didplc/replica")

var (
	IngestCursorGauge      metric.Int64Gauge
	IngestedOpsQueueGauge  metric.Int64Gauge
	SeqOpsQueueGauge       metric.Int64Gauge
	ValidatedOpsQueueGauge metric.Int64Gauge
	IngestStateGauge       metric.Int64Gauge
	LastIngestedOpTsGauge  metric.Int64Gauge
)

var (
	IngestStateStream    = attribute.String("state", "stream")
	IngestStatePaginated = attribute.String("state", "paginated")
)

func init() {
	var err error
	IngestCursorGauge, err = meter.Int64Gauge("plc_replica_ingest_cursor",
		metric.WithDescription("The most recently committed seq value"),
	)
	if err != nil {
		panic(err)
	}
	IngestedOpsQueueGauge, err = meter.Int64Gauge("plc_replica_ingested_ops_queue",
		metric.WithDescription("Number of items in the ingested ops channel"),
	)
	if err != nil {
		panic(err)
	}
	SeqOpsQueueGauge, err = meter.Int64Gauge("plc_replica_seq_ops_queue",
		metric.WithDescription("Number of items in the sequenced ops channel"),
	)
	if err != nil {
		panic(err)
	}
	ValidatedOpsQueueGauge, err = meter.Int64Gauge("plc_replica_validated_ops_queue",
		metric.WithDescription("Number of items in the validated ops channel"),
	)
	if err != nil {
		panic(err)
	}
	IngestStateGauge, err = meter.Int64Gauge("plc_replica_ingest_state",
		metric.WithDescription("Current ingest mode: 1 with state attribute (stream or paginated)"),
	)
	if err != nil {
		panic(err)
	}
	LastIngestedOpTsGauge, err = meter.Int64Gauge("plc_replica_last_ingested_op_ts",
		metric.WithDescription("Unix timestamp of the most recently ingested operation"),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(err)
	}
}
