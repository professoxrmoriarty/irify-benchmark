package store

import "github.com/irify/irify-benchmark/pkg/schema"

// Store abstracts persistent storage for benchmark artifacts.
type Store interface {
	// ReadAnnotation loads a benchmark annotation set.
	ReadAnnotation(benchmarkID string) (*schema.Annotation, error)

	// WriteAnnotation saves an annotation set.
	WriteAnnotation(a *schema.Annotation) error

	// ReadFindingSet loads engine findings.
	ReadFindingSet(benchmarkID, engine, version string) (*schema.FindingSet, error)

	// WriteFindingSet saves engine findings.
	WriteFindingSet(f *schema.FindingSet) error

	// ReadResult loads an evaluation result.
	ReadResult(benchmarkID, engine, version string) (*schema.Result, error)

	// WriteResult saves an evaluation result.
	WriteResult(r *schema.Result) error

	// ReadPendingQueue loads the review queue.
	ReadPendingQueue(benchmarkID string) (*schema.PendingQueue, error)

	// WritePendingQueue saves the review queue.
	WritePendingQueue(q *schema.PendingQueue) error

	// SaveRawReport persists the original engine output bytes.
	SaveRawReport(benchmarkID, engine, version, format string, data []byte) error

	// ReadRawReport loads the original engine output bytes.
	ReadRawReport(benchmarkID, engine, version string) ([]byte, string, error)
}
