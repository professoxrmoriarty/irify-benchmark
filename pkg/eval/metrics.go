// Package eval provides metric computation for benchmark evaluation.
package eval

// ComputeRecall calculates recall = TP / (TP + FN).
// Returns 0 when the denominator is 0 to avoid division by zero.
func ComputeRecall(tp, fn int) float64 {
	denom := tp + fn
	if denom == 0 {
		return 0
	}
	return float64(tp) / float64(denom)
}

// ComputePrecision calculates precision = TP / (TP + FP).
// Returns 0 when the denominator is 0 to avoid division by zero.
func ComputePrecision(tp, fp int) float64 {
	denom := tp + fp
	if denom == 0 {
		return 0
	}
	return float64(tp) / float64(denom)
}

// ComputeF1 calculates the F1 score from precision and recall.
// Returns 0 when the denominator is 0 to avoid division by zero.
func ComputeF1(precision, recall float64) float64 {
	denom := precision + recall
	if denom == 0 {
		return 0
	}
	return 2 * precision * recall / denom
}
