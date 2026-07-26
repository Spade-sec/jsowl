package jsowl

import "github.com/youmulijiang/jsowl/internal/model"

// Target describes one isolated scan target and its request state.
type Target = model.Target

// BatchItem streams one target result or task error from ScanBatch.
type BatchItem = model.BatchItem
