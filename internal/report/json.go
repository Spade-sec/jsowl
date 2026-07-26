package report

import (
	"encoding/json"
	"fmt"

	"github.com/youmulijiang/jsowl/internal/model"
)

// WriteJSON atomically writes an indented, complete scan result.
func WriteJSON(path string, result *model.Result) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	data = append(data, '\n')
	return writeAtomic(path, data)
}
