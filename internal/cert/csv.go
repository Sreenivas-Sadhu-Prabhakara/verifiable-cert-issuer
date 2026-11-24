package cert

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

// BatchHeader is the column set the batch importer expects. Column order does
// not matter and grade, hours and issued_on may be left out.
var BatchHeader = []string{"learner_name", "course", "hours", "grade", "issued_on"}

// columnAliases maps the names a spreadsheet is likely to carry onto the
// canonical column names.
var columnAliases = map[string]string{
	"learner_name": "learner_name",
	"learner":      "learner_name",
	"name":         "learner_name",
	"student":      "learner_name",
	"student_name": "learner_name",
	"course":       "course",
	"course_name":  "course",
	"programme":    "course",
	"program":      "course",
	"hours":        "hours",
	"course_hours": "hours",
	"duration":     "hours",
	"grade":        "grade",
	"result":       "grade",
	"marks":        "grade",
	"issued_on":    "issued_on",
	"issue_date":   "issued_on",
	"date":         "issued_on",
	"completed_on": "issued_on",
}

// BatchRow is one line of the uploaded file, ready to sign or ready to report.
type BatchRow struct {
	Line        int      `json:"line"`
	LearnerName string   `json:"learnerName"`
	Course      string   `json:"course"`
	Hours       int      `json:"hours"`
	Grade       string   `json:"grade"`
	IssuedOn    string   `json:"issuedOn"`
	Problems    []string `json:"problems,omitempty"`
}

// OK reports whether the row can be signed.
func (r BatchRow) OK() bool { return len(r.Problems) == 0 }

// ParseBatchCSV reads a learner list. It returns an error only when the file
// cannot be read as a table at all; a row with a bad value comes back as a
// BatchRow carrying its own problems, so one bad line never stops the rest.
//
// defaultDate fills the issue date for rows that leave it blank. Blank hours
// become zero.
func ParseBatchCSV(r io.Reader, defaultDate string) ([]BatchRow, error) {
	rd := csv.NewReader(r)
	rd.FieldsPerRecord = -1 // rows shorter than the header are padded, not rejected
	rd.TrimLeadingSpace = true

	var (
		index     map[string]int
		rows      []BatchRow
		sawHeader bool
	)
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the file could not be read as CSV: %w", err)
		}
		// FieldPos reports the line in the file, not the index of the record,
		// so a problem can be pointed at the line the institute actually sees
		// in their spreadsheet even when blank lines sit in between.
		line, _ := rd.FieldPos(0)

		if !sawHeader {
			if index, err = mapHeader(rec); err != nil {
				return nil, err
			}
			sawHeader = true
			continue
		}
		if blankRecord(rec) {
			continue
		}

		row := BatchRow{Line: line}
		row.LearnerName = squash(cell(rec, index["learner_name"]))
		row.Course = squash(cell(rec, index["course"]))
		row.Grade = squash(cell(rec, index["grade"]))
		row.IssuedOn = squash(cell(rec, index["issued_on"]))

		if row.LearnerName == "" {
			row.Problems = append(row.Problems, "Learner name is empty.")
		}
		if row.Course == "" {
			row.Problems = append(row.Problems, "Course is empty.")
		}

		if h := squash(cell(rec, index["hours"])); h != "" {
			n, err := parseStrictInt(h)
			switch {
			case err != nil:
				row.Problems = append(row.Problems, fmt.Sprintf("Hours %q is not a whole number of hours.", h))
			case n > MaxHours:
				row.Problems = append(row.Problems, fmt.Sprintf("Hours cannot exceed %d.", MaxHours))
			default:
				row.Hours = n
			}
		}

		if row.IssuedOn == "" {
			row.IssuedOn = defaultDate
		}
		if err := ValidateDate(row.IssuedOn); err != nil {
			row.Problems = append(row.Problems, "Issue date: "+err.Error())
		}

		rows = append(rows, row)
	}
	if !sawHeader {
		return nil, errors.New("the file is empty")
	}
	if len(rows) == 0 {
		return nil, errors.New("the file has a header but no learner rows")
	}
	return rows, nil
}

// mapHeader resolves the header line to column positions.
func mapHeader(header []string) (map[string]int, error) {
	index := map[string]int{}
	for i, raw := range header {
		key := normaliseHeaderCell(raw)
		if canonical, ok := columnAliases[key]; ok {
			if _, seen := index[canonical]; !seen {
				index[canonical] = i
			}
		}
	}
	var missing []string
	for _, required := range []string{"learner_name", "course"} {
		if _, ok := index[required]; !ok {
			missing = append(missing, required)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the header line is missing the %s column; expected a header like: %s",
			strings.Join(missing, " and "), strings.Join(BatchHeader, ","))
	}
	for _, optional := range []string{"hours", "grade", "issued_on"} {
		if _, ok := index[optional]; !ok {
			index[optional] = -1
		}
	}
	return index, nil
}

// normaliseHeaderCell lowercases a header cell, drops a leading byte-order mark
// left by spreadsheet exports, and treats spaces and hyphens as underscores.
func normaliseHeaderCell(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "_", "-", "_", ".", "").Replace(s)
	return strings.Trim(s, "_")
}

func cell(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return rec[i]
}

func blankRecord(rec []string) bool {
	for _, c := range rec {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}
