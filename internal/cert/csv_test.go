package cert_test

import (
	"strings"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

func TestParseBatchCSV(t *testing.T) {
	const today = "2026-03-14"

	tests := []struct {
		name string
		in   string
		want []cert.BatchRow
	}{
		{
			name: "canonical header",
			in: "learner_name,course,hours,grade,issued_on\n" +
				"Asha Kumari,Arc Welding Level 2,120,A,2026-02-10\n" +
				"Ravi Patil,Arc Welding Level 2,120,B+,2026-02-10\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Arc Welding Level 2", Hours: 120, Grade: "A", IssuedOn: "2026-02-10"},
				{Line: 3, LearnerName: "Ravi Patil", Course: "Arc Welding Level 2", Hours: 120, Grade: "B+", IssuedOn: "2026-02-10"},
			},
		},
		{
			name: "spreadsheet header names and column order",
			in: "Course Name,Student Name,Result,Duration,Issue Date\n" +
				"Basic Tailoring,Niño Dela Cruz,Pass,60,2026-01-05\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Niño Dela Cruz", Course: "Basic Tailoring", Hours: 60, Grade: "Pass", IssuedOn: "2026-01-05"},
			},
		},
		{
			name: "byte order mark from a spreadsheet export",
			in:   "\ufeffLearner Name,Course\nAsha Kumari,Welding\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding", IssuedOn: today},
			},
		},
		{
			name: "optional columns absent fall back to defaults",
			in:   "learner_name,course\nAsha Kumari,Welding\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding", Hours: 0, Grade: "", IssuedOn: today},
			},
		},
		{
			name: "blank cells fall back to defaults",
			in:   "learner_name,course,hours,grade,issued_on\nAsha Kumari,Welding,,,\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding", IssuedOn: today},
			},
		},
		{
			name: "blank lines are skipped and line numbers still point at the file",
			in:   "learner_name,course\n\nAsha Kumari,Welding\n , \nRavi Patil,Welding\n",
			want: []cert.BatchRow{
				{Line: 3, LearnerName: "Asha Kumari", Course: "Welding", IssuedOn: today},
				{Line: 5, LearnerName: "Ravi Patil", Course: "Welding", IssuedOn: today},
			},
		},
		{
			name: "whitespace is collapsed",
			in:   "learner_name,course\n\"  Asha   Kumari \",\" Arc  Welding \"\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Arc Welding", IssuedOn: today},
			},
		},
		{
			name: "quoted field containing a comma",
			in:   "learner_name,course\nAsha Kumari,\"Welding, advanced\"\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding, advanced", IssuedOn: today},
			},
		},
		{
			name: "bad rows report their own problems and do not stop the file",
			in: "learner_name,course,hours,issued_on\n" +
				",Welding,10,2026-02-10\n" +
				"Asha Kumari,,10,2026-02-10\n" +
				"Ravi Patil,Welding,ten,2026-02-10\n" +
				"Meena Rao,Welding,10.5,2026-02-10\n" +
				"Sunil Das,Welding,-4,2026-02-10\n" +
				"Lata Shah,Welding,10,2026-02-30\n" +
				"Hari Singh,Welding,10,10-02-2026\n" +
				"Gita Roy,Welding,10,2026-02-10\n",
			want: []cert.BatchRow{
				{Line: 2, Course: "Welding", Hours: 10, IssuedOn: "2026-02-10", Problems: []string{"Learner name is empty."}},
				{Line: 3, LearnerName: "Asha Kumari", Hours: 10, IssuedOn: "2026-02-10", Problems: []string{"Course is empty."}},
				{Line: 4, LearnerName: "Ravi Patil", Course: "Welding", IssuedOn: "2026-02-10", Problems: []string{`Hours "ten" is not a whole number of hours.`}},
				{Line: 5, LearnerName: "Meena Rao", Course: "Welding", IssuedOn: "2026-02-10", Problems: []string{`Hours "10.5" is not a whole number of hours.`}},
				{Line: 6, LearnerName: "Sunil Das", Course: "Welding", IssuedOn: "2026-02-10", Problems: []string{`Hours "-4" is not a whole number of hours.`}},
				{Line: 7, LearnerName: "Lata Shah", Course: "Welding", Hours: 10, IssuedOn: "2026-02-30", Problems: []string{`Issue date: "2026-02-30" is not a date in YYYY-MM-DD form`}},
				{Line: 8, LearnerName: "Hari Singh", Course: "Welding", Hours: 10, IssuedOn: "10-02-2026", Problems: []string{`Issue date: "10-02-2026" is not a date in YYYY-MM-DD form`}},
				{Line: 9, LearnerName: "Gita Roy", Course: "Welding", Hours: 10, IssuedOn: "2026-02-10"},
			},
		},
		{
			name: "hours over the cap",
			in:   "learner_name,course,hours\nAsha Kumari,Welding,100001\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding", IssuedOn: today, Problems: []string{"Hours cannot exceed 100000."}},
			},
		},
		{
			name: "short rows are padded rather than dropped",
			in:   "learner_name,course,hours,grade,issued_on\nAsha Kumari,Welding\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding", IssuedOn: today},
			},
		},
		{
			name: "leap day is accepted",
			in:   "learner_name,course,issued_on\nAsha Kumari,Welding,2024-02-29\n",
			want: []cert.BatchRow{
				{Line: 2, LearnerName: "Asha Kumari", Course: "Welding", IssuedOn: "2024-02-29"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cert.ParseBatchCSV(strings.NewReader(tc.in), today)
			if err != nil {
				t.Fatalf("ParseBatchCSV: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d\ngot: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Line != tc.want[i].Line ||
					got[i].LearnerName != tc.want[i].LearnerName ||
					got[i].Course != tc.want[i].Course ||
					got[i].Hours != tc.want[i].Hours ||
					got[i].Grade != tc.want[i].Grade ||
					got[i].IssuedOn != tc.want[i].IssuedOn {
					t.Errorf("row %d:\n got %+v\nwant %+v", i, got[i], tc.want[i])
				}
				if strings.Join(got[i].Problems, " | ") != strings.Join(tc.want[i].Problems, " | ") {
					t.Errorf("row %d problems:\n got %v\nwant %v", i, got[i].Problems, tc.want[i].Problems)
				}
				if got[i].OK() != (len(tc.want[i].Problems) == 0) {
					t.Errorf("row %d OK() = %v, want %v", i, got[i].OK(), len(tc.want[i].Problems) == 0)
				}
			}
		})
	}
}

func TestParseBatchCSVRejectsUnusableFiles(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		mentions string
	}{
		{"empty file", "", "empty"},
		{"header only", "learner_name,course\n", "no learner rows"},
		{"header only with blank lines", "learner_name,course\n\n\n", "no learner rows"},
		{"no learner column", "course,hours\nWelding,10\n", "learner_name"},
		{"no course column", "learner_name,hours\nAsha,10\n", "course"},
		{"unrecognised header", "a,b,c\n1,2,3\n", "learner_name"},
		{"ragged quoting", "learner_name,course\n\"unterminated,Welding\n", "CSV"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := cert.ParseBatchCSV(strings.NewReader(tc.in), "2026-03-14")
			if err == nil {
				t.Fatalf("ParseBatchCSV accepted an unusable file, returning %+v", rows)
			}
			if !strings.Contains(err.Error(), tc.mentions) {
				t.Fatalf("error %q does not mention %q", err, tc.mentions)
			}
		})
	}
}

// TestBatchRowsIssueEndToEnd checks the batch path produces certificates that
// verify, which is the only outcome that matters to the institute.
func TestBatchRowsIssueEndToEnd(t *testing.T) {
	k, err := cert.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	rows, err := cert.ParseBatchCSV(strings.NewReader(
		"learner_name,course,hours,grade,issued_on\n"+
			"Asha Kumari,Arc Welding Level 2,120,A,2026-02-10\n"+
			"Niño Dela Cruz,Basic Tailoring,60,Pass,2026-02-11\n"), "2026-03-14")
	if err != nil {
		t.Fatalf("ParseBatchCSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	for i, row := range rows {
		if !row.OK() {
			t.Fatalf("row %d reported problems: %v", row.Line, row.Problems)
		}
		signed, problems := cert.Issue(cert.Certificate{
			ID:          cert.FormatID("ASI", 2026, i+1),
			LearnerName: row.LearnerName,
			Course:      row.Course,
			Hours:       row.Hours,
			Grade:       row.Grade,
			IssuedOn:    row.IssuedOn,
			IssuerName:  "Acme Skills Institute",
		}, k)
		if len(problems) > 0 {
			t.Fatalf("row %d did not issue: %v", row.Line, problems)
		}
		res := cert.VerifyCode(signed.Code, k.PublicKeyString())
		if !res.Pass {
			t.Fatalf("row %d certificate did not verify: %s", row.Line, res.Reason)
		}
		if res.Certificate.LearnerName != row.LearnerName {
			t.Errorf("row %d verified a different learner: %q", row.Line, res.Certificate.LearnerName)
		}
	}
}
