package cert_test

import (
	"strings"
	"testing"

	"github.com/sreenivas-sadhu-prabhakara/verifiable-cert-issuer/internal/cert"
)

func TestValidateDate(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"2026-03-14", true},
		{"2026-01-01", true},
		{"2026-12-31", true},
		{"2024-02-29", true},  // leap year divisible by 4
		{"2000-02-29", true},  // century year divisible by 400
		{"2023-02-29", false}, // not a leap year
		{"1900-02-29", false}, // century year not divisible by 400
		{"2100-02-29", false}, // century year not divisible by 400
		{"2026-02-29", false},
		{"2026-04-31", false}, // April has 30 days
		{"2026-06-31", false},
		{"2026-09-31", false},
		{"2026-11-31", false},
		{"2026-01-32", false},
		{"2026-13-01", false},
		{"2026-00-10", false},
		{"2026-01-00", false},
		{"2026-3-14", false},  // month must be zero padded
		{"2026-03-4", false},  // day must be zero padded
		{"26-03-14", false},   // year must be four digits
		{"14-03-2026", false}, // day-first form is not accepted
		{"2026/03/14", false},
		{"", false},
		{"today", false},
		{"2026-03-14T00:00:00Z", false},
		{" 2026-03-14", false},
		{"2026-03-14 ", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			err := cert.ValidateDate(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("ValidateDate(%q) = %v, want nil", tc.in, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("ValidateDate(%q) = nil, want an error", tc.in)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		in       cert.Certificate
		problems int
		mentions string
	}{
		{"complete", baseCert(), 0, ""},
		{"grade may be empty", with(func(c *cert.Certificate) { c.Grade = "" }), 0, ""},
		{"zero hours allowed", with(func(c *cert.Certificate) { c.Hours = 0 }), 0, ""},
		{"max hours allowed", with(func(c *cert.Certificate) { c.Hours = cert.MaxHours }), 0, ""},
		{"missing id", with(func(c *cert.Certificate) { c.ID = "" }), 1, "Certificate number"},
		{"missing learner", with(func(c *cert.Certificate) { c.LearnerName = "" }), 1, "Learner name"},
		{"missing course", with(func(c *cert.Certificate) { c.Course = "" }), 1, "Course name"},
		{"negative hours", with(func(c *cert.Certificate) { c.Hours = -1 }), 1, "negative"},
		{"hours over the cap", with(func(c *cert.Certificate) { c.Hours = cert.MaxHours + 1 }), 1, "exceed"},
		{"bad date", with(func(c *cert.Certificate) { c.IssuedOn = "2026-02-30" }), 1, "Issue date"},
		{"empty date", with(func(c *cert.Certificate) { c.IssuedOn = "" }), 1, "Issue date is required"},
		{"missing institute", with(func(c *cert.Certificate) { c.IssuerName = "" }), 1, "Institute name"},
		{"missing key", with(func(c *cert.Certificate) { c.IssuerPubKey = "" }), 1, "public key is required"},
		{"bad key", with(func(c *cert.Certificate) { c.IssuerPubKey = "nope" }), 1, "public key"},
		{"over-long learner name", with(func(c *cert.Certificate) {
			c.LearnerName = strings.Repeat("N", cert.MaxNameLen+1)
		}), 1, "Learner name is longer"},
		{"over-long course", with(func(c *cert.Certificate) {
			c.Course = strings.Repeat("C", cert.MaxCourseLen+1)
		}), 1, "Course name is longer"},
		{"over-long grade", with(func(c *cert.Certificate) {
			c.Grade = strings.Repeat("G", cert.MaxGradeLen+1)
		}), 1, "Grade is longer"},
		{"over-long id", with(func(c *cert.Certificate) {
			c.ID = strings.Repeat("1", cert.MaxIDLen+1)
		}), 1, "Certificate number is longer"},
		{"everything empty", cert.Certificate{}, 6, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cert.Validate(tc.in)
			if len(got) != tc.problems {
				t.Fatalf("Validate reported %d problems %v, want %d", len(got), got, tc.problems)
			}
			if tc.mentions != "" && !strings.Contains(strings.Join(got, " | "), tc.mentions) {
				t.Fatalf("problems %v do not mention %q", got, tc.mentions)
			}
		})
	}
}

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   cert.Certificate
		want cert.Certificate
	}{
		{
			name: "trims and collapses whitespace",
			in: cert.Certificate{
				ID: "  ASI-2026-00001 ", LearnerName: "Asha\t\tKumari", Course: " Arc  Welding ",
				Hours: 120, Grade: " A ", IssuedOn: " 2026-03-14 ", IssuerName: "Acme\nSkills\nInstitute",
				IssuerPubKey: "  " + zeroKey + "\n",
			},
			want: cert.Certificate{
				ID: "ASI-2026-00001", LearnerName: "Asha Kumari", Course: "Arc Welding",
				Hours: 120, Grade: "A", IssuedOn: "2026-03-14", IssuerName: "Acme Skills Institute",
				IssuerPubKey: zeroKey,
			},
		},
		{
			name: "whitespace-only fields become empty",
			in:   cert.Certificate{LearnerName: "   ", Course: "\t\n", Grade: " "},
			want: cert.Certificate{},
		},
		{
			name: "already clean is unchanged",
			in:   baseCert(),
			want: baseCert(),
		},
		{
			name: "collapses runs inside non-latin text",
			in:   cert.Certificate{LearnerName: "आशा   कुमारी"},
			want: cert.Certificate{LearnerName: "आशा कुमारी"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cert.Clean(tc.in)
			if got != tc.want {
				t.Fatalf("Clean:\n got %+v\nwant %+v", got, tc.want)
			}
			if again := cert.Clean(got); again != got {
				t.Fatalf("Clean is not idempotent:\n got %+v\nwant %+v", again, got)
			}
		})
	}
}

func TestIssuerCode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Acme Skills Institute", "ASI"},
		{"acme skills institute", "ASI"},
		{"Barangay Skills Centre Taguig", "BSC"},
		{"Bharat", "B"},
		{"Bharat Technical", "BT"},
		{"  spaced   out   name  ", "SON"},
		{"", "CERT"},
		{"   ", "CERT"},
		{"आशा कुमारी", "CERT"},
		{"123 456", "CERT"},
		{"3M Welding School", "MWS"},
		{"St. Mary's Trade School", "SMT"},
		{"a-b c", "AC"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got := cert.IssuerCode(tc.in)
			if got != tc.want {
				t.Fatalf("IssuerCode(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if len(got) < 1 || len(got) > 4 {
				t.Fatalf("IssuerCode(%q) = %q, which is not a short prefix", tc.in, got)
			}
		})
	}
}

func TestFormatID(t *testing.T) {
	tests := []struct {
		prefix string
		year   int
		seq    int
		want   string
	}{
		{"ASI", 2026, 1, "ASI-2026-00001"},
		{"ASI", 2026, 7, "ASI-2026-00007"},
		{"ASI", 2026, 99999, "ASI-2026-99999"},
		{"ASI", 2026, 100000, "ASI-2026-100000"},
		{"ASI", 2026, 0, "ASI-2026-00001"},
		{"ASI", 2026, -3, "ASI-2026-00001"},
		{"", 2026, 4, "CERT-2026-00004"},
		{"BSC", 2027, 12, "BSC-2027-00012"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := cert.FormatID(tc.prefix, tc.year, tc.seq); got != tc.want {
				t.Fatalf("FormatID(%q, %d, %d) = %q, want %q", tc.prefix, tc.year, tc.seq, got, tc.want)
			}
		})
	}
}

func TestFormatIDFitsTheIDLengthCap(t *testing.T) {
	id := cert.FormatID("CERT", 2026, 999999)
	if len(id) > cert.MaxIDLen {
		t.Fatalf("generated id %q is longer than the %d-character cap", id, cert.MaxIDLen)
	}
	if problems := cert.Validate(with(func(c *cert.Certificate) { c.ID = id })); len(problems) != 0 {
		t.Fatalf("a generated id failed validation: %v", problems)
	}
}
