package matcher

import (
	"strconv"
	"strings"

	"github.com/irify/irify-benchmark/pkg/schema"
)

// caseExpectedCWE returns the CWE this case declares it expects to be detected
// as, normalised to the canonical "CWE-<id>" form. An empty result means the
// case does not constrain by CWE (legacy / informational cases): the matcher
// then considers every finding as a candidate, preserving backward-compatible
// behaviour.
func caseExpectedCWE(c schema.Case) string {
	if c.Metadata == nil {
		return ""
	}
	return normaliseCWE(c.Metadata.CWE)
}

// cweMatches reports whether a finding's CWE falls within the scope declared by
// a case. A case with no declared CWE (empty caseCWE) is lenient and matches
// any finding so that unconstrained cases keep their historical behaviour. A
// finding with an empty CWE is considered out-of-scope whenever the case
// declares one, so unmapped noise cannot win a best-candidate slot.
func cweMatches(caseCWE, findingCWE string) bool {
	if caseCWE == "" {
		return true
	}
	return normaliseCWE(caseCWE) == normaliseCWE(findingCWE) && findingCWE != ""
}

// normaliseCWE collapses the assorted CWE spellings engines emit into a single
// canonical "CWE-<id>" token: "CWE-89", "cwe-89", "  CWE-89  ", and the bare
// number "89" all map to "CWE-89". Empty / non-numeric input maps to "".
func normaliseCWE(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, pfx := range []string{"CWE-", "cwe-"} {
		if rest := strings.TrimPrefix(s, pfx); rest != s {
			return "CWE-" + strings.TrimSpace(rest)
		}
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "CWE-" + s
	}
	return s
}