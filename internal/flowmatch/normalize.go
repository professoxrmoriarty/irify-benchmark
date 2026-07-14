// Package flowmatch holds the shared source/sink symbol normalisation and
// precise flow-matching logic used by both the matcher and the diagnose layer.
//
// Yak SyntaxFlow reports findings whose symbols are SSA IR toString strings
// (e.g. "Undefined-stmt.executeQuery(...)" or
// "ParameterMember-parameter[1].getParameter(Parameter-req,\"name\")") rather
// than source-code symbols (e.g. "stmt.executeQuery"). These helpers collapse
// the SSA forms back into a receiver.method shape so the matcher can compare
// them against case annotations by method name.
package flowmatch

import (
	"strings"
)

// ssaPrefixes are the leading SSA type tags yak emits before a `-` separator.
// They carry no source-level meaning and are stripped during normalisation.
var ssaPrefixes = []string{
	"Undefined-", "ParameterMember-", "Parameter-", "Function-",
	"Call-", "Load-", "Store-", "Const-", "Variable-", "Phi-", "Make-",
}

// NormalizeIRSymbol collapses a yak SSA IR toString string into a
// source-code-style "receiver.method" symbol (or just "method" when no
// receiver can be recovered). It is the single source of truth for symbol
// normalisation shared by the matcher and diagnose layers.
//
// Examples:
//
//	"Undefined-stmt.executeQuery(...)"            -> "stmt.executeQuery"
//	"ParameterMember-parameter[1].getParameter(...)" -> "parameter.getParameter"
//	"Undefined-s.toLowerCase"                     -> "s.toLowerCase"
//	"stmt.execute"                                -> "stmt.execute"
//	"getParameter"                                -> "getParameter"
//	""                                            -> ""
func NormalizeIRSymbol(irCode string) string {
	s := strings.TrimSpace(irCode)
	if s == "" {
		return ""
	}

	// Strip SSA type prefix (only the leading segment before the first '-',
	// and only when that segment matches a known SSA tag, so method names that
	// legitimately contain '-' are not corrupted).
	for _, pfx := range ssaPrefixes {
		if strings.HasPrefix(s, pfx) {
			s = strings.TrimSpace(s[len(pfx):])
			break
		}
	}

	// Strip call arguments: remove all "(...)" argument groups so that
	// chained calls like "Runtime.getRuntime().exec" survive as
	// "Runtime.getRuntime.exec" (keeping the trailing .exec method that the
	// first-'(' truncation would have dropped). A simple first-'(' cut is
	// wrong for chained zero-arg calls because it stops at the intermediate
	// "getRuntime(" and loses ".exec".
	s = stripCallArgs(s)

	// Strip SSA array-index subscripts: "parameter[1].getParameter" -> "parameter.getParameter".
	s = stripArraySubscripts(s)

	// yak sometimes separates receiver and method with '-' instead of '.'
	// (e.g. "Files-readAllBytes"). Normalise to '.' so the symbol matches
	// source-style annotations ("Files.readAllBytes") and MethodName can
	// extract the trailing method segment. Only convert the first '-' that
	// splits two identifier-like halves, so method names that legitimately
	// contain '-' are not corrupted.
	s = normaliseDashSeparator(s)

	// Strip any residual SSA decorations such as quoted string literals.
	s = strings.Trim(s, "\"'` ")

	// If a receiver.method form survives, keep it; otherwise return whatever
	// method name remains (already trimmed of args and subscripts).
	return s
}

// MethodName returns the final method segment of a source-code-style symbol,
// i.e. the part after the last '.'. This is the stable key used for symbol
// matching because yak's SSA receiver names (e.g. "parameter") differ from
// source receiver names (e.g. "req") while the method name (e.g.
// "getParameter") is preserved.
//
//	"stmt.executeQuery"  -> "executeQuery"
//	"req.getParameter"   -> "getParameter"
//	"executeQuery"       -> "executeQuery"
//	""                   -> ""
func MethodName(symbol string) string {
	s := strings.TrimSpace(symbol)
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ".")
	return strings.TrimSpace(parts[len(parts)-1])
}

// SymbolContainsMethod reports whether the method name extracted from the
// expected source symbol appears as a method-segment of the normalised
// finding symbol. This is the symbol-matching predicate for precise flow
// matching: yak's SSA toString may wrap the real call but the method name
// survives verbatim inside it.
//
// The match is segment-aware: "execute" does NOT match "executeQuery" even
// though it is a substring, because they are different method names. A method
// segment is delimited by '.' boundaries or the string start/end, so
// "getParameter" matches "parameter.getParameter" but "execute" does not
// match "stmt.executeQuery".
//
// Both arguments are normalised first so callers can pass raw IR or
// source-style symbols interchangeably.
func SymbolContainsMethod(expectedSource, findingIR string) bool {
	method := MethodName(NormalizeIRSymbol(expectedSource))
	if method == "" {
		return false
	}
	normalisedFinding := NormalizeIRSymbol(findingIR)
	if normalisedFinding == "" {
		return false
	}
	return containsMethodSegment(strings.ToLower(normalisedFinding), strings.ToLower(method))
}

// containsMethodSegment reports whether method appears as a complete '.'
// delimited segment of symbol, not merely as a substring. This prevents
// "execute" from matching "executeQuery".
func containsMethodSegment(symbol, method string) bool {
	if symbol == method {
		return true
	}
	parts := strings.Split(symbol, ".")
	for _, p := range parts {
		if p == method {
			return true
		}
	}
	return false
}

// stripCallArgs removes all "(...)" argument groups from a symbol string,
// preserving the dotted method chain. This handles chained calls where a
// zero-arg method precedes the real sink, e.g. "Runtime.getRuntime().exec"
// -> "Runtime.getRuntime.exec". It also strips call args from the final
// method, e.g. "stmt.executeQuery(sql)" -> "stmt.executeQuery".
func stripCallArgs(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(c)
			}
		}
	}
	return strings.TrimSpace(b.String())
}

// stripArraySubscripts removes "[N]" index subscripts produced by yak's SSA
// parameter numbering, e.g. "parameter[1].getParameter" -> "parameter.getParameter".
func stripArraySubscripts(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '[' {
			// Skip through the matching ']'.
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				break
			}
			i += j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// normaliseDashSeparator converts the first '-' that separates two
// identifier-like halves into '.', so yak's "Files-readAllBytes" becomes
// "Files.readAllBytes". A '-' is only converted when both sides look like
// identifiers (start with a letter/underscore) and there is no '.' already
// present, which avoids corrupting legitimately dashed names.
func normaliseDashSeparator(s string) string {
	if strings.Contains(s, ".") {
		return s
	}
	idx := strings.Index(s, "-")
	if idx <= 0 || idx >= len(s)-1 {
		return s
	}
	left := s[:idx]
	right := s[idx+1:]
	if isIdentStart(left) && isIdentStart(right) {
		return left + "." + right
	}
	return s
}

func isIdentStart(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}