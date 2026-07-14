package flowmatch

import "testing"

func TestNormalizeIRSymbol(t *testing.T) {
	tests := []struct {
		name string
		ir   string
		want string
	}{
		{"Undefined prefix stripped", "Undefined-stmt.executeQuery(Undefined-con.createStatement)", "stmt.executeQuery"},
		{"ParameterMember prefix + array subscript stripped", "ParameterMember-parameter[1].getParameter(Parameter-req,\"name\")", "parameter.getParameter"},
		{"Parameter prefix stripped", "Parameter-req", "req"},
		{"lowercase toLowerCase", "Undefined-s.toLowerCase", "s.toLowerCase"},
		{"plain source symbol preserved", "stmt.execute", "stmt.execute"},
		{"single method name", "executeQuery", "executeQuery"},
		{"empty input", "", ""},
		{"whitespace trimmed", "  Undefined-stmt.executeQuery()  ", "stmt.executeQuery"},
		{"Function prefix stripped", "Function-FileController.download", "FileController.download"},
		{"method name with no args no receiver", "getParameter", "getParameter"},
		{"nested call args stripped", "Undefined-stmt.executeQuery(add(\"select * from Users\", Undefined-s.toLowerCase))", "stmt.executeQuery"},
		{"dash separator normalised to dot", "Files-readAllBytes", "Files.readAllBytes"},
		{"dash separator with existing dot untouched", "stmt.executeQuery-other", "stmt.executeQuery-other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeIRSymbol(tt.ir); got != tt.want {
				t.Errorf("NormalizeIRSymbol(%q) = %q, want %q", tt.ir, got, tt.want)
			}
		})
	}
}

func TestMethodName(t *testing.T) {
	tests := []struct {
		symbol string
		want   string
	}{
		{"stmt.executeQuery", "executeQuery"},
		{"req.getParameter", "getParameter"},
		{"executeQuery", "executeQuery"},
		{"", ""},
		{"parameter.getParameter", "getParameter"},
	}
	for _, tt := range tests {
		if got := MethodName(tt.symbol); got != tt.want {
			t.Errorf("MethodName(%q) = %q, want %q", tt.symbol, got, tt.want)
		}
	}
}

func TestSymbolContainsMethod(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		finding  string
		want     bool
	}{
		{"method substring in finding IR", "req.getParameter", "ParameterMember-parameter[1].getParameter(Parameter-req,\"name\")", true},
		{"exact receiver.method match", "stmt.executeQuery", "Undefined-stmt.executeQuery(...)", true},
		{"case insensitive", "Req.GetParameter", "parameter[1].getParameter", true},
		{"different method no match", "stmt.execute", "Undefined-stmt.executeQuery", false},
		{"empty expected no match", "", "executeQuery", false},
		{"empty finding no match", "executeQuery", "", false},
		{"hardcoded sink match", "con.prepareStatement", "Undefined-con.prepareStatement", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SymbolContainsMethod(tt.expected, tt.finding); got != tt.want {
				t.Errorf("SymbolContainsMethod(%q, %q) = %v, want %v", tt.expected, tt.finding, got, tt.want)
			}
		})
	}
}