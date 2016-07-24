package authenticator

import "testing"

const codeLen = 5

func TestGenerateAuthCodeLength(t *testing.T) {
	var tests = []struct {
		shared string
		timer  func() uint64
	}{
		{"2rm61wyGHj0CIj2KheSKHV3GZ1E=", nil},
	}

	for _, test := range tests {
		code, err := GenerateAuthCode(test.shared, test.timer)
		if err != nil {
			t.Errorf("shared = %q: unexpected error", test.shared)
		}
		if len(code) != codeLen {
			t.Errorf("shared = %q: code = %q, got len(code) = %v, want %v", test.shared, code, len(code), codeLen)
		}
	}
}

func TestGenerateAuthCodeError(t *testing.T) {
	var tests = []struct {
		shared string
		timer  func() uint64
	}{
		{"", nil},
		{"invalid secret", nil},
	}

	for _, test := range tests {
		code, err := GenerateAuthCode(test.shared, test.timer)
		if err == nil {
			t.Errorf("shared = %q: got err = %v, want nil", test.shared, err)
		}
		if code != "" {
			t.Errorf("shared = %q: got code = %v, want \"\"", test.shared, code)
		}
	}
}
