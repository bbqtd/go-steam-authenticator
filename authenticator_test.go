package authenticator

import "testing"

func TestNewAuthenticator(t *testing.T) {
	var tests = []struct {
		shared   string
		identity string
		want     *Authenticator
	}{
		{"", "", nil},
		{"", "9rm61wyGHjadbw0KheSKHV3GZ1E=", nil},
		{"2rm61wyGHj0CIj2KheSKHV3GZ1E=", "", nil},
		{"thisShouldBeWrong", "someOthercase=", nil},
		{"but this wrong", "9rm61wyGHjadbw0KheSKHV3GZ1E=", nil},
		{"2rm61wyGHj0CIj2KheSKHV3GZ1E=", "but this wrong", nil},
	}

	for _, test := range tests {
		a, _ := New(test.shared, test.identity, nil)
		if a != nil {
			t.Errorf("shared = %q, identity = %q: got %#v, want %#v", test.shared, test.identity, a, test.want)
		}
	}
}
