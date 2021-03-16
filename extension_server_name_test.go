package dtls

import "testing"

func TestServerName(t *testing.T) {
	extension := ExtensionServerName{ServerName: "test.domain"}

	raw, err := extension.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	newExtension := ExtensionServerName{}
	err = newExtension.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	if newExtension.ServerName != extension.ServerName {
		t.Errorf("extensionServerName marshal: got %s expected %s", newExtension.ServerName, extension.ServerName)
	}
}
