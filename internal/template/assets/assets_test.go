package assets

import "testing"

func Test_GetAssets(t *testing.T) {
	for _, name := range []string{"resources/favicon.ico", "resources/logo.png", "resources/styles.css"} {
		t.Run(name, func(t *testing.T) {
			content, readError := GetAssets().ReadFile(name)
			if readError != nil {
				t.Fatalf("Expected embedded asset, got %v", readError)
			}
			if len(content) == 0 {
				t.Error("Expected non empty asset")
			}
		})
	}
}
