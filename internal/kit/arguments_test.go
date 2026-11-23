package kit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgumentPairs(t *testing.T) {
	tests := []struct {
		item      string
		wantKey   string
		wantValue string
		wantErr   bool
	}{
		{item: "region=eu", wantKey: "region", wantValue: "eu"},
		{item: "region=a=b", wantKey: "region", wantValue: "a=b"},
		{item: "region=", wantKey: "region", wantValue: ""},
		{item: "my-kit.region=us", wantKey: "my-kit.region", wantValue: "us"},
		{item: "a.b.c=1", wantKey: "a.b.c", wantValue: "1"},
		{item: "region", wantErr: true},
		{item: "=eu", wantErr: true},
		{item: "1region=eu", wantErr: true},
		{item: "bad name=eu", wantErr: true},
		{item: ".region=eu", wantErr: true},
		{item: "kit.1bad=eu", wantErr: true},
		{item: "bad kit.region=eu", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.item, func(t *testing.T) {
			key, value, err := parseArgumentPair(tt.item)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err == nil && (key != tt.wantKey || value != tt.wantValue) {
				t.Fatalf("key=%q value=%q", key, value)
			}
		})
	}
}

func TestReadArgumentsFileForms(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name    string
		body    string
		want    map[string]string
		wantErr string
	}{
		{name: "lines", body: "# comment\n\nregion=eu\r\n  tag=v1  \n", want: map[string]string{"region": "eu", "tag": "v1"}},
		{name: "yaml map", body: "region: eu\ncount: 3\n", want: map[string]string{"region": "eu", "count": "3"}},
		{name: "json map", body: `{"region": "eu", "flag": true}`, want: map[string]string{"region": "eu", "flag": "true"}},
		{name: "nested value", body: "region:\n  nested: eu\n", wantErr: "must map a name to a scalar value"},
		{name: "null value", body: "region: ~\n", wantErr: "must map a name to a scalar value"},
		{name: "bad name", body: "1bad: eu\n", wantErr: "must map a name to a scalar value"},
		{name: "bad line", body: "region=eu\nnot-a-pair\n", wantErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadArgumentsFile(write(strings.ReplaceAll(tt.name, " ", "-")+".txt", tt.body))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v want %q", err, tt.wantErr)
				}
				return
			}
			if tt.want == nil {
				if err == nil {
					t.Fatalf("accepted %v", got)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got=%v err=%v want=%v", got, err, tt.want)
			}
		})
	}
}

func TestReadArgumentsFileRejectsDirectoryAndMissing(t *testing.T) {
	if _, err := ReadArgumentsFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory err=%v", err)
	}
	if _, err := ReadArgumentsFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file was accepted")
	}
}

func TestCollectArgumentsFlagsOverrideFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "args.txt")
	if err := os.WriteFile(path, []byte("region=eu\ntag=v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := CollectArguments([]string{path}, []string{"region=us"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]string{"region": "us", "tag": "v1"}) {
		t.Fatalf("got=%v", got)
	}
	if _, err := CollectArguments(nil, []string{"bogus"}); err == nil {
		t.Fatal("malformed --kit-arg was accepted")
	}
}
