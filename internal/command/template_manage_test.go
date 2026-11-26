package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type fakeTemplateService struct {
	sdk.TemplateService
	saves   []string
	loads   []string
	removes []string
	exports []string
}

func (f *fakeTemplateService) Save(_ context.Context, id, tag, output string) (sdk.TemplateSaveResult, error) {
	f.saves = append(f.saves, id+"|"+tag+"|"+output)
	return sdk.TemplateSaveResult{
		Template: sdk.Template{Name: "docker.io/library/" + tag, Layers: 18, SizeBytes: 70254080},
		Notice:   "warning: guest-resident secrets",
	}, nil
}

func (f *fakeTemplateService) Load(_ context.Context, tar, name string) (sdk.Template, error) {
	f.loads = append(f.loads, tar+"|"+name)
	return sdk.Template{Name: "docker.io/library/loaded:v1", Layers: 12, SizeBytes: 2048}, nil
}

func (f *fakeTemplateService) Remove(_ context.Context, name string, force bool) (bool, error) {
	f.removes = append(f.removes, name+"|")
	if force {
		f.removes[len(f.removes)-1] += "f"
	}
	return true, nil
}

func (f *fakeTemplateService) Export(_ context.Context, name, path string) (int64, error) {
	f.exports = append(f.exports, name+"|"+path)
	return 4096, nil
}

type templateProviderClient struct {
	fakeClient
	tmpl *fakeTemplateService
}

func (c templateProviderClient) TemplateService() sdk.TemplateService { return c.tmpl }

func newTemplateCommandRunner(t *testing.T, tmpl *fakeTemplateService) (*Runner, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("y\n"), NewClient: func(string) (sdk.Client, error) {
		return templateProviderClient{
			fakeClient: fakeClient{sandbox: &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}},
			tmpl:       tmpl,
		}, nil
	}}
	return runner, &out
}

func TestTemplateCommandsDriveSDK(t *testing.T) {
	tmpl := &fakeTemplateService{}
	runner, out := newTemplateCommandRunner(t, tmpl)
	ctx := context.Background()
	if code := runner.Run(ctx, []string{"template", "save", "dev", "mytpl:v1", "--output", "/tmp/t.tar"}); code != 0 {
		t.Fatalf("save exit=%d out=%q", code, out.String())
	}
	if len(tmpl.saves) != 1 || tmpl.saves[0] != "sb-1|mytpl:v1|/tmp/t.tar" {
		t.Fatalf("saves=%v", tmpl.saves)
	}
	if !strings.Contains(out.String(), "Saved template docker.io/library/mytpl:v1") || !strings.Contains(out.String(), "67.0 MiB") {
		t.Fatalf("save output=%q", out.String())
	}
	if !strings.Contains(out.String(), "guest-resident secrets") {
		t.Fatalf("notice missing: %q", out.String())
	}
	out.Reset()
	if code := runner.Run(ctx, []string{"template", "load", "/tmp/x.tar", "alias"}); code != 0 {
		t.Fatalf("load exit=%d out=%q", code, out.String())
	}
	if len(tmpl.loads) != 1 || tmpl.loads[0] != "/tmp/x.tar|alias" {
		t.Fatalf("loads=%v", tmpl.loads)
	}
	out.Reset()
	if code := runner.Run(ctx, []string{"template", "export", "docker.io/library/mytpl:v1", "/tmp/e.tar"}); code != 0 {
		t.Fatalf("export exit=%d out=%q", code, out.String())
	}
	if len(tmpl.exports) != 1 || tmpl.exports[0] != "docker.io/library/mytpl:v1|/tmp/e.tar" {
		t.Fatalf("exports=%v", tmpl.exports)
	}
	if !strings.Contains(out.String(), "Exported") || !strings.Contains(out.String(), "4.0 KiB") {
		t.Fatalf("export output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(ctx, []string{"template", "rm", "mytpl:v1", "-f"}); code != 0 {
		t.Fatalf("rm exit=%d out=%q", code, out.String())
	}
	if len(tmpl.removes) != 1 || !strings.HasSuffix(tmpl.removes[0], "|f") {
		t.Fatalf("removes=%v", tmpl.removes)
	}
}

func TestTemplateHelpListsManagementCommands(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
	if code := runner.Run(context.Background(), []string{"template", "--help"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	help := out.String()
	for _, name := range []string{"export", "inspect", "load", "ls", "rm", "save"} {
		if !strings.Contains(help, "\n  "+name+" ") {
			t.Fatalf("template help lacks %q command: %q", name, help)
		}
	}
	for _, stale := range []string{"not implemented", "does not snapshot", "lists and inspects"} {
		if strings.Contains(help, stale) {
			t.Fatalf("template help still claims %q: %q", stale, help)
		}
	}
}

func TestTemplateRemoveConfirmation(t *testing.T) {
	tmpl := &fakeTemplateService{}
	runner, out := newTemplateCommandRunner(t, tmpl)
	runner.In = strings.NewReader("n\n")
	if code := runner.Run(context.Background(), []string{"template", "rm", "mytpl:v1"}); code != 0 {
		t.Fatalf("canceled rm exit=%d", code)
	}
	if len(tmpl.removes) != 0 {
		t.Fatalf("answered no must not remove: %v", tmpl.removes)
	}
	if !strings.Contains(out.String(), "Removal canceled") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestTemplateCommandsUsageErrors(t *testing.T) {
	tmpl := &fakeTemplateService{}
	runner, _ := newTemplateCommandRunner(t, tmpl)
	for _, args := range [][]string{
		{"template", "save", "only-one"},
		{"template", "load"},
		{"template", "rm"},
		{"template", "export", "one"},
	} {
		if code := runner.Run(context.Background(), args); code != 2 {
			t.Fatalf("%v exit=%d want 2", args, code)
		}
	}
	if len(tmpl.saves)+len(tmpl.loads)+len(tmpl.removes)+len(tmpl.exports) != 0 {
		t.Fatal("usage errors reached the daemon")
	}
}
