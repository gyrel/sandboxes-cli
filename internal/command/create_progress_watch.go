package command

import (
	"context"
	"fmt"
	"sync"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

// startCreateProgressWatch opens the best-effort resilient Watch follower
// (reconnect/resume across transport drops) for a blocking create and returns its stop function. Calling stop cancels the
// stream and joins the follower; it is safe to call more than once.
func startCreateProgressWatch(ctx context.Context, client sdk.Client, name string, progress *deployProgress) (stop func()) {
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := sdk.WatchResilient(watchCtx, client, sdk.WatchOptions{})
		if err != nil {
			return
		}
		defer func() { _ = stream.Close() }()
		followCreateProgress(stream, name, progress.setDetail)
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// followCreateProgress consumes a sandbox Watch stream until it errors or
// closes and forwards matching pull progress to the spinner detail callback.
// Correlation model: the create RPC blocks, so the follower first learns the
// generated sandbox id from a sandbox event carrying the requested name, then
// accepts operation events for that id. Every failure ends the follower
// silently: the indicator is cosmetic and older daemons emit no progress.
func followCreateProgress(stream sdk.EventStream, name string, setDetail func(string)) {
	watchedID := ""
	for {
		event, err := stream.Recv()
		if err != nil || event == nil {
			return
		}
		switch {
		case event.Sandbox != nil && watchedID == "" && event.Sandbox.Name == name:
			watchedID = event.Sandbox.ID
		case event.Operation != nil && watchedID != "" && event.Operation.SandboxID == watchedID:
			progress := event.Operation.Progress
			if progress != nil && progress.Total > 0 && progress.Phase == "pulling" {
				setDetail(fmt.Sprintf("%d/%d layers", progress.Completed, progress.Total))
			}
		}
	}
}
