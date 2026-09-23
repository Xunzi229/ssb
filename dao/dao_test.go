package dao

import "testing"

func TestChannelsReadyBeforeRun(t *testing.T) {
	if TipChan == nil || StopChan == nil || MsgChan == nil {
		t.Fatal("channel is nil before Run")
	}
}
