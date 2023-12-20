package ipc_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/beeper/imessage/ipc"
)

func TestError_Is(t *testing.T) {
	var err error = ipc.Error{Code: "not_found"}
	if !errors.Is(err, ipc.ErrNotFound) {
		t.Error("errors.Is() returned false for an error with the same code")
	}
	if errors.Is(err, ipc.Error{Code: "test"}) {
		t.Error("errors.Is() returned true for an error with a different code")
	}
	if errors.Is(err, errors.New("not_found")) {
		t.Error("errors.Is() returned true for an unrelated error")
	}

	var err2 ipc.Error
	err = json.Unmarshal([]byte(`{"code": "timeout", "message": "Request timed out"}`), &err2)
	if err != nil {
		t.Error("Failed to unmarshal error:", err)
	}
	if !errors.Is(err2, ipc.ErrTimeoutError) {
		t.Error("errors.Is() returned false for an error with the same code")
	}
}
