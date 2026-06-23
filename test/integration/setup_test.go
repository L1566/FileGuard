package integration

import (
	"os"
	"testing"

	"github.com/L1566/FileGuard/pkg/logger"
)

func TestMain(m *testing.M) {
	logger.Init("error", "text")
	os.Exit(m.Run())
}
