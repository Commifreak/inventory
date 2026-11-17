package agent

import (
	"context"

	"github.com/commifreak/inventory/internal/protocol"
)

// darwinStorageAndMemory fills storage controllers and memory modules from
// system_profiler (no SMBIOS access on macOS).
func darwinStorageAndMemory(ctx context.Context, hw *protocol.HardwareInfo) error {
	out, err := runCmd(ctx, "system_profiler", "SPNVMeDataType", "SPSerialATADataType", "SPMemoryDataType", "-json")
	if err != nil {
		return err
	}
	parseSystemProfilerStorage(out, hw)
	return nil
}
