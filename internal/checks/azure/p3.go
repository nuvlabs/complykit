package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/complykit/complykit/internal/engine"
)

// ── VM Trusted Launch / Secure Boot ──────────────────────────────────────────

func (c *Checker) checkVMTrustedLaunch() []engine.Finding {
	client, err := armcompute.NewVirtualMachinesClient(c.subscriptionID, c.cred, nil)
	if err != nil {
		return []engine.Finding{skip("az_vm_trusted_launch", "Azure VM Trusted Launch", err.Error())}
	}
	pager := client.NewListAllPager(nil)
	var noTrustedLaunch []string
	hasAny := false

	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return []engine.Finding{skip("az_vm_trusted_launch", "Azure VM Trusted Launch", err.Error())}
		}
		for _, vm := range page.Value {
			hasAny = true
			name := ptrStr(vm.Name)
			if vm.Properties == nil ||
				vm.Properties.SecurityProfile == nil ||
				vm.Properties.SecurityProfile.SecurityType == nil ||
				*vm.Properties.SecurityProfile.SecurityType != armcompute.SecurityTypesTrustedLaunch {
				noTrustedLaunch = append(noTrustedLaunch, name)
			}
		}
	}

	if !hasAny {
		return nil
	}
	if len(noTrustedLaunch) == 0 {
		return []engine.Finding{pass("az_vm_trusted_launch", "All VMs use Trusted Launch (Secure Boot enabled)",
			soc2("CC6.6"), cis("7.5"))}
	}
	return []engine.Finding{fail(
		"az_vm_trusted_launch",
		fmt.Sprintf("%d VM(s) without Trusted Launch: %v", len(noTrustedLaunch), truncate(noTrustedLaunch, 5)),
		engine.SeverityLow,
		"Enable Trusted Launch on VM (requires re-creation for existing VMs):\n  az vm create --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true",
		soc2("CC6.6"), cis("7.5"),
	)}
}
