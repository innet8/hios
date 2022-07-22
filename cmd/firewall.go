package cmd

import (
	"github.com/innet8/hios/install"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

// firewallCmd represents the firewall command
var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Firewall",
	PreRun: func(cmd *cobra.Command, args []string) {
		install.FirewallConfig.Mode = strings.ToLower(install.FirewallConfig.Mode)
		if !install.InArray(install.FirewallConfig.Mode, []string{"install", "uninstall", "check"}) {
			install.Error("mode error")
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		install.BuildFirewall()
	},
}

func init() {
	rootCmd.AddCommand(firewallCmd)
	firewallCmd.Flags().StringVar(&install.FirewallConfig.Mode, "mode", "", "install|uninstall|check")
	firewallCmd.Flags().StringVar(&install.FirewallConfig.Keys, "keys", "", "")
}
