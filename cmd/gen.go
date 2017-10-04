package cmd

import (
	"github.com/foxboron/clave/clave"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var genCmd = &cobra.Command{
	Use:   "gen [file to sign]",
	Short: "Generate signing request",
	Long:  `desc`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyid := viper.Get("keyid").(string)
		key := clave.GetPublicKey(keyid)
		clave.CreateSignatureRequest(key, args[0:])
	},
}

func init() {
	RootCmd.AddCommand(genCmd)
}
