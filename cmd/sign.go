package cmd

import (
	"encoding/json"
	"log"
	"os"

	"github.com/foxboron/clave/src"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create signing request",
	Long:  `Desc`,
	Run: func(cmd *cobra.Command, args []string) {
		keyid := viper.Get("keyid").(string)
		pgpkey := clave.GetPrivateKey(keyid)

		var signs clave.SignRequests
		decoder := json.NewDecoder(os.Stdin)
		decoder.UseNumber()
		err := decoder.Decode(&signs)
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range signs {
			clave.CreateSignature(pgpkey, s)
		}
	},
}

func init() {
	RootCmd.AddCommand(signCmd)
}
