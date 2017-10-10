package cmd

import (
	"encoding/json"
	"log"
	"os"

	clave "github.com/foxboron/clave/src"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [request to verify]",
	Short: "Verify signing requests",
	Long:  `desc`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyid := viper.Get("keyid").(string)
		pgpkey := clave.GetPublicKey(keyid)
		var signs clave.SignRequests
		var decoder *json.Decoder
		if args[0] == "-" {
			decoder = json.NewDecoder(os.Stdin)
		} else {
			file, err := os.Open(args[0])
			if err != nil {
				log.Fatal(err)
			}
			decoder = json.NewDecoder(file)
		}
		decoder.UseNumber()
		err := decoder.Decode(&signs)
		if err != nil {
			log.Fatal(err)
		}
		for _, s := range signs {
			clave.VerifySignature(pgpkey, s)
		}
	},
}

func init() {
	RootCmd.AddCommand(verifyCmd)
}
