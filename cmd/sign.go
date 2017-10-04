// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"log"
	"os"

	"github.com/foxboron/clave/clave"
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
