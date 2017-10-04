clave
=====
Clave enables remote GPG signing without exposing your private key to an remote server. It generates the signing hash on
the remote server, and lets you sign the hash locally with your private key.

A hash PGP uses to sign, is a combination of the keyid, UnixTime and the contents of the artifact.

There are some drawbacks, the Go openpgp library is weird, so reading from keyrings are not trivial. The current
implementation exports your key from gnupg, and then decrypt the key where you end up with typing the password twice.

The other problem is if you inherently trust your remote server. Clave is more an experiment if this is a useful
compromise in some cases, like a build server. Where reproducible packages can be built, and the signed hash verified.


# Usage
```
$ cat ~/.clave.yml 
keyid: 9C02FF419FECBE16
$ clave gen ./tests/test > ./requests
$ cat ./requests 
[{"Name":"./tests/test","UnixTime":1507146122,"Digest":"8201143f42b240e803f9b36b70b610f7031eb05c6b2b6f7195bfe9c7b5e62997"}]%                                                                                                          
$ cat ./requests | clave sign
$ cd ./tests && gpg --verify test.sig 
gpg: assuming signed data in 'test'
gpg: Signature made Wed 04 Oct 2017 09:42:02 PM CEST
gpg:                using RSA key 9C02FF419FECBE16
gpg: Good signature from "Morten Linderud <morten@linderud.pw>" [ultimate]
gpg:                 aka "Morten Linderud <mcfoxax@gmail.com>" [ultimate]
gpg:                 aka "Morten Linderud <morten.linderud@fribyte.uib.no>" [ultimate]
gpg:                 aka "Morten Linderud <morten.linderud@student.uib.no>" [ultimate]
gpg:                 aka "Morten Linderud <foxboron@archlinux.org>" [ultimate]
```
