clave
=====
Clave enables remote GPG signing without exposing your private key to a remote
server. It generates the signing hash on the remote server, and lets you sign
the hash locally with your private key.

The tool is currently under development, and any suggestions or improvements are
appreciated!

## Why
The signature hash used for OpenPGP signatures requires a few things:
- signature type
- public-key algorithm
- hashed subpackets 

The above fields are concatenated with the data being signed to create the
signing hash. This prevents you from running `sha256sum` over your file to
create an OpenPGP signature.

The OpenPGP RFC explains this: https://tools.ietf.org/html/rfc4880#section-5.2.3

The problem occurs when you have created a 3 GB artefact on your build server,
and need to sign this. You could download the file, but this is slow and
cumbersome. There are options to forward the signing socket to the remote
server which could pose as a solution.

https://lists.archlinux.org/pipermail/arch-general/2017-January/042987.html

There has also been previous discussion on the pacman-dev mailing list when
signing was brought up. This in turn led to a discussion on the GnuPG mailing
list where Koch made it clear this won't be implemented.
 
https://lists.archlinux.org/pipermail/pacman-dev/2011-June/013333.html  
https://lists.gnupg.org/pipermail/gnupg-users/2011-June/042076.html  


## How
Golang implements the entire OpenPGP system with high level abstractions. It's
pretty neat and easy to use. To create the signature we initiate the signing
with the public key, along with a default configuration for the signature packet.

Since the public key is used, the actual signing parts of the library will
crash. We dispatch the actual signing into its own thread, and recover from the
crash. We can then grab the hash from the Hash struct we made, and use this in
our signature request.

https://github.com/Foxboron/clave/blob/master/src/signature.go#L47

The signature request created by clave contains the filename, Unix timestamp and
the signing hash. This is used locally to resume the signing process by faking a
hash struct. This enables us to make sure the OpenPGP library never modifies the
hash, and that our signing hash will always be returned. This creates the valid
signature locally.


## Drawbacks
There are some drawbacks, the Go openpgp library is weird, so reading from
keyrings is not trivial. The current implementation exports your key from
GnuPG, and then decrypts the key, where you end up typing the password twice.

The other problem is if you inherently trust your remote server. Clave is more
an experiment if this is a useful compromise in some cases (like a build server,
where reproducible packages can be built, and the signed hash verified).


## Usage
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
$ cat request | clave verify -
2017/10/10 22:22:33 Correct signature request!
```
