krp
===

K R Y P T O N - CLI Encryption Tool
Usage:

Available ciphers & hashing algorithms:
`base64`, `base32`, `base16`, `binary`, `hex`, `ascii`, `rot13`, `url`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`
Some shortcuts: `b64`, `b32`, `b16`, `r13` and `bin`

`krp <string>`
	The string encoded using all of the ciphers

`krp <d|de|dec|decode> <string>`
	The string decoded using all of the ciphers
	(could be useful for cipher identification)

`krp <cipher> [<e|en|enc|encode>] <string>`
	The string encoded using the specified cipher

`rp <cipher> <d|de|dec|decode> <string>`
	The string decoded using the specified cipher

The same rules apply for piping, just omit the <string>

E.g.:
`cat /etc/hosts | krp md5`
	Returns the md5 of the file contents
