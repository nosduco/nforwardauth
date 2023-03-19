# nforwardauth


An extremely slim and minified forward auth service (intended for use with [Traefik](https://github.com/traefik/traefik))

<!-- TODO: Fillout README -->

# How to add to passwd file

`mkpasswd -m sha-512 -s <<< [password]`

Example:
`mkpasswd -m sha-512 -s <<< test`
