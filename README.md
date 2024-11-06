# dns-scripts

## nsset-maintainer.py

Checks an ecs cluster and manages a nsset based on the returned results

Requires a ~/.tsigkeyring file with the contents:

`
[TSIG]
name: "name"
key: "<keydata>"
`

