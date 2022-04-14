module github.com/loopholelabs/certifier

go 1.17

replace github.com/go-acme/lego/v4 v4.6.0 => github.com/loopholelabs/lego/v4 v4.6.1-0.20220414220622-2c9352b24cc8

require (
	github.com/go-acme/lego/v4 v4.6.0
	github.com/google/uuid v1.3.0
	github.com/loopholelabs/logging v0.1.1
	github.com/miekg/dns v1.1.48
	github.com/rs/zerolog v1.26.1
)

require (
	github.com/cenkalti/backoff/v4 v4.1.1 // indirect
	github.com/gookit/color v1.5.0 // indirect
	github.com/xo/terminfo v0.0.0-20210125001918-ca9a967f8778 // indirect
	golang.org/x/crypto v0.0.0-20211215165025-cf75a172585e // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/tools v0.1.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)
