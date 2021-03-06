module github.com/darc1/dtls/v2

require (
	github.com/pion/dtls/v2 v2.0.3
	github.com/pion/logging v0.2.2
	github.com/pion/transport v0.10.1
	github.com/pion/udp v0.1.0
	golang.org/x/crypto v0.0.0-20201002094018-c90954cbb977
	golang.org/x/net v0.0.0-20200930145003-4acb6c075d10
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
)

go 1.13

replace github.com/pion/dtls/v2 => github.com/darc1/dtls/v2 v2.0.3
