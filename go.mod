module github.com/SUSE/stepdance

go 1.24.4

require (
	github.com/alexedwards/scs/v2 v2.8.0
	github.com/coreos/go-oidc/v3 v3.14.1
	github.com/jackc/pgx/v5 v5.6.0
	github.com/oauth2-proxy/mockoidc v0.0.0-20240214162133-caebfff84d25
	github.com/smallstep/certificates v0.28.3
	github.com/stretchr/testify v1.10.0
	golang.org/x/net v0.41.0
	golang.org/x/oauth2 v0.30.0
)

require (
	dario.cat/mergo v1.0.1 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.3.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/ccoveille/go-safecast v1.6.1 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgraph-io/badger v1.6.2 // indirect
	github.com/dgraph-io/badger/v2 v2.2007.4 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20200201041132-a6ae2369ad13 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0 // indirect
	github.com/go-chi/chi/v5 v5.2.2 // indirect
	github.com/go-jose/go-jose/v3 v3.0.4 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/golang/glog v1.2.4 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.7 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/newrelic/go-agent/v3 v3.39.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.22.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/slackhq/nebula v1.9.5 // indirect
	github.com/smallstep/cli-utils v0.12.1 // indirect
	github.com/smallstep/go-attestation v0.4.4-0.20241119153605-2306d5b464ca // indirect
	github.com/smallstep/linkedca v0.23.0 // indirect
	github.com/smallstep/nosql v0.7.0 // indirect
	github.com/smallstep/pkcs7 v0.2.1 // indirect
	github.com/smallstep/scep v0.0.0-20240926084937-8cf1ca453101 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/urfave/cli v1.22.17 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/bbolt v1.3.10 // indirect
	go.step.sm/crypto v0.67.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/exp v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/grpc v1.73.0 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// pending https://github.com/oauth2-proxy/mockoidc/pull/45
replace github.com/oauth2-proxy/mockoidc => github.com/tacerus/go-mockoidc v0.0.2

// pending https://github.com/smallstep/certificates/issues/2323
replace github.com/smallstep/certificates v0.28.3 => /home/georg/Work/git/smallstep-certificates
