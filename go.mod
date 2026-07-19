module servsecret

go 1.23.0

require (
	github.com/go-sql-driver/mysql v1.10.0
	github.com/lib/pq v1.12.3
	github.com/vyuvaraj/ServShared v1.0.2-0.20260714131806-8f86487bce70
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
)

replace github.com/vyuvaraj/ServShared => ../ServShared
