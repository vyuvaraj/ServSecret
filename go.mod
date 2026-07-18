module servsecret

go 1.26.4

require (
	github.com/vyuvaraj/ServShared v1.0.2-0.20260714131806-8f86487bce70
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/golang-jwt/jwt/v5 v5.3.1 // indirect

replace github.com/vyuvaraj/ServShared => ../ServShared
