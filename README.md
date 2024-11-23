# Vault go library wrapper


# Sample Usage
```

import (
    "(pathhere)"
)

func main() {
    var vault govault.API

    err := vault.SetURI("https://vault.foo.com:8200")
    // err check code here

    _, err = vault.InitApprole("/var/lib/vault/sample/role-id", "/var/lib/vault/sample/secret-id", "/var/lib/vault/sample/token", "")
    // err check code here

    // Retrieve a sample secret (vault.GetKV works on KV1 or KV2 it just always returns latest)
	secret, err := vault.GetKV("global/kv/data/services/sample/environments/prod/test")
    // err check code here

    // Retrieve a specific version of a KV2 secret (only works on KV2)
	secret, err = vault.GetKV2("global/kv/data/services/sample/environments/prod/test", 4)
    // err check code here
}
```

