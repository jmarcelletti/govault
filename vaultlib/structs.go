package govault

import (
	vaultapi "github.com/hashicorp/vault/api"
)

/* ----------------------------------------------------------------------------------------------------------------- */

type vaultApproleAuth struct {
	roleID       string
	secretID     string
	roleIDFile   string
	secretIDFile string
	tokenFile    string
	authPath     string
}

/* ----------------------------------------------------------------------------------------------------------------- */

type vaultKubernetesAuth struct {
	jwt      string
	role     string
	authPath string
}

/* ----------------------------------------------------------------------------------------------------------------- */

type vaultLDAPAuth struct {
	username string
	password string
	authPath string
}

/* ----------------------------------------------------------------------------------------------------------------- */

type vaultAuthCache struct {
	kubernetes     vaultKubernetesAuth
	approle        vaultApproleAuth
	ldap           vaultLDAPAuth
	lastAuthTime   int64
	lastAuthMethod string
}

/* ----------------------------------------------------------------------------------------------------------------- */

// API is the entrypoint for this module
type API struct {
	Client    *vaultapi.Client
	authCache vaultAuthCache
}
