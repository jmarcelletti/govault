package govault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

/* ----------------------------------------------------------------------------------------------------------------- */

// checkAuthNeeded is called after an issue occurs and is an attempt to retry getting a new token (if needed)
func (v *API) checkAuthNeeded() error {
	if time.Now().Unix()-v.authCache.lastAuthTime < 5 {
		return errors.New("login was attempted recently, not retrying")
	}

	if !v.tokenRefreshNeeded(5) {
		// This means there was an error, but it was unrelated to auth
		return errors.New("vault token does not need refreshing")
	}

	switch v.authCache.lastAuthMethod {
	case "approle":
		if v.authCache.approle.roleIDFile == "" || v.authCache.approle.secretIDFile == "" {
			_, err := v.ApproleLogin(v.authCache.approle.roleID, v.authCache.approle.secretID, v.authCache.approle.authPath)
			return err
		}
		_, err := v.InitApprole(v.authCache.approle.roleIDFile, v.authCache.approle.secretIDFile, v.authCache.approle.tokenFile, v.authCache.approle.authPath)
		return err
	case "kubernetes":
		_, err := v.KubernetesLogin(v.authCache.kubernetes.jwt, v.authCache.kubernetes.role, v.authCache.kubernetes.authPath)
		return err
	case "ldap":
		_, err := v.LDAPLogin(v.authCache.ldap.username, v.authCache.ldap.password, v.authCache.ldap.authPath)
		return err
	case "token": // This is for testing only / local since there's no point in re-authenticating if all you have is a token.
		// If we get here, it means the token they provided is expiring soon (or has expired). The only thing we can is try to renew it but it probably won't work.
		// @ TODO Add the option to renew a token, and when they set the auth method as a token, we should change the tokenRefreshNeeded time to longer for a better change of catching it.
		//v.Client.Auth().Token().RenewSelf(1) ???
		v.authCache.lastAuthTime = time.Now().Unix()
		return nil
	default:
		return fmt.Errorf("unknown previous auth method or no authentication performed: [%s]", v.authCache.lastAuthMethod)
	}

}

/* ----------------------------------------------------------------------------------------------------------------- */

// GetTokenTTL retrieves the remaining ttl (in seconds) from vault for a given token
func (v *API) GetTokenTTL() (int64, error) {
	data, err := v.Client.Logical().Read("/auth/token/lookup-self")
	if err != nil {
		return 0, fmt.Errorf("unable to perform token/lookup-self: %s", err)
	}

	ttl, err := data.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return 0, err
	}

	return ttl, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// TokenRefreshNeeded returns if the token is in good standing
func (v *API) tokenRefreshNeeded(minimumTokenTTL int64) bool {
	tokenTTL, err := v.GetTokenTTL()
	if err != nil {
		return true
	}

	// Check if we need to renew the token
	if tokenTTL < minimumTokenTTL {
		return true
	}

	return false
}

/* ----------------------------------------------------------------------------------------------------------------- */

// RevokeSelf revokes the current stored token
func (v *API) RevokeSelf() error {
	return v.Client.Auth().Token().RevokeSelf(v.Client.Token())
}

/* ----------------------------------------------------------------------------------------------------------------- */

// SetToken is a shorthand for .Client.SetToken and is really only used for debugging to set up some test variables. You shouldn't use this over a real auth method.
func (v *API) SetToken(token string) {
	v.authCache.lastAuthMethod = "token"
	v.authCache.lastAuthTime = time.Now().Unix()
	v.Client.SetToken(token)
}

/* ----------------------------------------------------------------------------------------------------------------- */

// InitApprole attempts to obtain a valid Vault token via approle or local cache
func (v *API) InitApprole(roleIDFile string, secretIDFile string, tokenFile string, authPath string) (string, error) {
	var vaultToken string

	if authPath != "" {
		v.authCache.approle.authPath = authPath
	}

	// We save this stuff for automatic re-auth later
	v.authCache.approle.roleIDFile = roleIDFile
	v.authCache.approle.secretIDFile = secretIDFile
	v.authCache.approle.tokenFile = tokenFile
	v.authCache.lastAuthMethod = "approle"

	// Load Vault secret-id from file
	roleIDTmp, err := os.ReadFile(v.authCache.approle.roleIDFile)
	if err != nil {
		return "", fmt.Errorf("error occurred while trying to read role-id from file: %s", v.authCache.approle.roleIDFile)
	}
	roleID := strings.TrimSuffix(string(roleIDTmp), "\n")

	// Load Vault secret-id from file
	secretIDTmp, err := os.ReadFile(v.authCache.approle.secretIDFile)
	if err != nil {
		return "", fmt.Errorf("error occurred while trying to read secret-id from file: %s", v.authCache.approle.secretIDFile)
	}
	secretID := strings.TrimSuffix(string(secretIDTmp), "\n")

	// Attempt to read token from file cache
	tokenTmp, _ := os.ReadFile(v.authCache.approle.tokenFile)

	vaultToken = strings.TrimSuffix(string(tokenTmp), "\n")
	v.Client.SetToken(vaultToken)

	if vaultToken == "" || v.tokenRefreshNeeded(5) {
		vaultToken, err = v.ApproleLogin(roleID, secretID, v.authCache.approle.authPath)
		if err != nil {
			return "", fmt.Errorf("error attempting approle login: %s", err)
		}

		// Let's save the token for next time
		tokenHwnd, err := os.Create(v.authCache.approle.tokenFile)
		if err != nil {
			return "", fmt.Errorf("unable to create vault token file: %s", v.authCache.approle.tokenFile)
		}

		defer tokenHwnd.Close()
		_, err = tokenHwnd.WriteString(vaultToken)
		if err != nil {
			return "", fmt.Errorf("unable to write to vault token file: %s", v.authCache.approle.tokenFile)
		}
	}

	return vaultToken, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// ApproleLogin logins in using role-id and secret-id and returns a token if successful
func (v *API) ApproleLogin(roleID string, secretID string, authPath string) (string, error) {
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	// Sane default
	if authPath == "" {
		authPath = "auth/approle"
	}

	v.authCache.approle.roleID = roleID
	v.authCache.approle.secretID = secretID
	v.authCache.lastAuthMethod = "approle"
	v.authCache.approle.authPath = authPath

	secret, err := v.Client.Logical().Write(fmt.Sprintf("%s/login", authPath), data)
	if err != nil {
		return "", err
	}

	if secret.Auth == nil {
		return "", fmt.Errorf("no auth info returned")
	}

	v.authCache.lastAuthTime = time.Now().Unix()
	v.Client.SetToken(secret.Auth.ClientToken)
	return secret.Auth.ClientToken, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// KubernetesLogin uses the service token (JWT) to authenticate to a vault role
func (v *API) KubernetesLogin(jwt string, role string, authPath string) (string, error) {
	data := map[string]interface{}{
		"jwt":  jwt,
		"role": role,
	}

	v.authCache.lastAuthMethod = "kubernetes"
	v.authCache.kubernetes.jwt = jwt
	v.authCache.kubernetes.role = role
	v.authCache.kubernetes.authPath = authPath

	secret, err := v.Client.Logical().Write(authPath, data)
	if err != nil {
		return "", err
	}

	if secret.Auth == nil {
		return "", fmt.Errorf("no auth info returned")
	}

	v.authCache.lastAuthTime = time.Now().Unix()
	v.Client.SetToken(secret.Auth.ClientToken)
	return secret.Auth.ClientToken, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// LDAPLogin authenticates to Vault via LDAP
func (v *API) LDAPLogin(username string, password string, authPath string) (string, error) {
	data := map[string]interface{}{
		"password": password,
	}

	if authPath == "" {
		authPath = "auth/ldap"
	}

	v.authCache.lastAuthMethod = "ldap"
	v.authCache.ldap.username = username
	v.authCache.ldap.password = password
	v.authCache.ldap.authPath = authPath

	// default would look like auth/ldap/login/${username}
	secret, err := v.Client.Logical().Write(fmt.Sprintf("%s/login/%s", authPath, username), data)
	if err != nil {
		return "", err
	}

	if secret.Auth == nil {
		return "", fmt.Errorf("no auth info returned")
	}

	v.authCache.lastAuthTime = time.Now().Unix()
	v.Client.SetToken(secret.Auth.ClientToken)
	return secret.Auth.ClientToken, nil
}
