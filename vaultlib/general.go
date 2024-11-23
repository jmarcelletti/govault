package govault

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

/* ----------------------------------------------------------------------------------------------------------------- */

// SetURI sets the Vault URI for this package
func (v *API) SetURI(uri string) error {

	vaultAPIConfig := &vaultapi.Config{
		Address: uri,
	}

	var err error
	v.Client, err = vaultapi.NewClient(vaultAPIConfig)
	if err != nil {
		return err
	}

	return nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// Base64SmartDecode returns the original string if it's not base64 encoded, or the decoded version if it is.
func (v *API) Base64SmartDecode(data string) string {
	// If we can convert this to a raw int, we aren't treating it as base64
	if _, err := strconv.Atoi(data); err == nil {
		return data
	}

	// On short base64 strings they should end with an equal(=), which isn't always true but that's life.
	if len(data) < 5 {
		if data[len(data)-1:] != "=" {
			return data
		}
	}

	decodeData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data
	}

	return string(decodeData)
}

/* ----------------------------------------------------------------------------------------------------------------- */

// List returns a list of keys in a given METADATA path
func (v *API) List(path string) ([]interface{}, error) {
	data, err := v.Client.Logical().List(path)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.List(path)
		}

		return nil, err
	}

	if data == nil {
		return nil, errors.New("unable to find specified path")
	}

	return data.Data["keys"].([]interface{}), nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// Read allows a raw read request against the Vault API
func (v *API) Read(path string) (*vaultapi.Secret, error) {
	secret, err := v.Client.Logical().Read(path)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.Read(path)
		}

		return nil, err
	}

	if secret == nil {
		return nil, errors.New("secret not found")
	}

	return secret, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

func (v *API) Write(path string, data map[string]interface{}) (*vaultapi.Secret, error) {
	secret, err := v.Client.Logical().Write(path, data)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.Write(path, data)
		}
	}

	return secret, err
}

/* ----------------------------------------------------------------------------------------------------------------- */

// Delete uses the Hashicorp Vault golang API to delete a KV secret.
func (v *API) Delete(path string) error {
	_, err := v.Client.Logical().Delete(path)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.Delete(path)
		}
	}

	return err
}

/* ----------------------------------------------------------------------------------------------------------------- */

// GetAuthType returns the auth backend by path
func (v *API) GetAuthType(path string) (string, error) {

	// Be nice and remove auth/ since the vault api adds it automatically
	if strings.HasPrefix(path, "auth/") {
		path = strings.Replace(path, "auth/", "", 1)
	}

	// Vault always returns this with a trailing slash so make sure we adjust if needed.
	if path[len(path)-1:] != "/" {
		path = path + "/"
	}

	data, err := v.Client.Logical().Read("sys/auth")
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.GetAuthType(path)
		}

		return "", err
	}

	for clusterMount, mountConfig := range data.Data {
		if clusterMount == path {
			mountData, ok := mountConfig.(map[string]interface{})
			if !ok {
				return "", errors.New("failed to work with data from sys/auth")
			}

			return mountData["type"].(string), nil
		}
	}

	return "", errors.New("mount not found")

}

/* ----------------------------------------------------------------------------------------------------------------- */

// GetAuthMountsByType returns all auth mounts that match a certain auth type
func (v *API) GetAuthMountsByType(authType string, prefixMatch string) ([]string, error) {
	var authMounts []string

	data, err := v.Client.Logical().Read("sys/auth")
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.GetAuthMountsByType(authType, prefixMatch)
		}

		return authMounts, err
	}

	for clusterMount, mountConfig := range data.Data {
		mountData, ok := mountConfig.(map[string]interface{})
		if !ok {
			return authMounts, errors.New("failed to work with data from sys/auth")
		}

		if !strings.HasPrefix(clusterMount, prefixMatch) {
			continue
		}

		if mountData["type"].(string) == authType {
			authMounts = append(authMounts, clusterMount)
		}
	}

	return authMounts, nil
}
