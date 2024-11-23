package govault

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

/* ----------------------------------------------------------------------------------------------------------------- */

// GetKV uses the Hashicorp Vault golang API to retrieve KV secrets from Vault. This works on kv1 or kv2
func (v *API) GetKV(path string, returnOnlyData bool) (map[string]interface{}, error) {
	secret, err := v.Read(path)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.GetKV(path, returnOnlyData)
		}
		return nil, err
	}

	if secret == nil {
		return nil, errors.New("secret not found")
	}

	if returnOnlyData {
		m, ok := secret.Data["data"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unable to read requested secret at %s", path)
		}
		return m, nil
	}

	return secret.Data, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// GetKV2ByVersion retrieves KV secrets from Vault at a specific version.
func (v *API) GetKV2ByVersion(path string, version int) (map[string]interface{}, error) {
	data := map[string][]string{
		"version": {strconv.Itoa(version)},
	}

	secret, err := v.Client.Logical().ReadWithData(path, data)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.GetKV2ByVersion(path, version)
		}
		return nil, err
	}

	if secret == nil {
		return nil, errors.New("secret version not found")
	}

	m, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unable to read requested secret at %s", path)
	}

	return m, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// PutKV2 writes KV2 secrets to Vault. This is a simple wrapper that encapsulates the data array
func (v *API) PutKV2(path string, data map[string]interface{}) (*vaultapi.Secret, error) {
	adjustedData := map[string]interface{}{
		"data": data,
	}

	return v.Write(path, adjustedData)
}

/* ----------------------------------------------------------------------------------------------------------------- */

// GetKV2VersionList returns a list of versions for a given kv path
func (v *API) GetKV2VersionList(path string, autoFixPath bool, includeDeleted bool, includeDestroyed bool) ([]int, error) {
	if autoFixPath {
		path = v.GetKV2ListPath(path)
	}

	secret, err := v.Read(path)
	if err != nil {
		checkAuthErr := v.checkAuthNeeded()
		if checkAuthErr == nil {
			return v.GetKV2VersionList(path, false, includeDeleted, includeDestroyed) // We already fixed it so force a false
		}
		return nil, err
	}

	if secret == nil {
		return nil, errors.New("secret not found")
	}

	if _, ok := secret.Data["versions"]; !ok {
		return nil, errors.New("version information not found in secret")
	}

	var returnVersions []int
	if versions, ok := secret.Data["versions"].(map[string]interface{}); ok {
		for k, v := range versions {
			data := v.(map[string]interface{})
			if data["deletion_time"] != "" && !includeDeleted {
				continue
			}

			if data["destroyed"] == true && !includeDestroyed {
				continue
			}

			version, err := strconv.Atoi(k)
			if err != nil {
				return returnVersions, fmt.Errorf("failed to convert version key from string to int on %v: %s", k, err)
			}
			returnVersions = append(returnVersions, version)
		}
	}

	sort.Sort(sort.Reverse(sort.IntSlice(returnVersions)))
	return returnVersions, nil
}

/* ----------------------------------------------------------------------------------------------------------------- */

// GetKV2ListPath attempts to fix a KV path from data to metadata
func (v *API) GetKV2ListPath(path string) string {
	if !strings.Contains(path, "/metadata/") {
		path = strings.Replace(path, "/data/", "/metadata/", 1)
	}

	return path
}
