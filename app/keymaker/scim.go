package keymaker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type (
	SCIMClient struct {
		GEID   string
		Config Config
	}
	MigrateUserData struct {
		Schemas           []string  `json:"schemas"`
		ExternalID        string    `json:"externalId"`
		Email             string    `json:"email"`
		GlobalEntityID    string    `json:"globalEntityId"`
		HashedPassword    *Password `json:"hashedPassword,omitempty"`
		PreferredLanguage string    `json:"preferredLanguage"`
	}
	Password struct {
		Password       string `json:"password"`
		CryptAlgorithm string `json:"cryptAlgorithm"`
		Salt           string `json:"salt"`
	}
	MigrateUserOperation struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		BulkID string          `json:"bulkId"`
		Data   MigrateUserData `json:"data"`
	}
	MigrateUserRequest struct {
		Schemas    []string               `json:"schemas"`
		Operations []MigrateUserOperation `json:"Operations"`
	}
	MigrateUserResponse struct {
		Schemas    []string                       `json:"schemas"`
		Operations []MigrateUserResponseOperation `json:"operations"`
	}
	MigrateUserResponseOperation struct {
		Method   string `json:"method"`
		BulkID   string `json:"bulkId"`
		Path     string `json:"path"`
		Location string `json:"location"`
		Status   string `json:"status"`
	}
	Credential struct {
		ID       string
		Email    string
		Salt     string
		Password string
	}
	BulkArgs struct {
		BulkID      string
		Credentials []Credential
	}
)

func (c SCIMClient) MigrateUsers(accessToken string, args BulkArgs) (*MigrateUserResponse, error) {
	creds := args.Credentials
	operations := make([]MigrateUserOperation, 0, len(creds))
	clientID := c.Config.ClientID

	for _, cred := range creds {
		datum := MigrateUserData{
			Schemas:           []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			Email:             cred.Email,
			PreferredLanguage: "en-US",
			ExternalID:        cred.ID,
			GlobalEntityID:    c.GEID,
		}
		if cred.Password != "" {
			datum.HashedPassword = &Password{
				Password:       cred.Password,
				Salt:           cred.Salt,
				CryptAlgorithm: "bcrypt",
			}
		}
		operation := MigrateUserOperation{
			Method: "POST",
			Path:   "/Users",
			BulkID: args.BulkID,
			Data:   datum,
		}

		operations = append(operations, operation)
	}

	payload := MigrateUserRequest{
		Schemas:    []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
		Operations: operations,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.Config.URL+"/scim/v2/Bulk", bytes.NewBuffer(raw))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Global-Entity-ID", c.GEID)
	req.Header.Set("X-CLIENT-ID", clientID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("not success got %d", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	respBody := &MigrateUserResponse{}
	if err := json.Unmarshal(body, respBody); err != nil {
		return nil, err
	}

	return respBody, nil
}
