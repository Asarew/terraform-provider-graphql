package graphql

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform/helper/schema"
)

func QueryExecute(d *schema.ResourceData, m interface{}, queryType string) (map[string]interface{}, error) {
	query := d.Get(queryType).(string)
	variables := d.Get("variables").(map[string]interface{})
	apiURL := m.(*GraphqlProviderConfig).GQLServerUrl
	headers := m.(*GraphqlProviderConfig).RequestHeaders

	var queryBodyBuffer bytes.Buffer

	queryObj := gqlQuery{
		Query:     query,
		Variables: variables,
	}

	if err := json.NewEncoder(&queryBodyBuffer).Encode(queryObj); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", apiURL, &queryBodyBuffer)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	queryResponseObj := make(map[string]interface{})
	err = json.Unmarshal(body, &queryResponseObj)
	if err != nil {
		return nil, err
	}
	return queryResponseObj, nil
}
