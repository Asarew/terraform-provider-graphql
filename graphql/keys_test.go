package graphql

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var datablob = `{"data": {"someField": "someValue", "items": ["itemValueOne", "itemValueTwo"], "otherItems": [{"field1": "value1", "field2": "value2"}, {"field1": "value3", "field2": "value4"}]}}`

func TestComputeMutationVariableKeys(t *testing.T) {
	cases := []struct {
		body             string
		computeKeys      map[string]interface{}
		expectedValues   map[string]interface{}
		expectedErrorMsg string
	}{
		{
			body:           `{"data": {"todo": {"id": "computed_id", "otherComputedValue": "computed_value_two"}}}`,
			computeKeys:    map[string]interface{}{"id_key": "todo.id", "other_computed_value": "todo.otherComputedValue"},
			expectedValues: map[string]interface{}{"id_key": "computed_id", "other_computed_value": "computed_value_two"},
		},
		{
			body:           `{"data": {"todos": [{"id": "computed_id"}, {"id": "second_id"}]}}`,
			computeKeys:    map[string]interface{}{"id_key": "todos[1].id"},
			expectedValues: map[string]interface{}{"id_key": "second_id"},
		},
		{
			body:             `{"data": {"todos": [{"id": "computed_id"}, {"id": "second_id"}]}}`,
			computeKeys:      map[string]interface{}{"id_key": "todos[3].id"},
			expectedErrorMsg: "provided index, 3, out of range for items in object todos with length of 2",
		},
		{
			body:             `{"data": {"todos": [{"id": "computed_id", "items": []}]}}`,
			computeKeys:      map[string]interface{}{"id_key": "todos[0].notreal[1]"},
			expectedErrorMsg: "mutation_key not found in nested object: notreal",
		},
		{
			body:             `{"data": {"todo": {"id": "computed_id"}}}`,
			computeKeys:      map[string]interface{}{"id_key": "todo[0].notreal"},
			expectedErrorMsg: "structure at key [todo] must be an array",
		},
		{
			body:             `{"data": {"todos": ["notanobject"]}}`,
			computeKeys:      map[string]interface{}{"id_key": "todos[0].id"},
			expectedErrorMsg: "malformed structure at provided index: 0",
		},
		{
			body:             `{"data": {"todos": [{"id": "computed_id"}, {"id": "second_id"}]}}`,
			computeKeys:      map[string]interface{}{"id_key": "todos.id"},
			expectedErrorMsg: "malformed structure at []interface {}{map[string]interface {}{\"id\":\"computed_id\"}, map[string]interface {}{\"id\":\"second_id\"}}",
		},
		{
			body:             `{"data": {"todo": {"id": "computed_id"}}}`,
			computeKeys:      map[string]interface{}{"id_key": "notreal.id"},
			expectedErrorMsg: "mutation_key not found",
		},
		{
			body:             `{"data": {"todo": {"id": "computed_id"}}}`,
			computeKeys:      map[string]interface{}{"id_key": ""},
			expectedErrorMsg: "no path provided for mutation key",
		},
	}

	for i, c := range cases {
		var robj = make(map[string]interface{})
		err := json.Unmarshal([]byte(c.body), &robj)
		if err != nil {
			t.Fatalf("Unable to unmarshal json response body %v", err)
		}

		m, err := computeMutationVariableKeys(c.computeKeys, robj)
		if c.expectedErrorMsg != "" {
			assert.Error(t, err, fmt.Sprintf("test case: %d", i))
			assert.EqualError(t, err, c.expectedErrorMsg, fmt.Sprintf("test case: %d", i))
		} else {
			for k, v := range c.expectedValues {
				assert.Equal(t, m[k], v, fmt.Sprintf("test case: %d", i))
			}
		}
	}
}

func TestMapQueryResponse(t *testing.T) {
	var foo map[string]interface{}
	err := json.Unmarshal([]byte(datablob), &foo)
	if err != nil {
		fmt.Println("error:", err)
	}

	cases := []struct {
		value     string
		expectKey string
	}{
		{
			value:     "value1",
			expectKey: "data.otherItems[0].field1",
		},
		{
			value:     "itemValueOne",
			expectKey: "data.items[0]",
		},
		{
			value:     "someValue",
			expectKey: "data.someField",
		},
		{
			value:     "anotherListValue1",
			expectKey: "data.funItems[0].anotherList[0]",
		},
	}

	for i, c := range cases {
		keyOut, _ := mapQueryResponseInputKey(foo, c.value, "", nil)
		assert.Equal(t, c.expectKey, keyOut, "test case %d", i)
		ks := strings.Split(keyOut, ".")
		_, err = getResourceKey(foo, ks...)
		assert.NoError(t, err, "test case %d", i)
	}

}

func TestMapQueryResponseJSONString(t *testing.T) {
	var foo map[string]interface{}
	err := json.Unmarshal([]byte(datablob), &foo)
	if err != nil {
		fmt.Println("error:", err)
	}

	items := []string{"itemValueOne", "itemValueTwo"}
	jsonV, _ := json.Marshal(items)
	itemsValueKey, _ := mapQueryResponseInputKey(foo, string(jsonV), "", nil)
	assert.Equal(t, "data.items", itemsValueKey)
	ks := strings.Split(itemsValueKey, ".")
	_, err = getResourceKey(foo, ks...)
	assert.NoError(t, err)
}
