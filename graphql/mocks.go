package graphql

import (
	"net/http"

	"github.com/jarcoal/httpmock"
)

const (
	readDataResponse   = `{"data": {"todo": {"id": "1", "text": "something todo", "userId": "900"}}}`
	createDataResponse = `{"data": {"createTodo": {"id": "2"}}}`
	errDataResponse    = `{"data": {}, errors: [{message: "bad things happened"}]}`
	queryUrl           = "http://mock-gql-url.io"

	dataSourceConfig = `
	data "graphql_query" "basic_query" {
		query_variables = {}
		query     =  <<-EOT
		query findTodos{
			todo {
			  id
			  text
			  done
			  user {
				name
			  }
			  list
			}
		  }
		EOT
	}
`
	resourceConfigCreate = `
	resource "graphql_mutation" "basic_mutation" {
		mutation_variables = {
			"text" = "something todo"
			"userId" = "900"
		}
		delete_mutation_variables = {
			"testvar1" = "testval1"
		}
		read_query_variables = {}
		
		create_mutation = <<-EOT
		mutation createTodo($text: String!, $userId: String!, $list: [String!]!) {
			createTodo(input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT

		update_mutation = <<-EOT
		mutation updateTodo($id: String!, $text: String!, $userId: String!, $list: [String!]!) {
			updateTodo(id: $id, input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT

		delete_mutation = <<-EOT
		mutation deleteTodo($id: String!) {
			deleteTodo(input: $id) {
			  user {
				id
			  }
			  text
			  done
			}
		  }
		EOT

		read_query = <<-EOT
		query findTodos{
			todo {
			  id
			  text
			  done
			  user {
				name
			  }
			  list
			}
		  }
		EOT

		compute_mutation_keys = {
			"id" = "todo.id"
		}
	}
`

	resourceConfigComputeMutationKeysOnCreate = `
	resource "graphql_mutation" "basic_mutation" {
		mutation_variables = {
			"text" = "something todo"
			"userId" = "900"
		}
		delete_mutation_variables = {
			"testvar1" = "testval1"
		}
		read_query_variables = {
			"testvar1" = "testval1"
		}

		create_mutation = <<-EOT
		mutation createTodo($text: String!, $userId: String!, $list: [String!]!) {
			createTodo(input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT

		update_mutation = <<-EOT
		mutation updateTodo($id: String!, $text: String!, $userId: String!, $list: [String!]!) {
			updateTodo(id: $id, input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT

		delete_mutation = <<-EOT
		mutation deleteTodo($id: String!) {
			deleteTodo(input: $id) {
			  user {
				id
			  }
			  text
			  done
			}
		  }
		EOT

		read_query      = <<-EOT
		query findTodos{
			todo {
			  id
			  text
			  done
			  user {
				name
			  }
			  list
			}
		  }
		EOT

		compute_from_create = true

		compute_mutation_keys = {
			"id" = "createTodo.id"
		}
	}
`
	resourceConfigUpdate = `
	resource "graphql_mutation" "basic_mutation" {
		mutation_variables = {
			"text" = "something else"
			"userId" = "500"
		}
		delete_mutation_variables = {
			"testvar1" = "testval1"
		}
		read_query_variables = {}
		create_mutation = <<-EOT
		mutation createTodo($text: String!, $userId: String!, $list: [String!]!) {
			createTodo(input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT
		update_mutation = <<-EOT
		mutation updateTodo($id: String!, $text: String!, $userId: String!, $list: [String!]!) {
			updateTodo(id: $id, input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT
		delete_mutation = <<-EOT
		mutation deleteTodo($id: String!) {
			deleteTodo(input: $id) {
			  user {
				id
			  }
			  text
			  done
			}
		  }
		EOT
		read_query      = <<-EOT
		query findTodos{
			todo {
			  id
			  text
			  done
			  user {
				name
			  }
			  list
			}
		  }
		EOT

		compute_mutation_keys = {
			"id" = "todo.id"
		}
	}
`
	resourceConfigUpdateForceReplace = `
	resource "graphql_mutation" "basic_mutation" {
		force_replace = true
		mutation_variables = {
			"text" = "forced replacement"
			"userId" = "500"
		}
		delete_mutation_variables = {
			"testvar1" = "testval1"
		}
		read_query_variables = {}
		create_mutation = <<-EOT
		mutation createTodo($text: String!, $userId: String!, $list: [String!]!) {
			createTodo(input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT
		update_mutation = <<-EOT
		mutation updateTodo($id: String!, $text: String!, $userId: String!, $list: [String!]!) {
			updateTodo(id: $id, input:{text: $text, userId: $userId, list: $list}) {
			  user {
				id
			  }
			  id
			  text
			  list
			  done
			}
		  }
		EOT
		delete_mutation = <<-EOT
		mutation deleteTodo($id: String!) {
			deleteTodo(input: $id) {
			  user {
				id
			  }
			  text
			  done
			}
		  }
		EOT
		read_query      = <<-EOT
		query findTodos{
			todo {
			  id
			  text
			  done
			  user {
				name
			  }
			  list
			}
		  }
		EOT

		compute_mutation_keys = {
			"id" = "todo.id"
		}
	}
`
)

func mockGqlServerResponse(req *http.Request) (*http.Response, error) {
	return httpmock.NewStringResponse(200, readDataResponse), nil
}

func mockGqlServerResponseError(req *http.Request) (*http.Response, error) {
	return httpmock.NewStringResponse(200, errDataResponse), nil
}

func mockGqlServerResponseCreate(req *http.Request) (*http.Response, error) {
	return httpmock.NewStringResponse(200, createDataResponse), nil
}
