package main

import (
	"strings"
)


type Todo struct {
	ID      string    `json:"id"`
	UserID  string    `json:"user_id"`
	Task 	string `json:"task"`
}

type TodoMapStore struct {
	todos map[string]Todo
}

func NewTodoMapStore() *TodoMapStore {
	return &TodoMapStore{
		todos: make(map[string]Todo),
	}
}

type TodoStore interface {
	Seed(userID string)
	Search(userID, term string) []Todo
}

func (t *TodoMapStore) Seed(userID string) {
	t.todos["1"] = Todo{
		ID: "1",
		UserID: userID,
		Task: "Learn Go",
	}

	t.todos["2"] = Todo{
		ID: "2",
		UserID: userID,
		Task: "Learn React",
	}

	t.todos["3"] = Todo{
		ID: "3",
		UserID: userID,
		Task: "Learn GraphQL",
	}

	t.todos["4"] = Todo{
		ID: "4",
		UserID: userID,
		Task: "Learn GraphQL",
	}
}

func (t *TodoMapStore) Search(userID string, term string) []Todo {
	term = strings.ToLower(term)
	termFields := strings.Fields(term)
	result := []Todo{}

	for _, field := range termFields {
		for _, todo := range t.todos {
			if strings.Contains(strings.ToLower(todo.Task), field) {
				if todo.UserID == userID && !contains(result, todo) {
					result = append(result, todo)
				}
			}
		}
	}

	return result
}

func contains(slice []Todo, item Todo) bool {
	for _, todo := range slice {
		if todo.ID == item.ID {
			return true
		}
	}
	return false
}
