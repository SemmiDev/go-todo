package main

import "fmt"


type User struct {
	ID       string    `json:"id"`
	Email    string `json:"email"`
	FamilyName string `json:"family_name"`
	GivenName string `json:"given_name"`
	Locale string `json:"locale"`
	Name string `json:"name"`
	Picture string `json:"picture"`
	VerifiedEmail bool `json:"verified_email"`
}

type UserMapStore struct {
	users map[string]User
}

func NewUserMapStore() *UserMapStore {
	return &UserMapStore{
		users: make(map[string]User),
	}
}

var (
	ErrUserNotFound = fmt.Errorf("user not found")
	ErrorUserExists = fmt.Errorf("user already exists")
)

type UserStore interface {
	Get(id string) (User, error)
	GetByEmail(email string) (User, error)
	Insert(user User) error
	Exists(id string) bool
	Update(user User) error
}

func (s *UserMapStore) Get(id string) (User, error) {
	user, ok := s.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

func (s *UserMapStore) GetByEmail(email string) (User, error) {
	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (s *UserMapStore) Insert(user User) error {
	_, ok := s.users[user.ID]
	if ok {
		return ErrorUserExists
	}

	s.users[user.ID] = user
	return nil
}

func (s *UserMapStore) Exists(id string) bool {
	_, ok := s.users[id]
	return ok
}

func (s *UserMapStore) Update(user User) error {
	_, ok := s.users[user.ID]
	if !ok {
		return ErrUserNotFound
	}

	s.users[user.ID] = user
	return nil
}
