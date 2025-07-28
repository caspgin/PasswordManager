package user

import "testing"

func TestGetAllUsers(t *testing.T) {
	var expectedUsers []User = nil

	t.Run("Length Check", func(t *testing.T) {
		derivedUsers, err := GetAllUsers()

		if err != nil {
			t.Errorf("Got error instead of users: %v", err.Error())
			return
		}

		if len(derivedUsers) != len(expectedUsers) {
			t.Errorf(" Test Case 1 failed: Derived Users length mismatch Expected Users length, expected %d , got %d", len(expectedUsers), len(derivedUsers))
		}
	})
}
