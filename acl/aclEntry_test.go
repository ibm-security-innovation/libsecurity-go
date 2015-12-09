package acl

import (
	"fmt"
	"testing"

	//	um "github.com/ibm-security-innovation/libsecurity-go/usersManagement"
)

const (
	PerRead        = "Read"
	PerWrite       = "Write"
	PerExe         = "Execute"
	PerTake        = "Take"
	PerAll         = "Can be used by All"
	PerNotAnEntry1 = "NotAnEntry1"
	PerNotAnEntry2 = "NotAnEntry2"

	entryName = "test1"
)

var permissionsVec = []Permission{PerRead, PerWrite, PerExe, PerTake, PerAll}
var notPermissionsVec = []Permission{PerNotAnEntry1, "", PerNotAnEntry2}
var permissionsMap = make(map[Permission]bool)

func init() {
	for _, p := range permissionsVec {
		permissionsMap[p] = true
	}
	for _, p := range notPermissionsVec {
		permissionsMap[p] = false
	}
}

func addPermissions(a *AclEntry, permissions map[Permission]bool, expected bool) (bool, *Permission) {
	for p, val := range permissions {
		if val == true {
			val, err := a.AddPermission(p)
			if len(p) == 0 && err != nil {
				return !expected, &p
			}
			if val != expected {
				return false, &p
			}
		}
	}
	return true, nil
}

// Verify that empty permission can't be added
// verify that valid permission can be added
// verify that permission that is in the list can't be added again
// verify that only permission that are in the list can be removed
// Verify that at the end of the loop, no permissions are left in the list
func Test_AddRemovePermissions(t *testing.T) {
	expected := []bool{true, false}
	name := "User1"

	a, _ := NewEntry(name)
	// verify that empty permission can't be added
	p := Permission("")
	_, err := a.AddPermission(p)
	if err == nil {
		t.Error(fmt.Sprintf("Test fail: Invalid permission: '%v' was added to the %v", p, a))
	}
	// verify that valid permission can be added
	// verify that permission that is in the list can't be added again
	for _, exp := range expected {
		ok, permission := addPermissions(a, permissionsMap, exp)
		if ok == false {
			if exp == true {
				t.Errorf("Test fail: Fail to add valid permission: '%v' to %v", permission, a)
			} else {
				t.Errorf("Test fail: Permission: '%v' was added to %v but is was already added before", permission, a)
			}
		}
	}

	// verify that only permission that are in the list can be removed
	for p, val := range permissionsMap {
		err := a.RemovePermission(p)
		if err != nil && val == true {
			t.Errorf("Test fail: Fail to remove valid permission: '%v' from %v", p, a)
		} else if err == nil && val == false {
			t.Errorf("Test fail: Permission: '%v' was removed from %v, but it wasn't in the permissions list", p, a)
		}
	}
	if len(a.Permissions) != 0 {
		t.Error("Test fail: The permission list of", a, "must be empty")
	}
}

// Add permissions to an entry and verify that only permission that are in the
//   entry return true
func Test_CheckPermissions(t *testing.T) {
	name := "User1"
	//
	//	ul := um.NewUsersList()
	//	user1, _ := um.NewUser(name, nil)
	//	ul.AddUser(user1)
	a, _ := NewEntry(name)

	// verify that valid permission can be added
	ok, permission := addPermissions(a, permissionsMap, true)
	if ok == false {
		t.Errorf("Test fail: Fail to add valid permission: '%v' to %v", permission, a)
	}
	// verify that only permission that are in the list returns true
	for p, val := range permissionsMap {
		ok, _ := a.CheckPermission(p)
		if ok == false && val == true {
			t.Errorf("Test fail: Permission: '%v' from %v wasn't found", p, a)
		} else if ok == true && val == false {
			t.Errorf("Test fail: Permission: '%v' that is not in %v, was found", p, a)
		}
	}
}
