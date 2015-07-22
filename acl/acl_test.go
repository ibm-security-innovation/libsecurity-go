package acl

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"testing"

	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
)

const (
	userName     = "user1"
	groupName    = "Group1"
	resourceName = "disk"
)

var ()

type entryS struct {
	name        string // entry name
	permissions []Permission
}

type expectS struct {
	name        string // entry name
	permissions []Permission
}

type expectWhoUsePermissionsS struct {
	permission string
	names      []string
}

type testGroupS struct {
	name    string
	members []string
}

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)
}

func initEntityManager() *en.EntityManager {
	el := en.NewEntityManager()
	el.AddResource(resourceName)
	return el
}

// Create a new ACL, add a given number of entities to Entity list,
// Add each new entity to the new ACL
func initAclAndEntries(length int) (*en.EntityManager, *Acl, map[*AclEntry]bool, error) {
	var entries map[*AclEntry]bool

	el := initEntityManager()
	a := NewACL()
	entries = make(map[*AclEntry]bool)
	for i := 0; i < length; i++ {
		name := "name[0]-a" + strconv.Itoa(i)
		el.AddResource(name)
		e, err := NewEntry(name)
		if err != nil {
			return nil, nil, entries, err
		}
		if e == nil {
			return nil, nil, entries, fmt.Errorf("Error: Can't add the new entry '%v' to the ACL list", name)
		}
		entries[e] = true
	}
	return el, a, entries, nil
}

// Try to add a new entry to a given ACL and check if it functions as expected
func addEntries(a *Acl, entries map[*AclEntry]bool, expected bool) (bool, error) {
	for e, _ := range entries {
		err := a.addEntry(e)
		if expected == true && err != nil {
			return false, fmt.Errorf("Error: Can't add the valid entry '%v', ACL list: %v", e, a)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("Error: Attempting to add an already existing entry '%v' to the ACL list: %v", e, a)
		}
	}
	return true, nil
}

// Try to remove an entry from a given ACL and check if it functions as expected
func removeEntries(a *Acl, entries map[*AclEntry]bool, expected bool) (bool, error) {
	for e, _ := range entries {
		err := a.removeEntry(e.EntityName)
		if expected == true && err != nil {
			return false, fmt.Errorf("Error: Can't remove the valid entry '%v' from ACL list: %v", e, a)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("Error: Attempting to remove the non existing entry '%v' from ACL list: %v", e, a)
		}
	}
	return true, nil
}

// Verify that empty entries can't be added
// Verify that the same entry can be added to both lists: user and group
// Verify that an entry is removed only from the relevant list
// At the end of the test, the entries list must by empty
func Test_AddRemoveAclEntry(t *testing.T) {
	expected := []bool{true, false}

	_, a, entries, err := initAclAndEntries(10)
	if err != nil {
		t.Error("Test fail: Can't initalize entry list, error:", err)
		t.FailNow()
	}

	err = a.addEntry(nil)
	if err == nil {
		t.Error("Test fail: nil entry was added:", a)
	}

	for _, exp := range expected {
		_, err := addEntries(a, entries, exp)
		if err != nil {
			t.Errorf("Test fail: %v", err)
			t.FailNow()
		}
	}
	for _, exp := range expected {
		_, err := removeEntries(a, entries, exp)
		if err != nil {
			t.Errorf("Test fail: %v", err)
		}
	}
	if len(a.Permissions) != 0 {
		t.Error("Test fail: The entry list of", a, "must be empty")
	}
}

func isPermissionExp(pVec []Permission, permission Permission) bool {
	for _, p := range pVec {
		if p == permission {
			return true
		}
	}
	return false
}

// Create a new el, ACL and add to it users and groups. Initialize the permissions of each of the entries using predefined data
// setPermissionData: Determines whether the permissions of the given entries should be set during initializion
func setupCheckPermissions(setPermissionData bool) (*en.EntityManager, *Acl, []string, []entryS, []entryS, [][]expectS, [][]expectS, []expectWhoUsePermissionsS) {
	a := NewACL()
	el := initEntityManager()
	numOfUsers := 5
	numOfGroups := 3
	usersName := make([]string, numOfUsers)
	groupsName := make([]string, numOfGroups)
	allNames := make([]string, numOfUsers+numOfGroups)

	for i := 0; i < numOfUsers; i++ {
		usersName[i] = "a" + fmt.Sprintf("%d", i)
		allNames[i] = usersName[i]
	}
	for i := 0; i < numOfGroups; i++ {
		groupsName[i] = "testGroup" + fmt.Sprintf("%d", i)
		allNames[i+numOfUsers] = groupsName[i]
	}
	groupsData := []testGroupS{{groupsName[0], []string{usersName[0], usersName[2]}},
		{groupsName[1], []string{usersName[1]}}}

	setEntries := []entryS{
		{usersName[0], []Permission{PerRead, PerWrite, PerExe}},
		{groupsName[0], []Permission{PerRead}},
		{groupsName[1], []Permission{PerExe, PerTake}},
		{stc.AclAllEntryName, []Permission{PerAll}}}
	resetEntries := []entryS{ // note the remove can be done for a single user/group in each step
		{}, // check the setup
		{groupsName[1], []Permission{PerExe}},
		{usersName[0], []Permission{PerRead}},
		{groupsName[0], []Permission{PerRead}},
		{usersName[0], []Permission{PerWrite}}}
	// test both that the expected permissions are set and that the others are clear
	expectUserPermissions := [][]expectS{
		{{usersName[0], []Permission{PerRead, PerWrite, PerExe, PerAll}}, {usersName[1], []Permission{PerExe, PerTake, PerAll}}},
		{{usersName[0], []Permission{PerRead, PerWrite, PerExe, PerAll}}, {usersName[1], []Permission{PerAll, PerTake}}},
		{{usersName[0], []Permission{PerWrite, PerExe, PerRead, PerAll}}, {usersName[1], []Permission{PerAll, PerTake}}},
		{{usersName[0], []Permission{PerWrite, PerExe, PerAll}}, {usersName[1], []Permission{PerAll, PerTake}}},
		{{usersName[0], []Permission{PerExe, PerAll}}, {usersName[1], []Permission{PerAll, PerTake}}}}
	expectGroupPermissions := [][]expectS{
		{{groupsName[0], []Permission{PerRead, PerAll}}, {groupsName[1], []Permission{PerExe, PerTake, PerAll}}},
		{{groupsName[0], []Permission{PerRead, PerAll}}, {groupsName[1], []Permission{PerTake, PerAll}}},
		{{groupsName[0], []Permission{PerRead, PerAll}}, {groupsName[1], []Permission{PerTake, PerAll}}},
		{{groupsName[0], []Permission{PerAll}}, {groupsName[1], []Permission{PerTake, PerAll}}},
		{{groupsName[0], []Permission{PerAll}}, {groupsName[1], []Permission{PerTake, PerAll}}}}
	expectWhoUsePermission := []expectWhoUsePermissionsS{
		{PerExe, []string{usersName[0], usersName[1], groupsName[1]}},
		{PerAll, []string{usersName[0], usersName[1], usersName[2], groupsName[0], groupsName[1], stc.AclAllEntryName}},
		{"aa", []string{}},
	}
	for _, gData := range groupsData {
		el.AddGroup(gData.name)
		for _, name := range gData.members {
			el.AddUser(name)
			el.AddUserToGroup(gData.name, name)
		}
	}
	var e *AclEntry
	for _, v := range setEntries {
		e, _ = a.Permissions[v.name]
		if e == nil {
			e, _ = NewEntry(v.name)
		}
		if setPermissionData {
			for _, p := range v.permissions {
				e.AddPermission(p)
			}
		}
		a.addEntry(e)
	}
	el.AddPropertyToEntity(resourceName, stc.AclPropertyName, a)
	//	el.PrintWithProperties()
	return el, a, allNames, setEntries, resetEntries, expectUserPermissions, expectGroupPermissions, expectWhoUsePermission
}

func checkExp(t *testing.T, el *en.EntityManager, a *Acl, idx int, name string, expState []expectS) {
	for _, exp := range expState {
		if exp.name == name {
			for _, p := range permissionsVec {
				exp := isPermissionExp(exp.permissions, p)
				expStr := "set"
				if exp == false {
					expStr = "clear"
				}
				ok := CheckUserPermission(el, name, resourceName, p)
				if ok != exp {
					t.Error("Test fail: Error in Step:", idx, ": user:", name, ", permission:", p, "was expected to be", expStr)
				}
			}
		}
	}
}

// Test that the object's permissions are as expected in each step of the test.
//    In each of the test's steps, permissions could be added or removed
//    and the test checks that only the expected permissions, after the change, are set
// 2 entries:
// First entry a1: user: read, write, exe, group read
// Second entry a2: user: nil, group exe
// Tests:
// setup: First entry: permissions: read, write, exe, no take
//        Second entry: permissions: group exe only
// Test that empty permission is allowed and results with the behaviour that is determined by the default
// Note for all tests: test that the expected permissions are set and the others are clear
// Step 1. Remove exe permission from the second entry => no permissions
// Step 2. Remove read from the first entry of the users list => read, write, exe, no take
// Step 3. Remove read from the first entry of the groups list => write, exe, no read, take
// Step 4. Remove write from the first entry of the groups list => exe only
func Test_Permissions(t *testing.T) {
	el, a, usersName, _, resetEntries, expectUserPermissions, expectGroupPermissions, _ := setupCheckPermissions(true)

	el.GetPropertyAttachedToEntity(resourceName, stc.AclPropertyName)
	ok := CheckUserPermission(el, usersName[0], resourceName, "")
	if ok == true {
		t.Error("Test fail: Error empty permission were allowed")
	}
	for i, v := range resetEntries {
		e, _ := a.Permissions[v.name]
		for _, p := range v.permissions {
			e.RemovePermission(p)
		}
		for _, name := range usersName {
			checkExp(t, el, a, i, name, expectUserPermissions[i])
			checkExp(t, el, a, i, name, expectGroupPermissions[i])
		}
	}
}

// THe same test as Test_Permissions, but in this test, the permissions are updated by
// calling AddPermission/RemovePermission with the entry name/type and the updated permissions
func Test_UpdatePermissions(t *testing.T) {
	el, a, usersName, setEntries, resetEntries, expectUserPermissions, expectGroupPermissions, _ := setupCheckPermissions(false)

	for _, v := range setEntries {
		for _, p := range v.permissions {
			a.AddPermissionToResource(el, v.name, p)
		}
	}

	for i, v := range resetEntries {
		for _, p := range v.permissions {
			a.RemovePermissionFromEntity(v.name, p)
		}
		for _, name := range usersName {
			checkExp(t, el, a, i, name, expectUserPermissions[i])
			checkExp(t, el, a, i, name, expectGroupPermissions[i])
		}
	}
}

// Verify that a nil groups list returns no permissions
// Verify that permission can't be added to a nil groups list
// Verify that permission can't be added to an undefined group
// Verify that removal of a user from a group removes that user's permissions
func Test_GroupListCorrectness(t *testing.T) {
	el := initEntityManager()
	a := NewACL()

	el.AddPropertyToEntity(resourceName, stc.AclPropertyName, a)
	if CheckUserPermission(el, userName, resourceName, PerRead) == true {
		t.Error("Test fail: Have permissions for empty lists")
	}
	err := a.AddPermissionToResource(el, groupName, PerRead)
	if err == nil {
		t.Error("Test fail: Set permissions for a group but the group list is nil", a)
	}
	err = a.AddPermissionToResource(el, groupName, PerRead)
	if err == nil {
		t.Error("Test fail: Set permissions for an unknown group", groupName, a)
	}
	el.AddGroup(groupName)
	el.AddUser(userName)
	el.AddUserToGroup(groupName, userName)
	e, _ := NewEntry(groupName)
	a.addEntry(e)
	a.AddPermissionToResource(el, groupName, PerRead)
	if CheckUserPermission(el, userName, resourceName, PerRead) != true {
		t.Errorf("Test fail: '%v' permission must be set, %v", PerRead, a)
	}
	el.RemoveUserFromGroup(groupName, userName)
	if CheckUserPermission(el, userName, resourceName, PerRead) == true {
		t.Errorf("Test fail: user: %v doesn't have permission '%v', %v", userName, PerRead, a)
	}
}

// Verify that if a permission set to the All ACL list it is valid for all users
func Test_AllListPermissions(t *testing.T) {
	el := initEntityManager()
	a := NewACL()
	el.AddUser(userName)
	el.AddPropertyToEntity(resourceName, stc.AclPropertyName, a)
	a.AddPermissionToResource(el, stc.AclAllEntryName, PerRead)
	if CheckUserPermission(el, userName, resourceName, PerRead) != true {
		t.Errorf("Test fail: '%v' permission must be set, %v", PerRead, a)
	}
	if CheckUserPermission(el, userName, resourceName, PerWrite) == true {
		t.Errorf("Test fail: '%v' permission must be clear, %v", PerWrite, a)
	}
}

// Verify that if a user was a member of a group in an ACL of entity with a permission
// If the group was removed, the user doesn't have the permission
// than the permission was added to the user, the user have the permission
// and than the user was removed from the list and readded (maybe its another user), it doesn't have the permission
func Test_CheckPermissionWhenUserIsRemovedAndAdded(t *testing.T) {
	el := initEntityManager()
	a := NewACL()
	p := Permission(PerRead)
	// create entity list with disk, user, group entities (user1 is part of group)
	// set ACL to disk, add the group entry with read permission to disk ACL
	el.AddUser(userName)
	el.AddGroup(groupName)
	el.AddUserToGroup(groupName, userName)
	el.AddPropertyToEntity(resourceName, stc.AclPropertyName, a)
	entry, _ := NewEntry(groupName)
	a.addEntry(entry)
	entry.AddPermission(p)
	if CheckUserPermission(el, userName, resourceName, p) != true {
		t.Errorf("Test fail: '%v' permission must be set, %v", p, a)
	}
	el.RemoveGroupAddUserToGroup(groupName)
	if CheckUserPermission(el, userName, resourceName, p) == true {
		t.Errorf("Test fail: '%v' permission must not be allowed, %v", p, a)
	}
	entry, _ = NewEntry(userName)
	a.addEntry(entry)
	entry.AddPermission(p)
	if CheckUserPermission(el, userName, resourceName, p) != true {
		t.Errorf("Test fail: '%v' permission must be set, %v", p, a)
	}
	el.RemoveUserAddUserToGroup(userName)
	el.AddUser(userName)
	if CheckUserPermission(el, userName, resourceName, p) == true {
		t.Errorf("Test fail: '%v' permission must not be allowed, %v", p, a)
	}
}

func Test_WhoUsesPermissions(t *testing.T) {
	el, _, _, _, _, _, _, expectWhoUse := setupCheckPermissions(true)
	for _, v := range expectWhoUse {
		permissionSet := GetWhoUseAPermission(el, resourceName, v.permission)
		for _, name := range v.names {
			if permissionSet[name] == false {
				t.Error("Error: user", name, "permission", v.permission, "was not found")
			}
		}
		if len(v.names) != len(permissionSet) {
			t.Error("Error: users list", v.names, "are not equal to permissions list", permissionSet, "len1:", len(v.names), "len2:", len(permissionSet))
		}
	}
}

func generateAcl(el *en.EntityManager) bool {
	for n, _ := range el.Resources {
		tmpE, _ := el.GetPropertyAttachedToEntity(n, stc.AclPropertyName)
		a, ok := tmpE.(*Acl)
		if ok == false {
			return false
		}
		for name, _ := range el.Users {
			a.AddPermissionToResource(el, name, Permission("uP"+n))
		}
	}
	return true
}

func Test_StoreLoad(t *testing.T) {
	filePath := "./try.txt"
	secret := []byte("ABCDEFGH12345678")

	el := en.NewEntityManager()
	for i := 0; i < 3; i++ {
		el.AddUser(fmt.Sprintf("User %d", i+1))
		resourceName := fmt.Sprintf("Disk %d", i+1)
		el.AddResource(resourceName)
		a := NewACL()
		el.AddPropertyToEntity(resourceName, stc.AclPropertyName, a)
	}

	if generateAcl(el) == false {
		t.Error("Test fail, can't generate ACL")
		t.FailNow()
	}
	el.StoreInfo(filePath, secret)

	entityManager1 := en.NewEntityManager()
	err := en.LoadInfo(filePath, secret, entityManager1)
	if err != nil {
		fmt.Println(err)
	}

	for n, _ := range el.Resources {
		tmpE, _ := el.GetPropertyAttachedToEntity(n, stc.AclPropertyName)
		a := tmpE.(*Acl)
		tmpE1, _ := entityManager1.GetPropertyAttachedToEntity(n, stc.AclPropertyName)
		a1 := tmpE1.(*Acl)
		if a.IsEqual(*a1) == false {
			t.Errorf("Test fail, Stored ACL property != loaded one")
			fmt.Println("The stored ACL for resource:", n, a)
			fmt.Println("The loaded ACL for resource:", n, a1)
		}
	}
}
