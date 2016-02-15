package acl

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"testing"
	"reflect"

	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
)

const (
	userName     = "user1"
	groupName    = "Group1"
	resourceName = "disk"
)

var ()

type aclTestEntry struct {
	name        string // aclAclEntry name
	permissions []en.Permission
}

type expectTest struct {
	name        string // aclAclEntry name
	permissions []en.Permission
}

type expectWhoUsePermissions struct {
	permission string
	names      []string
}

type testGroup struct {
	name    string
	members []string
}

type AclTestMap map[*Entry]bool

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)
}

func initEntityManager() *en.EntityManager {
	el := en.New()
	el.AddResource(resourceName)
	return el
}

// Create a new ACL, add a given number of entities to Entity list,
// Add each new entity to the new ACL
func initAclAndEntries(length int) (*en.EntityManager, *Acl, AclTestMap, error) {
	var entries AclTestMap

	el := initEntityManager()
	a := NewACL()
	entries = make(AclTestMap)
	for i := 0; i < length; i++ {
		name := "name[0]-a" + strconv.Itoa(i)
		el.AddResource(name)
		e, err := NewEntry(name)
		if err != nil {
			return nil, nil, entries, err
		}
		if e == nil {
			return nil, nil, entries, fmt.Errorf("can't add the new aclAclEntry '%v' to the ACL list", name)
		}
		entries[e] = true
	}
	return el, a, entries, nil
}

// Try to add a new Entry to a given ACL and check if it functions as expected
func addEntries(a *Acl, entries AclTestMap, expected bool) (bool, error) {
	for e := range entries {
		err := a.addAclEntry(e)
		if expected == true && err != nil {
			return false, fmt.Errorf("can't add the valid aclAclEntry '%v', ACL list: %v", e, a)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("attempting to add an already existing aclAclEntry '%v' to the ACL list: %v", e, a)
		}
	}
	return true, nil
}

// Try to remove an aclAclEntry from a given ACL and check if it functions as expected
func removeEntries(a *Acl, entries AclTestMap, expected bool) (bool, error) {
	for e := range entries {
		err := a.removeAclEntry(e.EntityName)
		if expected == true && err != nil {
			return false, fmt.Errorf("can't remove the valid aclAclEntry '%v' from ACL list: %v", e, a)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("attempting to remove the non existing aclAclEntry '%v' from ACL list: %v", e, a)
		}
	}
	return true, nil
}

// Verify that empty entries can't be added
// Verify that the same aclAclEntry can be added to both lists: user and group
// Verify that an aclAclEntry is removed only from the relevant list
// At the end of the test, the entries list must by empty
func Test_AddRemoveaclEntry(t *testing.T) {
	expected := []bool{true, false}

	_, a, entries, err := initAclAndEntries(10)
	if err != nil {
		t.Error("Test fail: Can't initalize aclAclEntry list, error:", err)
		t.FailNow()
	}

	err = a.addAclEntry(nil)
	if err == nil {
		t.Error("Test fail: nil aclAclEntry was added:", a)
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
		t.Error("Test fail: The aclAclEntry list of", a, "must be empty")
	}
}

func isPermissionExp(pVec []en.Permission, permission en.Permission) bool {
	for _, p := range pVec {
		if p == permission {
			return true
		}
	}
	return false
}

// Create a new el, ACL and add to it users and groups. Initialize the permissions of each of the entries using predefined data
// setPermissionData: Determines whether the permissions of the given entries should be set during initializion
func setupCheckPermissions(setPermissionData bool) (*en.EntityManager, *Acl, []string, []aclTestEntry, []aclTestEntry, [][]expectTest, [][]expectTest, []expectWhoUsePermissions) {
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
	groupsData := []testGroup{{groupsName[0], []string{usersName[0], usersName[2]}},
		{groupsName[1], []string{usersName[1]}}}

	setEntries := []aclTestEntry{
		{usersName[0], []en.Permission{PerRead, PerWrite, PerExe}},
		{groupsName[0], []en.Permission{PerRead}},
		{groupsName[1], []en.Permission{PerExe, PerTake}},
		{defs.AclAllEntryName, []en.Permission{PerAll}}}
	resetEntries := []aclTestEntry{ // note the remove can be done for a single user/group in each step
		{}, // check the setup
		{groupsName[1], []en.Permission{PerExe}},
		{usersName[0], []en.Permission{PerRead}},
		{groupsName[0], []en.Permission{PerRead}},
		{usersName[0], []en.Permission{PerWrite}}}
	// test both that the expected permissions are set and that the others are clear
	expectUserPermissions := [][]expectTest{
		{{usersName[0], []en.Permission{PerRead, PerWrite, PerExe, PerAll}}, {usersName[1], []en.Permission{PerExe, PerTake, PerAll}}},
		{{usersName[0], []en.Permission{PerRead, PerWrite, PerExe, PerAll}}, {usersName[1], []en.Permission{PerAll, PerTake}}},
		{{usersName[0], []en.Permission{PerWrite, PerExe, PerRead, PerAll}}, {usersName[1], []en.Permission{PerAll, PerTake}}},
		{{usersName[0], []en.Permission{PerWrite, PerExe, PerAll}}, {usersName[1], []en.Permission{PerAll, PerTake}}},
		{{usersName[0], []en.Permission{PerExe, PerAll}}, {usersName[1], []en.Permission{PerAll, PerTake}}}}
	expectGroupPermissions := [][]expectTest{
		{{groupsName[0], []en.Permission{PerRead, PerAll}}, {groupsName[1], []en.Permission{PerExe, PerTake, PerAll}}},
		{{groupsName[0], []en.Permission{PerRead, PerAll}}, {groupsName[1], []en.Permission{PerTake, PerAll}}},
		{{groupsName[0], []en.Permission{PerRead, PerAll}}, {groupsName[1], []en.Permission{PerTake, PerAll}}},
		{{groupsName[0], []en.Permission{PerAll}}, {groupsName[1], []en.Permission{PerTake, PerAll}}},
		{{groupsName[0], []en.Permission{PerAll}}, {groupsName[1], []en.Permission{PerTake, PerAll}}}}
	expectWhoUsePermission := []expectWhoUsePermissions{
		{PerExe, []string{usersName[0], usersName[1], groupsName[1]}},
		{PerAll, []string{usersName[0], usersName[1], usersName[2], groupsName[0], groupsName[1], defs.AclAllEntryName}},
		{"aa", []string{}},
	}
	for _, gData := range groupsData {
		el.AddGroup(gData.name)
		for _, name := range gData.members {
			el.AddUser(name)
			el.AddUserToGroup(gData.name, name)
		}
	}
	var e *Entry
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
		a.addAclEntry(e)
	}
	el.AddPropertyToEntity(resourceName, defs.AclPropertyName, a)
	//	el.PrintWithProperties()
	return el, a, allNames, setEntries, resetEntries, expectUserPermissions, expectGroupPermissions, expectWhoUsePermission
}

func checkExp(t *testing.T, el *en.EntityManager, a *Acl, idx int, name string, expState []expectTest) {
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
// First aclAclEntry a1: user: read, write, exe, group read
// Second aclAclEntry a2: user: nil, group exe
// Tests:
// setup: First Entry: permissions: read, write, exe, no take
//        Second Entry: permissions: group exe only
// Test that empty permission is allowed and results with the behaviour that is determined by the default
// Note for all tests: test that the expected permissions are set and the others are clear
// Step 1. Remove exe permission from the second aclAclEntry => no permissions
// Step 2. Remove read from the first aclAclEntry of the users list => read, write, exe, no take
// Step 3. Remove read from the first aclAclEntry of the groups list => write, exe, no read, take
// Step 4. Remove write from the first aclAclEntry of the groups list => exe only
func Test_Permissions(t *testing.T) {
	el, a, usersName, _, resetEntries, expectUserPermissions, expectGroupPermissions, _ := setupCheckPermissions(true)

	el.GetPropertyAttachedToEntity(resourceName, defs.AclPropertyName)
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
// calling AddPermission/RemovePermission with the aclAclEntry name/type and the updated permissions
func Test_UpdatePermissions(t *testing.T) {
	el, a, usersName, setEntries, resetEntries, expectUserPermissions, expectGroupPermissions, _ := setupCheckPermissions(false)

	for _, v := range setEntries {
		for _, p := range v.permissions {
			el.AddPermission(en.Permission(p))
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

	el.AddPropertyToEntity(resourceName, defs.AclPropertyName, a)
	if CheckUserPermission(el, userName, resourceName, PerRead) == true {
		t.Error("Test fail: Have permissions for empty lists")
	}
	el.AddPermission(en.Permission(PerRead))
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
	a.addAclEntry(e)
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
	el.AddPropertyToEntity(resourceName, defs.AclPropertyName, a)
	el.AddPermission(en.Permission(PerRead))
	a.AddPermissionToResource(el, defs.AclAllEntryName, PerRead)
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
	p := en.Permission(PerRead)
	// create entity list with disk, user, group entities (user1 is part of group)
	// set ACL to disk, add the group aclAclEntry with read permission to disk ACL
	el.AddUser(userName)
	el.AddGroup(groupName)
	el.AddUserToGroup(groupName, userName)
	el.AddPropertyToEntity(resourceName, defs.AclPropertyName, a)
	Entry, _ := NewEntry(groupName)
	a.addAclEntry(Entry)
	Entry.AddPermission(p)
	if CheckUserPermission(el, userName, resourceName, p) != true {
		t.Errorf("Test fail: '%v' permission must be set, %v", p, a)
	}
	el.RemoveGroup(groupName)
	if CheckUserPermission(el, userName, resourceName, p) == true {
		t.Errorf("Test fail: '%v' permission must not be allowed, %v", p, a)
	}
	Entry, _ = NewEntry(userName)
	a.addAclEntry(Entry)
	Entry.AddPermission(p)
	if CheckUserPermission(el, userName, resourceName, p) != true {
		t.Errorf("Test fail: '%v' permission must be set, %v", p, a)
	}
	el.RemoveUser(userName)
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
	for n := range el.Resources {
		tmpE, _ := el.GetPropertyAttachedToEntity(n, defs.AclPropertyName)
		a, ok := tmpE.(*Acl)
		if ok == false {
			return false
		}
		for name := range el.Users {
			a.AddPermissionToResource(el, name, en.Permission("uP"+n))
		}
	}
	return true
}

func Test_StoreLoad(t *testing.T) {
	filePath := "./try.txt"
	secret := []byte("ABCDEFGH12345678")

	el := en.New()
	for i := 0; i < 3; i++ {
		el.AddUser(fmt.Sprintf("User %d", i+1))
		resourceName := fmt.Sprintf("Disk %d", i+1)
		el.AddResource(resourceName)
		a := NewACL()
		el.AddPropertyToEntity(resourceName, defs.AclPropertyName, a)
	}

	if generateAcl(el) == false {
		t.Error("Test fail, can't generate ACL")
		t.FailNow()
	}
	el.StoreInfo(filePath, secret, false)
	entityManager1 := en.New()
	err := en.LoadInfo(filePath, secret, entityManager1)
	if err != nil {
		fmt.Println(err)
	}

	as := defs.Serializers[defs.AclPropertyName]	
	for n := range el.Resources {
		tmpE, _ := el.GetPropertyAttachedToEntity(n, defs.AclPropertyName)
		a := tmpE.(*Acl)
		tmpE1, _ := entityManager1.GetPropertyAttachedToEntity(n, defs.AclPropertyName)
		a1 := tmpE1.(*Acl)
		if a.IsEqual(*a1) == false || as.IsEqualProperties(a, a1) == false {
			t.Errorf("Test fail, Stored ACL property != loaded one")
			fmt.Println("The stored ACL for resource:", n, a)
			fmt.Println("The loaded ACL for resource:", n, a1)
		}
		eq := reflect.DeepEqual(a.GetAllPermissions(), a1.GetAllPermissions())
		logger.Trace.Println("Data:", as.PrintProperties(a))
		if eq == false {
			t.Errorf("Test fail, Stored ACL permissions %v != loaded one %v", a.GetAllPermissions(), a1.GetAllPermissions())
		}
	}
}
