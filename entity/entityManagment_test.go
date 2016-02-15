package entityManagement

import (
	"fmt"
	"math"
	"io/ioutil"
	"testing"
	"time"

	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	am "github.com/ibm-security-innovation/libsecurity-go/accounts"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
)

var (
	secret = []byte("ABCDEFGH12345678")
	salt   = []byte("Salt")
)

// Print an EntityManager with its properties
func (el *EntityManager) getEntityManagerStrWithProperties() string {
	str := ""
	for _, e := range el.Users {
		str += fmt.Sprintf("%v:", userTypeStr)
		str += e.Entity.getEntityStrWithProperties()
	}
	for _, e := range el.Groups {
		str += fmt.Sprintf("%v:", groupTypeStr)
		str += e.getGroupStrWithProperties()
	}
	for _, e := range el.Resources {
		str += fmt.Sprintf("%v:", resourceTypeStr)
		str += e.Entity.getEntityStrWithProperties()
	}
	return str
}

func (el *EntityManager) contains(el1 *EntityManager) bool {
	if el1 == nil {
		return false
	}
	for _, e := range el.Users {
		e1, _ := el1.getUser(e.Name)
		if e1 == nil || e.isEqualUser(e1) == false {
			return false
		}
		if e.isEqualProperties(e1.Entity) == false {
			return false
		}
	}
	for _, g := range el.Groups {
		g1, _ := el1.getGroup(g.Name)
		if g1 == nil || g.isEqualGroup(g1) == false {
			return false
		}
		if g.isEqualProperties(g1.Entity) == false {
			return false
		}
	}
	for _, e := range el.Resources {
		e1, _ := el1.getResource(e.Name)
		if e1 == nil || e.isEqualResource(e1) == false {
			return false
		}
		if e.isEqualProperties(e1.Entity) == false {
			return false
		}
	}
	return true
}

// Compare 2 EntityManagers including all their entities, members and properties
func (el *EntityManager) IsEqual(el1 *EntityManager) bool {
	if el1 == nil {
		return false
	}
	return el.contains(el1) && el1.contains(el)
}

func getGroupFormat(name string) string {
	return "G-" + name
}

func addEntities(el *EntityManager, typeStr string, names []string, expected bool) (bool, error) {
	var err error
	var groupName string

	for i, name := range names {
		if typeStr == userTypeStr {
			err = el.AddUser(name)
		} else if typeStr == groupTypeStr {
			el.AddUser(name)
			groupName = getGroupFormat(name)
			err = el.AddGroup(groupName)
		} else if typeStr == resourceTypeStr {
			err = el.AddResource(name)
		}else {
			err = el.AddPermission(Permission(name))
		}
		if expected == true && err != nil {
			return false, fmt.Errorf("Cannot add a valid %v name '%v' to the entity list %v, error: %v", typeStr, name, el, err)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("Attempting to add an existing %v ('%v') to the entity list %v", typeStr, name, el)
		}
		if typeStr == permissionTypeStr {
			if el.IsPermissionInList(Permission(name)) == false {
				return false, fmt.Errorf("%v '%v' added to the permissions list but was not found in %v", typeStr, name, el.Permissions)
			}
		}else if el.IsEntityInList(name) == false {
			return false, fmt.Errorf("%v '%v' added to the entity list but was not found in %v", typeStr, name, el)
		}
		if typeStr == groupTypeStr {
			for j, name1 := range names {
				err := el.AddUserToGroup(groupName, name1)
				if err == nil && i < j && expected == true {
					return false, fmt.Errorf("User '%v' is not part of the entity list %v but was added as a member", name1, el)
				}
				if err != nil && i >= j {
					return false, fmt.Errorf("User '%v' is part of the entity list %v but was not added as a member, error: %v", name1, el, err)
				}
				_, err = el.getGroup(groupName)
				if err != nil {
					return false, fmt.Errorf("%v '%v' added to the entity list but was not found in %v", typeStr, name, el)
				}
				el.RemoveUserFromGroup(groupName, name1)
			}
		}
	}
	return true, nil
}

func removeEntities(el *EntityManager, typeStr string, names []string, expected bool) (bool, error) {
	var err error

	for _, name := range names {
		if typeStr == userTypeStr {
			err = el.RemoveUser(name)
		} else if typeStr == groupTypeStr {
			el.RemoveUser(name)
			err = el.RemoveGroup(getGroupFormat(name))
		} else if typeStr == resourceTypeStr{
			err = el.RemoveResource(name)
		}else {
			err = el.RemovePermission(Permission(name))
		}
		if expected == true && err != nil {
			return false, fmt.Errorf("Cannot remove a valid %v '%v' from the entity list %v", typeStr, name, el)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("Removed an already removed %v '%v' from entity list %v", typeStr, name, el)
		}
		if typeStr == userTypeStr {
			_, err = el.getUser(name)
		} else if typeStr == groupTypeStr {
			_, err = el.getGroup(name)
		} else if typeStr == resourceTypeStr {
			_, err = el.getResource(name)
		} else {
			if el.IsPermissionInList(Permission(name)) == true {
				return false, fmt.Errorf("%v '%v' found in permissions list %v after it was removed", typeStr, name, el.Permissions)
			}
		}
		if err == nil && typeStr != permissionTypeStr {
			return false, fmt.Errorf("%v '%v' found in entity list %v after it was removed", typeStr, name, el)
		}
	}
	return true, nil
}

/*

	The real tests
==============================




*/

// Test that an empty entity can't be added to the entity list
// Verify that the same entity can be added only once
// Verify that entity can be added to members list only when the entity is already in the entity list
// Verify that entity is removed only once
// Verift that at the end of the test, the entity list must be empty
func Test_AddGetRemoveEntity(t *testing.T) {
	expected := []bool{true, false}
	names := []string{"a", "a1", "a2"}
	types := []string{userTypeStr, groupTypeStr, resourceTypeStr, permissionTypeStr}

	for _, typeStr := range types {
		el := New()
		for _, exp := range expected {
			_, err := addEntities(el, typeStr, names, exp)
			if err != nil {
				t.Errorf("Test fail: %v", err)
				t.FailNow()
			}
		}
		for _, exp := range expected {
			_, err := removeEntities(el, typeStr, names, exp)
			if err != nil {
				t.Errorf("Test fail: %v", err)
			}
		}
		if len(el.Users) != len(protectedEntityManager) || len(el.Groups) != 0 || len(el.Resources) != 0 {
			t.Error("Test fail: The entity list:", el, "must be with only the following entities:", protectedEntityManager)
		}
		if len(el.Permissions) != 0 {
			t.Error("Test fail: The permissions list:", el.Permissions, "must be empty")
		}
	}
}

// Verift that 2 entity list are equal only if all their data is equal
func Test_EntityManagerIsEqual(t *testing.T) {
	names := []string{"g1", "g2", "g3"}
	resourceNames := []string{"r1", "r2"}
	userName := "user1"
	len := 3
	var el [3]*EntityManager

	for i := 0; i < len; i++ {
		el[i] = New()
		addEntities(el[i], groupTypeStr, names, true)
		if i > 0 {
			if el[i].IsEqual(el[i-1]) == false {
				t.Errorf("Test fail: entity list %v: %v must be equal to entity list %v %v", i, el[i], i-1, el[i-1])
			}
		}
	}
	a1, _ := am.NewUserAm(am.UserPermission, secret, salt, false)
	el[0].AddPropertyToEntity(getGroupFormat(names[1]), defs.AmPropertyName, a1)
	el[2].AddPropertyToEntity(getGroupFormat(names[1]), defs.AmPropertyName, a1)
	el[1].AddUser(userName)
	el[1].AddUserToGroup(getGroupFormat(names[1]), userName)
	logger.Trace.Println("Entity data", el[1].String(), el[1].GetGroupUsers(getGroupFormat(names[1])))
	if el[1].IsUserPartOfAGroup(getGroupFormat(names[1]), userName) == false {
		t.Errorf("user '%v' should be part of group %v in entity %v\n", userName, getGroupFormat(names[1]), el[1])
	}
	if el[1].IsUserPartOfAGroup(names[0], userName) == true {
		t.Errorf("user '%v' should not be part of group entity %v\n", userName, el[1])
	}
	el[2].RemovePropertyFromEntity(getGroupFormat(names[1]), defs.AmPropertyName)
	for i := 0; i < len; i++ {
		for j := 0; j < len; j++ {
			if i != j && el[i].IsEqual(el[j]) == true {
				t.Errorf("Test fail: entity list %v:\n%v is not equal to entity list %v:\n%v", i, el[i].getEntityManagerStrWithProperties(), j, el[j].getEntityManagerStrWithProperties())
			}
		}
	}
	err := el[2].RemovePropertyFromEntity(names[1], defs.AmPropertyName)
	if err == nil {
		t.Errorf("Test fail: successfully removed undefined property %v", names[1])
	}
	el[2].AddPropertyToEntity(names[1], defs.AmPropertyName, a1)
	err = el[2].RemovePropertyFromEntity(names[1], defs.AmPropertyName)
	if err != nil {
		t.Errorf("Test fail: fail to removed property %v from el %v", userName, el[2])
	}
	addEntities(el[2], resourceTypeStr, resourceNames, true)
	el[2].AddPropertyToEntity(resourceNames[0], defs.AmPropertyName, a1)
	err = el[2].RemovePropertyFromEntity(resourceNames[0], defs.AmPropertyName)
	if err != nil {
		t.Errorf("Test fail: fail to removed property %v from el %v, error: %v", resourceNames[0], el[2], err)
	}
	err = el[2].RemovePropertyFromEntity("undef1", defs.AmPropertyName)
	if err == nil {
		t.Errorf("Test fail: Successfully removed undefined property from el %v", el[2])
	}
}

// Verift that entities in entity list retun OK only if the entity is in the list and the password match
// Verify that the throttling delay is the same for cases were the user is not in the list as well as if the password does not match
func Test_VerifyEntityPasswordAndTimmingAttack(t *testing.T) {
	baseName := "a"
	types := []string{userTypeStr, groupTypeStr, resourceTypeStr}
	throttleDelayMiliSec := int64(100)
	randomThrottling := int64(3)
	allowedErrorP := float64(randomThrottling + 1)

	el := New()
	for _, typeStr := range types {
		user := []string{baseName + typeStr}
		_, err := addEntities(el, typeStr, user, true)
		if err != nil {
			t.Errorf("Test fail: %v", err)
			t.FailNow()
		}
		pass := []byte(string(secret) + typeStr)
		a1, _ := am.NewUserAm(am.UserPermission, pass, salt, false)
		el.AddPropertyToEntity(user[0], defs.AmPropertyName, a1)
	}
	for _, typeStr := range types {
		user := baseName + typeStr
		pass := []byte(string(secret) + typeStr)
		for _, typeStr1 := range types {
			user1 := baseName + typeStr1
			start := time.Now()
			_, err := el.GetEntityAccountHandler(user1, pass, throttleDelayMiliSec, randomThrottling)
			totalDelay := float64(time.Since(start) / time.Millisecond)
			errorP := math.Abs(float64(totalDelay/float64(throttleDelayMiliSec))-1) * 100
			if typeStr == typeStr1 && err != nil {
				t.Errorf("Test fail: user %v with pass %v was not found, error: %v", user1, pass, err)
				t.FailNow()
			}
			if typeStr != typeStr1 && errorP > allowedErrorP {
				t.Errorf("Test fail: the throttling %v was not as expected %v with tolerance of %v%%", totalDelay, throttleDelayMiliSec, allowedErrorP)
				t.FailNow()
			}
			if typeStr != typeStr1 && err == nil {
				t.Errorf("Test fail: user %v with pass %v match user %v with different password", user, pass, user1)
				t.FailNow()
			}
		}
	}
	for _, typeStr := range types {
		user := []string{baseName + typeStr}
		pass := []byte(string(secret) + typeStr)
		_, err := removeEntities(el, typeStr, user, true)
		if err != nil {
			t.Errorf("Test fail: %v", err)
		}
		start := time.Now()
		_, err = el.GetEntityAccountHandler(user[0], pass, throttleDelayMiliSec, randomThrottling)
		totalDelay := float64(time.Since(start) / time.Millisecond)
		errorP := math.Abs(float64(totalDelay/float64(throttleDelayMiliSec))-1) * 100
		if err == nil {
			t.Errorf("Test fail: removed user %v with pass %v was found", user, pass)
			t.FailNow()
		} else if err != nil && errorP > allowedErrorP {
			t.Errorf("Test fail: the throttling %v was not as expected %v with tolerance of %v%%", totalDelay, throttleDelayMiliSec, allowedErrorP)
			t.FailNow()
		}
	}
}

func Test_StoreLoad(t *testing.T) {
	filePath := "./try.txt"
	permissions := map[string]interface{}{"add":"", "save":"", "can use it":""}
	size := 20
	usersName := make([]string, size, size)

	for i := 0; i < size; i++ {
		usersName[i] = fmt.Sprintf("User%d", i)
	}
	usersList := New()
	GenerateUserData(usersList, usersName, secret, salt)
	GenerateGroupList(usersList, usersName)
	for p := range permissions {
		usersList.AddPermission(Permission(p))
	}
	//GenerateAcl(st) // done in the acl_test
	logger.Init(ioutil.Discard, ioutil.Discard, ioutil.Discard, ioutil.Discard)
	err := usersList.StoreInfo(filePath, []byte("1234"), true)
	if err == nil {
		t.Errorf("TEst fail: successfully store with easy password")
	}
	usersList.StoreInfo(filePath, secret, false)
	usersList1 := New()
	err = LoadInfo(filePath, secret, nil)
	if err == nil {
		t.Errorf("TEst fail: successfully load from nil storage")
	}
	err = LoadInfo("", secret, nil)
	if err == nil {
		t.Errorf("Test fail: successfully load from undefined file")
	}
	err = LoadInfo(filePath, secret, usersList1)
	if err != nil {
		fmt.Println(err)
	}
	if usersList.IsEqual(usersList1) == false {
		t.Errorf("Test fail, Stored users list != loaded one")
		fmt.Println("The stored entity list:", usersList.getEntityManagerStrWithProperties())
		fmt.Println("The loaded entity list:", usersList1.getEntityManagerStrWithProperties())
	}
	if usersList.Permissions.IsEqual(usersList1.Permissions) == false {
		t.Errorf("Test fail, Stored permissions != loaded one")
		fmt.Println("The stored permisions list:", usersList.Permissions)
		fmt.Println("The loaded permisions list:", usersList1.getPermissions())
	}
}

// Test corners: 
func Test_corners(t *testing.T) {
	userName := "u1"
	groupName := "g1"
	u, _ := newUser(userName)
	g, _ := newGroup(groupName)
	g.addUserToGroup(u.Name)
	err := g.addUserToGroup("")
	if err == nil {
		t.Errorf("Test fail: Success to add undefined user to group")
	}
	logger.Trace.Println("The data is:", g.String())
	err = g.addGroupToStorage(groupName, nil)
	if err == nil {
		t.Errorf("Test fail: Add group to nil storage")
	}
	err = u.Entity.addEntityToStorage(groupName, nil)
	if err == nil {
		t.Errorf("Test fail: Add entity to nil storage")
	}
	err = u.Entity.addProperty(groupName, nil)
	if err == nil {
		t.Errorf("Test fail: Add property with nil data")
	}
	storage, _ := ss.NewStorage([]byte("12345678"), false)
	err = g.addGroupToStorage(groupName, storage)
	if err != nil {
		t.Errorf("Test fail: Can't add group to storage")
	}
	_, err = readEntityFromStorage("a12", storage)
	if err == nil {
		t.Errorf("Test fail: undefined entity name was found in the storage")
	}
	_, err = readEntityFromStorage(groupName, nil)
	if err == nil {
		t.Errorf("Test fail: read entity from nil storage")
	}
	_, err = readGroupFromStorage(groupName, nil)
	if err == nil {
		t.Errorf("Test fail: read group from nil storage")
	}
}
