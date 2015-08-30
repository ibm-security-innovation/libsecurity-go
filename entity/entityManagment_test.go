package entityManagement

import (
	"fmt"
	"testing"

	am "ibm-security-innovation/libsecurity-go/accounts"
	stc "ibm-security-innovation/libsecurity-go/defs"
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
		} else {
			err = el.AddResource(name)
		}
		if expected == true && err != nil {
			return false, fmt.Errorf("can't add a valid %v name '%v' to the entity list %v, error: %v", typeStr, name, el, err)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("attempting to add an existing %v ('%v') to the entity list %v", typeStr, name, el)
		}
		if el.IsEntityInList(name) == false {
			return false, fmt.Errorf("%v '%v' added to the entity list but was not found in %v", typeStr, name, el)
		}
		if typeStr == groupTypeStr {
			for j, name1 := range names {
				err := el.AddUserToGroup(groupName, name1)
				if err == nil && i < j && expected == true {
					return false, fmt.Errorf("user '%v' is not part of the entity list %v but was added as a member", name1, el)
				}
				if err != nil && i >= j {
					return false, fmt.Errorf("user '%v' is part of the entity list %v but was not added as a member, error: %v", name1, el, err)
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
		} else {
			err = el.RemoveResource(name)
		}
		if expected == true && err != nil {
			return false, fmt.Errorf("can't remove a valid %v '%v' from the entity list %v", typeStr, name, el)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("removed an already removed %v '%v' from entity list %v", typeStr, name, el)
		}
		if typeStr == userTypeStr {
			_, err = el.getUser(name)
		} else if typeStr == groupTypeStr {
			_, err = el.getGroup(name)
		} else {
			_, err = el.getResource(name)
		}
		if err == nil {
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
	types := []string{userTypeStr, groupTypeStr, resourceTypeStr}

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
	}
}

// Verift that 2 entity list are equal only if all their data is equal
func Test_EntityManagerIsEqual(t *testing.T) {
	names := []string{"g1", "g2", "g3"}
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
	a1, _ := am.NewUserAm(am.UserPermission, []byte("123456"), []byte("abcd"), false)
	el[0].AddPropertyToEntity(getGroupFormat(names[1]), stc.AmPropertyName, a1)
	el[2].AddPropertyToEntity(getGroupFormat(names[1]), stc.AmPropertyName, a1)
	el[1].AddUser(userName)
	el[1].AddUserToGroup(getGroupFormat(names[1]), userName)
	el[2].RemovePropertyFromEntity(getGroupFormat(names[1]), stc.AmPropertyName)
	for i := 0; i < len; i++ {
		for j := 0; j < len; j++ {
			if i != j && el[i].IsEqual(el[j]) == true {
				t.Errorf("Test fail: entity list %v:\n%v is not equal to entity list %v:\n%v", i, el[i].getEntityManagerStrWithProperties(), j, el[j].getEntityManagerStrWithProperties())
			}
		}
	}
}

func Test_StoreLoad(t *testing.T) {
	filePath := "./try.txt"
	size := 20
	usersName := make([]string, size, size)

	for i := 0; i < size; i++ {
		usersName[i] = fmt.Sprintf("User%d", i)
	}
	usersList := New()
	GenerateUserData(usersList, usersName, secret, salt)
	GenerateGroupList(usersList, usersName)
	//GenerateAcl(st) // done in the acl_test
	usersList.StoreInfo(filePath, secret, false)
	usersList1 := New()
	err := LoadInfo(filePath, secret, usersList1)
	if err != nil {
		fmt.Println(err)
	}
	if usersList.IsEqual(usersList1) == false {
		t.Errorf("Test fail, Stored users list != loaded one")
		fmt.Println("The stored entity list:", usersList.getEntityManagerStrWithProperties())
		fmt.Println("The loaded entity list:", usersList1.getEntityManagerStrWithProperties())
	}
}
