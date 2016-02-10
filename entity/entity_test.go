package entityManagement

import (
	"fmt"
	"reflect"
	"testing"

	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
)

const (
	entityName = "test1"
)

// Print an Entity and its properties
func (e Entity) getEntityStrWithProperties() string {
	str := fmt.Sprintf("'%v'\n", e.Name)
	for propertyName := range e.EntityProperties {
		data, _ := e.getProperty(propertyName)
		str += fmt.Sprintf("\tProperty: %v, data: %v\n", propertyName, defs.Serializers[propertyName].PrintProperties(data))
	}
	return str
}

// Print a Group and its properties
func (g Group) getGroupStrWithProperties() string {
	return g.Entity.getEntityStrWithProperties() + fmt.Sprintf("\tMembers: %v\n", g.Group)
}

// Compare all the properties associated with the given entities
func (e *Entity) isEqualProperties(e1 Entity) bool {
	for propertyName := range e.EntityProperties {
		_, exist := defs.PropertiesName[propertyName]
		if exist == false {
			fmt.Printf("Internal error: unknown property '%v' was in the entity properties %v", propertyName, e.EntityProperties)
			return false
		}
		data1, _ := e.getProperty(propertyName)
		data2, _ := e1.getProperty(propertyName)
		if data1 == nil || data2 == nil {
			return false
		}
		if defs.Serializers[propertyName].IsEqualProperties(data1, data2) == false {
			return false
		}
	}
	return true
}

// Compare 2 entities including their name and properties
func (e *User) isEqualUser(e1 *User) bool {
	return e1 != nil && e.Name == e1.Name &&
		e.Entity.isEqualProperties(e1.Entity) && e1.Entity.isEqualProperties(e.Entity)
}

// Compare 2 groups including thier name, group of members and properties
func (g Group) isEqualGroup(g1 *Group) bool {
	return g1 != nil && g.Entity.isEqualProperties(g1.Entity) && g1.Entity.isEqualProperties(g.Entity) &&
		reflect.DeepEqual(g.Group, g1.Group)
}

// Compare 2 entities including their name and properties
func (e *Resource) isEqualResource(e1 *Resource) bool {
	return e1 != nil && e.Name == e1.Name &&
		e.Entity.isEqualProperties(e1.Entity) && e1.Entity.isEqualProperties(e.Entity)
}

/*

	The real tests
==============================




*/

func addMembers(e *Group, names []string, expected bool) (bool, error) {
	for _, name := range names {
		err := e.addUserToGroup(name)
		if expected == true && err != nil {
			return false, fmt.Errorf("can't add the valid member '%v' to entity %v", name, e)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("attempting to add an existing member '%v' to entity %v", name, e)
		}
		if e.isUserInGroup(name) == false {
			return false, fmt.Errorf("member was '%v' added to group but was not found in entity list %v", name, e)
		}
	}
	return true, nil
}

func removeMembers(e *Group, names []string, expected bool) (bool, error) {
	for _, name := range names {
		err := e.removeUserFromGroup(name)
		if expected == true && err != nil {
			return false, fmt.Errorf("can't remove the valid member '%v' from entity %v", name, e)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("removed an already removed member '%v' from entity %v", name, e)
		}
		if e.isUserInGroup(name) == true {
			return false, fmt.Errorf("member '%v' found in group %v after it was removed", name, e)
		}
	}
	return true, nil
}

func addProperty(e *Entity, propertyList []string) (bool, error) {
	prefix := "a-"

	for _, p := range propertyList {
		pData := prefix + p
		err := e.addProperty(p, pData)
		if err != nil {
			return false, fmt.Errorf("can't add the valid property '%v' with data' %v' to entity %v", p, pData, e)
		}
		data, err := e.getProperty(p)
		if err != nil {
			return false, fmt.Errorf("property '%v' added to property list but was not found in property list %v", p, e.EntityProperties)
		} else if data != pData {
			return false, fmt.Errorf("data '%v was added to property '%v' but read '%v', entity %v", pData, p, data, e)
		}
	}
	return true, nil
}

func removeProperty(e *Entity, propertyList []string, expected bool) (bool, error) {
	for _, p := range propertyList {
		err := e.removeProperty(p)
		if expected == true && err != nil {
			return false, fmt.Errorf("can't remove a property '%v' from entity %v", p, e)
		} else if expected == false && err == nil {
			return false, fmt.Errorf("attempting to remove a non exiting member '%v' from entity %v", p, e)
		}
		_, err = e.getProperty(p)
		if err == nil {
			return false, fmt.Errorf("property '%v' found in property %v after it was removed", p, e)
		}
	}
	return true, nil
}

// Test that an empty entity can't be added to the entity list
// Verify that when a user was added to group, it is in the users list
// Verify that the same user can be added only once
// Verify thet user member is removed only once
// Verift that at the end of the test, the users list must by empty
func Test_AddRemoveMember(t *testing.T) {
	expected := []bool{true, false}
	names := []string{"a", "a1", "a2"}

	e, _ := newGroup(entityName)
	_, err := newUser("")
	_, err1 := newGroup("")
	_, err2 := newResource("")
	if err == nil || err1 == nil || err2 == nil {
		t.Error("Test fail: Entity with an empty name was created")
		t.FailNow()
	}
	err = e.addUserToGroup("")
	if err == nil {
		t.Error("Test fail: Member with an empty name was added to entity list", e)
		t.FailNow()
	}
	for _, exp := range expected {
		_, err := addMembers(e, names, exp)
		if err != nil {
			t.Errorf("Test fail: %v", err)
			t.FailNow()
		}
	}
	for _, exp := range expected {
		_, err := removeMembers(e, names, exp)
		if err != nil {
			t.Errorf("Test fail: %v", err)
		}
	}
	if len(e.Group) != 0 {
		t.Error("Test fail: The group list of", e.Name, "must be empty", e.Group)
	}
}

// Verift that 2 entities are equal only if all their data is equal
func Test_EntityIsEqual(t *testing.T) {
	names := []string{"a", "a1", "a2"}
	len := 3
	var e [3]*Group

	for i := 0; i < len; i++ {
		e[i], _ = newGroup(entityName)
		addMembers(e[i], names, true)
		if i > 0 {
			if e[i].isEqualGroup(e[i-1]) == false {
				t.Errorf("Test fail: entity %v: %v must be equal to entity %v %v", i, e[i], i-1, e[i-1])
			}
		}
	}
	e[0].removeUserFromGroup(names[0])
	e[1].addProperty(defs.AmPropertyName, "try1") // it tests both wrong property as well as different entities
	for i := 0; i < len; i++ {
		for j := 0; j < len; j++ {
			ret := e[i].isEqualGroup(e[j])
			if i != j && ret == true {
				t.Errorf("Test fail: 2 different entities received equal true:\n%v: %v is not equal to entity\n%v: %v", i, e[i], j, e[j])
			}
		}
	}
}

func addRemoveProperty(t *testing.T, typeStr string) {
	propertyList := []string{defs.UmPropertyName, defs.OtpPropertyName, defs.OcraPropertyName, defs.PwdPropertyName, defs.AmPropertyName, defs.AclPropertyName}
	expected := []bool{true, false}
	var e Entity

	if typeStr == userTypeStr {
		u, _ := newUser(entityName)
		logger.Trace.Println("The data is:", u.String())
		e = u.Entity
	} else if typeStr == groupTypeStr {
		g, _ := newGroup(entityName)
		u, _ := newUser(entityName)
		g.addUserToGroup(u.Name)
		e = g.Entity
	} else {
		r, _ := newResource(entityName)
		logger.Trace.Println("The data is:", r.String())
		e = r.Entity
	}
	err := e.addProperty("try", []string{"try1", "try2"})
	if err == nil {
		t.Errorf("Test fail: Undefined property was added to the entity %v", err)
	}
	_, err = addProperty(&e, propertyList)
	if err != nil {
		t.Errorf("Test fail: %v", err)
		t.FailNow()
	}
	logger.Trace.Println("The data is:", e.String())
	for _, exp := range expected {
		_, err := removeProperty(&e, propertyList, exp)
		if err != nil {
			t.Errorf("Test fail: %v", err)
		}
	}
	if len(e.EntityProperties) != 0 {
		t.Error("Test fail: The property list of", e.Name, "must be empty", e.EntityProperties)
	}
}

// Verify that when a property was added, it is in the property list
// Verify that the new property override old one
// Verify that property can be removed multiple times
// Verift that at the end of the test, the property list must by empty
func Test_AddRemoveProperty(t *testing.T) {
	addRemoveProperty(t, userTypeStr)
	addRemoveProperty(t, groupTypeStr)
	addRemoveProperty(t, resourceTypeStr)
}
