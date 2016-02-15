// Package entityManagement : The entityManagement package includes implementation of User, Group, Resource and a container of all theses entities.
//
// There are three types of entities: User, Group and resource
//	- Users have a name and a list of properties
//	- Groups have a name, list of users associated with it
//	  (each user is a name of an existing User entityy) and a list of properties
//	- Resources have a name and a list of properties
//
// There is a special group entity, that is not defined explicitly, with the name "All".
//	This entity is used in the ACL when the resource has permission properties that applies to all the entities in the system
//
// Note: The GetEntityAccount is the only external function that can be called without crudential checking
//			therefore, it is protected against timming attacks (where the attacker tries to gain information
//			such as if a specific user name is already defined in the system)
package entityManagement

import (
	"encoding/json"
	"fmt"
	"strings"

	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	userTypeStr     = "User"
	groupTypeStr    = "Group"
	resourceTypeStr = "Resource"

	permissionTypeStr = "Permission"
)

// TODO group of groups are not handled

type entityProperties map[string]interface{}
type groupOfUsers map[string]interface{}

// Entity : structure that holds the entity name and the properties associated to it
type Entity struct {
	Name             string
	EntityProperties entityProperties
}

// User : structure that holds the user data: Entity
type User struct {
	Entity
}

// Group : structure that holds the group data: Entity and list of users associated to this group
type Group struct {
	Entity
	Group groupOfUsers
}

// Resource : structure that holds the resource data: Entity
type Resource struct {
	Entity
}

func (e Entity) String() string {
	pArray := make([]string, 0, len(e.EntityProperties))

	for name := range e.EntityProperties {
		pArray = append(pArray, name)
	}
	return fmt.Sprintf("%v, Properties: %v", e.Name, strings.Join(pArray, ","))
}

func (u User) String() string {
	return fmt.Sprintf("%v: %v", userTypeStr, u.Entity)
}

func (r Resource) String() string {
	return fmt.Sprintf("%v: %v", resourceTypeStr, r.Entity)
}

func (g Group) String() string {
	nArray := make([]string, 0, len(g.Group))

	for n := range g.Group {
		nArray = append(nArray, n)
	}
	return fmt.Sprintf("%v: %v, Users list: %q", groupTypeStr, g.Entity, nArray)
}

// IsEntityNameValid : Verify that the entity name is valid, the current limit is that its size must be at least 1 character
func IsEntityNameValid(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("Name is not valid, its length must be larger than 0")
	}
	return nil
}

// Generate a new user with the given name
func newUser(name string) (*User, error) {
	err := IsEntityNameValid(name)
	if err != nil {
		return nil, err
	}
	return &User{Entity{Name: name, EntityProperties: make(entityProperties)}}, nil
}

// Generate a new group with the given name
func newGroup(name string) (*Group, error) {
	err := IsEntityNameValid(name)
	if err != nil {
		return nil, err
	}
	e1 := Entity{Name: name, EntityProperties: make(entityProperties)}
	return &Group{Entity: e1, Group: make(groupOfUsers)}, nil
}

// Generate a new resource with the given name
func newResource(name string) (*Resource, error) {
	err := IsEntityNameValid(name)
	if err != nil {
		return nil, err
	}
	return &Resource{Entity{Name: name, EntityProperties: make(entityProperties)}}, nil
}

func (g *Group) addUserToGroup(name string) error {
	lock.Lock()
	defer lock.Unlock()

	if len(name) == 0 {
		return fmt.Errorf("Cannot add a nil user")
	}
	err := IsEntityNameValid(name)
	if err != nil {
		return err
	}
	_, exist := g.Group[name]
	if exist {
		return fmt.Errorf("User '%v', is already in group '%v'", name, g.Group)
	}
	g.Group[name] = ""
	return nil
}

// Remove a given user name from the group users list
func (g *Group) removeUserFromGroup(name string) error {
	_, exist := g.Group[name]
	if exist == false {
		return fmt.Errorf("Cannot remove user '%v', not part of group '%v'", name, g.Group)
	}
	delete(g.Group, name)
	return nil
}

// check if a given name is a user in the group users list
func (g Group) isUserInGroup(name string) bool {
	_, exist := g.Group[name]
	return exist
}

// Add a property to the given entity using the property name and the given data
func (e *Entity) addProperty(propertyName string, data interface{}) error {
	propertyLock.Lock()
	defer propertyLock.Unlock()

	if data == nil {
		return fmt.Errorf("Cannot add property of '%v' to the entity: Property data is nil", propertyName)
	}
	_, exist := defs.PropertiesName[propertyName]
	if exist == false {
		return fmt.Errorf("The property name '%v' cannot be used, the allowed properties names are: %v", propertyName, defs.PropertiesName)
	}
	e.EntityProperties[propertyName] = data
	return nil
}

// Remove a property from the given entity using the property given property name
func (e *Entity) removeProperty(propertyName string) error {
	propertyLock.Lock()
	defer propertyLock.Unlock()

	_, exist := e.EntityProperties[propertyName]
	if !exist {
		return fmt.Errorf("The property '%v' cannot be removed, it was not assigned to entity '%v'", propertyName, e.Name)
	}
	delete(e.EntityProperties, propertyName)
	return nil
}

// Return a property associated with the entity using the property
func (e *Entity) getProperty(propertyName string) (interface{}, error) {
	propertyLock.Lock()
	defer propertyLock.Unlock()

	data, exist := e.EntityProperties[propertyName]
	if !exist {
		return nil, fmt.Errorf("%v, property '%v' was not found", e.Name, propertyName)
	}
	return data, nil
}

// Add the group's data to disk (in JSON format)
func (g *Group) addGroupToStorage(prefix string, storage *ss.SecureStorage) error {
	if storage == nil {
		return fmt.Errorf("Cannot add group to storage: Storage is nil")
	}
	val, _ := json.Marshal(g)
	return storage.AddItem(prefix, string(val))
}

// Add the Entity's data to disk (in JSON format)
func (e *Entity) addEntityToStorage(prefix string, storage *ss.SecureStorage) error {
	if storage == nil {
		return fmt.Errorf("Cannot add to storage: Storage is nil")
	}
	val, _ := json.Marshal(e)
	return storage.AddItem(prefix, string(val))
}

// Read the Entity's data from disk (in JSON format)
func readEntityFromStorage(key string, storage *ss.SecureStorage) (*Entity, error) {
	var e Entity

	if storage == nil {
		return nil, fmt.Errorf("Cannot read entity from storage: Storage is nil")
	}
	value, exist := storage.Data[key]
	if exist == false {
		return nil, fmt.Errorf("Key '%v' was not found", key)
	}
	err := json.Unmarshal([]byte(value), &e)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Read the Group's data from disk (in JSON format)
func readGroupFromStorage(key string, storage *ss.SecureStorage) (*Group, error) {
	var g Group

	if storage == nil {
		return nil, fmt.Errorf("Cannot read group from storage: Storage is nil")
	}
	value, exist := storage.Data[key]
	if exist == false {
		return nil, fmt.Errorf("Key '%v' was not found", key)
	}
	err := json.Unmarshal([]byte(value), &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}
