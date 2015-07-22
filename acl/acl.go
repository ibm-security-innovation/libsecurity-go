// Access Control List (ACL) package provides all the ACL services including the definition and control of resource permissions.
// The implementation should allow flexible types of access to resources (not limited to READ/WRITE/EXECUTE)
//
// The ACL property structure:
// An ACL has a list of entries. Each ACL entry consists of the following fields:
// - An entry name (obligatory, must be the name of an entity from the entity list)
// - List of permissions (optional)
//
//  A user has a given permission to the entity if:
//    1. The user name is equal to the entry name and the permissions list of the relevant entry grants that permission
//    2. The entry is a name of entity (group) that the user is member of and the permissions list of the relevant entry grants that permission
//    3. The 'All' entry grants that permission
// Notes:
//    1. I'm not handling a Group of groups
//    2. If User1 is removed from the Entity list and then re added,
// 	the only permission it will initially have is the 'All' permissions.
// 	This is because a removed entity cannot be re-added,
// 	but a new entity with its name can be created.
// 	In this case, the new Entity User1 may be of a different user than the one that originally received the permissions.
//
// Example:
// If the Entity list is:
// 	Name: User1
// 	Name: IBM, members: User2, User3
// 	Name: All (reserved token)
// 	Name: Disk, properties: ACL:
// 	ACL → Name: User1, properties: “can write”, “Can take”
// 		Name: IBM, properties: “can read”
//		Name: All, Properties: “Execute”
//
// In this example:
// 	1.The user-entity named User1 has the following permissions with relation to the resource-entity Disk: “can write”, “Can take” and “Execute” (via All)
// 	2.The group-entity named IBM has the following permissions with relation to the resource-entity Disk: “can read” and “Execute” (via All)
// 	3.The user-entity named User2 has the following permissions with relation to the resource-entity Disk: “can read” (via IBM) and “Execute” (via All)
//
// Entity Structure:
//	Entity =======> ACL |===========> Entry
//	                    |===========> Entry
//	                    |===========> Entry
// Entry structure:
//	Entry  =======> name (entity name)
//	       |======> list of permissions
//
package acl

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"sync"

	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	logger "ibm-security-innovation/libsecurity-go/logger"
	ss "ibm-security-innovation/libsecurity-go/storage"
)

const ()

var (
	lock sync.Mutex
)

// Permission could be any string
type AclEntryMap map[string]*AclEntry
type PermissionSet map[string]bool

type Serializer struct{}

type Acl struct {
	Permissions AclEntryMap
}

func (a Acl) String() string {
	return fmt.Sprintf("ACL: Permission entries: %v\n", getEntryListItem(a.Permissions))
}

func init() {
	logger.Init(ioutil.Discard, ioutil.Discard, os.Stdout, os.Stderr)
	stc.Serializers[stc.AclPropertyName] = &Serializer{}

	en.RemoveEntityFromAcl = RemoveEntityFromAcl
}

// Generate a new ACL structure
func NewACL() *Acl {
	a := Acl{Permissions: make(AclEntryMap)}
	return &a
}

/* old use func (a *Acl) cloneEntries(acl Acl) {
	for n, e := range acl.Permissions {
		a.Permissions[n] = e
	}
}
*/

// Check if 2 ACLs are equal
func (a *Acl) IsEqual(acl Acl) bool {
	return (reflect.DeepEqual(a.Permissions, acl.Permissions) == true)
}

// Verify that an entry is valid, that is it's not nil and its entry name is valid
func isValidEntry(entry *AclEntry) error {
	if entry == nil {
		return fmt.Errorf("Error: entry is nil")
	}
	return en.IsEntityNameValid(entry.EntityName)
}

func getEntryListItem(eList AclEntryMap) string {
	uArray := make([]string, 0, len(eList))

	for _, p := range eList {
		uArray = append(uArray, fmt.Sprintf("\n\t%v", p))
	}
	return strings.Join(uArray, ",")
}

// Add a new entry to the Acl, Add it only if it's not nil and
// 	the entry (entityName) is not alredy in the ACL
func (a *Acl) addEntry(entry *AclEntry) error {
	lock.Lock()
	defer lock.Unlock()

	err := isValidEntry(entry)
	if err != nil {
		return err
	}
	_, exist := a.Permissions[entry.EntityName]
	if exist == true {
		return fmt.Errorf("Error: Can't add entry '%v', it already exists in the ACL", entry.EntityName)
	}
	a.Permissions[entry.EntityName] = entry
	logger.Trace.Println("Add entry:", entry, "to acl")
	return nil
}

// Remove the given entry from the ACL
func (a *Acl) removeEntry(name string) error {
	lock.Lock()
	defer lock.Unlock()

	err := en.IsEntityNameValid(name)
	if err != nil {
		return err
	}
	_, exist := a.Permissions[name]
	if exist == false {
		return fmt.Errorf("Error: Can't remove entry '%v', it does not exist in the ACL", name)
	}
	logger.Trace.Println("Remove entry:", name, "from acl")
	delete(a.Permissions, name)
	return nil
}

// Callback from EntityManager, when an entity is removed in order to remove
// the entity's permissions. This is needed to avoid giving a future
// new (unrelated) entity with the same name the permissions that
// were given to the original entity that was removed
func RemoveEntityFromAcl(el1 interface{}, userName string) {
	if el1 == nil {
		return
	}
	el, ok := el1.(*en.EntityManager)
	if ok == false {
		return
	}
	err := en.IsEntityNameValid(userName)
	if err != nil {
		return
	}
	for resourceName, _ := range el.Resources {
		data, err := el.GetPropertyAttachedToEntity(resourceName, stc.AclPropertyName)
		if err != nil {
			continue
		}
		acl, ok := data.(*Acl)
		if ok == false {
			return
		}
		for name, _ := range acl.Permissions {
			if name == userName {
				acl.removeEntry(userName)
			}
		}
	}
	return
}

// Return all the permissions that are associated with the entity
func (a Acl) GetAllPermissions() PermissionsMap {
	lock.Lock()
	defer lock.Unlock()
	permissions := make(PermissionsMap)

	for _, e := range a.Permissions {
		for p, _ := range e.Permissions {
			permissions[p] = ""
		}
	}
	logger.Trace.Println("The permissions of acl are:", permissions)
	return permissions
}

// Get all the permissions of a given user to a given resource-
// return the user's list of permissions to the given resource
// The permissions may be listed as the user's permissions, permissions to groups
// in which the user is a member or permissions that are given to 'all'
func GetUserPermissions(el *en.EntityManager, userName string, resourceName string) (PermissionsMap, error) {
	lock.Lock()
	defer lock.Unlock()

	if el == nil {
		return nil, fmt.Errorf("Error: EntityManager is nil")
	}
	err := en.IsEntityNameValid(userName)
	if err != nil {
		return nil, err
	}
	err = en.IsEntityNameValid(resourceName)
	if err != nil {
		return nil, err
	}
	permissions := make(PermissionsMap)
	data, err := el.GetPropertyAttachedToEntity(resourceName, stc.AclPropertyName)
	if err != nil {
		return nil, fmt.Errorf("Resource '%v' dose not have an ACL property", resourceName)
	}
	acl, ok := data.(*Acl)
	if ok == false {
		return nil, fmt.Errorf("Resource '%v' ACL property is in the wrong type", resourceName)
	}
	for name, p := range acl.Permissions {
		if name == userName || name == stc.AclAllEntryName || el.IsUserPartOfAGroup(name, userName) {
			for permission, _ := range p.Permissions {
				permissions[permission] = ""
			}
		}
	}
	logger.Trace.Println("The permissions of:", userName, "are:", permissions)
	return permissions, nil
}

// Check if the given user name has a given permission to the given entity
func CheckUserPermission(el *en.EntityManager, userName string, resourceName string, permission Permission) bool {
	if el == nil {
		return false
	}
	if en.IsEntityNameValid(userName) != nil {
		return false
	}
	if en.IsEntityNameValid(resourceName) != nil {
		return false
	}
	permissions, _ := GetUserPermissions(el, userName, resourceName)
	lock.Lock()
	defer lock.Unlock()
	_, exist := permissions[permission]
	logger.Trace.Println("Is permission:", permission, "of:", userName, "for entity:", resourceName, "set:", exist)
	return exist
}

// Add the given permission to the given resource for the given user
func (a *Acl) AddPermissionToResource(el *en.EntityManager, userName string, permission Permission) error {
	lock.Lock()
	defer lock.Unlock()

	if el == nil {
		return fmt.Errorf("Error: entityManager is nil")
	}
	err := en.IsEntityNameValid(userName)
	if err != nil {
		return err
	}
	if el.IsEntityInList(userName) == false {
		return fmt.Errorf("Error: Can't add permission to entity '%v', it is not in the resource entity list", userName)
	}
	e, exist := a.Permissions[userName]
	if exist == false {
		e, _ = NewEntry(userName)
	}
	logger.Trace.Println("Add permission:", permission, "to:", userName)
	_, err = e.AddPermission(permission)
	a.Permissions[userName] = e
	return err
}

// Remove the given permission from the given resource for the given user
func (a *Acl) RemovePermissionFromEntity(entityName string, permission Permission) error {
	lock.Lock()
	defer lock.Unlock()

	e, exist := a.Permissions[entityName]
	if exist == false {
		return fmt.Errorf("The ACL doesn't contain an entry with the name '%v'", entityName)
	}
	logger.Trace.Println("Remove permission:", permission, "from:", entityName)
	return e.RemovePermission(permission)
}

// Return all the users that have the given permission to the given resource
func GetWhoUseAPermission(el *en.EntityManager, resourceName string, permission string) PermissionSet {
	if el == nil {
		return nil
	}
	err := en.IsEntityNameValid(resourceName)
	if err != nil {
		return nil
	}
	data, err := el.GetPropertyAttachedToEntity(resourceName, stc.AclPropertyName)
	if err != nil {
		return nil
	}
	p := make(PermissionSet)

	acl, ok := data.(*Acl)
	if ok == false {
		return p
	}
	for name, _ := range acl.Permissions {
		pVec, _ := GetUserPermissions(el, name, resourceName)
		for v, _ := range pVec {
			if string(v) == permission {
				p[name] = true
				break
			}
		}
	}
	for name, _ := range p {
		groupMembers := el.GetGroupUsers(name)
		for _, name1 := range groupMembers {
			p[name1] = true
		}
	}
	logger.Trace.Println("Who uses permission:", permission, "results:", p)
	return p
}

func (s Serializer) PrintProperties(data interface{}) string {
	d, ok := data.(*Acl)
	if ok == false {
		return "Error: Can't print the ACL property it is not in the right type"
	}
	return d.String()
}

func (s Serializer) IsEqualProperties(da1 interface{}, da2 interface{}) bool {
	d1, ok1 := da1.(*Acl)
	d2, ok2 := da2.(*Acl)
	if ok1 == false || ok2 == false {
		return false
	}
	return reflect.DeepEqual(d1, d2)
}

// Store ACL data info in the secure_storage
func (s Serializer) AddToStorage(prefix string, data interface{}, storage *ss.SecureStorage) error {
	lock.Lock()
	defer lock.Unlock()

	d, ok := data.(*Acl)
	if ok == false {
		return fmt.Errorf("Error: Can't store the ACL property as it has an illegal type")
	}
	if storage == nil {
		return fmt.Errorf("Error: Can't add an ACL property to storage, storage is nil")
	}
	value, err := json.Marshal(d)
	err = storage.AddItem(prefix, string(value))
	if err != nil {
		return err
	}
	return nil
}

// Read the user ACL information from disk (in JSON format)
func (s Serializer) ReadFromStorage(key string, storage *ss.SecureStorage) (interface{}, error) {
	var user Acl

	if storage == nil {
		return nil, fmt.Errorf("Error: Can't read an ACL property from storage, storage is nil")
	}
	value, exist := storage.Data[key]
	if exist == false {
		return nil, fmt.Errorf("Error: Key '%v' was not found", key)
	}
	err := json.Unmarshal([]byte(value), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
