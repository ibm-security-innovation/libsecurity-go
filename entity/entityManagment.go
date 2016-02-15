package entityManagement

import (
	"fmt"
	"strings"
	"reflect"
	"encoding/json"
	"sync"

	"github.com/ibm-security-innovation/libsecurity-go/accounts"
	defs "github.com/ibm-security-innovation/libsecurity-go/defs"
	logger "github.com/ibm-security-innovation/libsecurity-go/logger"
	ss "github.com/ibm-security-innovation/libsecurity-go/storage"
)

const (
	entityToken = "entity-"
)

var (
	protectedEntityManager = []string{defs.RootUserName, defs.AclAllEntryName}
	// protectedGroupsList = []string{defs.SuperUserGroupName, defs.AdminGroupName, defs.UsersGroupName}

	lock         sync.Mutex
	propertyLock sync.Mutex

	// RemoveEntityFromAcl : call back function to enable remove of entity from ACL
	RemoveEntityFromAcl func(el1 interface{}, name string)
)

// Permission could be any string
type Permission string

type uList map[string]*User
type gList map[string]*Group
type rList map[string]*Resource
type pList map[Permission]interface{}

// EntityManager : structure that holds lists of users, gropus and resources
type EntityManager struct {
	Users     uList
	Groups    gList
	Resources rList
	Permissions pList
}

func (el EntityManager) String() string {
	uArray := make([]string, 0, len(el.Users))
	gArray := make([]string, 0, len(el.Groups))
	rArray := make([]string, 0, len(el.Resources))

	for _, u := range el.Users {
		uArray = append(uArray, u.Name)
	}
	for _, g := range el.Groups {
		gArray = append(gArray, g.Name)
	}
	for _, r := range el.Resources {
		rArray = append(rArray, r.Name)
	}
	return fmt.Sprintf("Users list: %q, Groups list: %q, Resource list: %q", uArray, gArray, rArray)
}

// Create and initilize a new EntityManager, add all the protected entities
// to avoid giving regular entities protected names
func initList() *EntityManager {
	entityManager := &EntityManager{Users: make(uList), Groups: make(gList), Resources: make(rList), Permissions: make(pList)}
	for _, name := range protectedEntityManager {
		entityManager.AddUser(name)
	}
	return entityManager
}

// New : Create and initilize a new EntityManager, add all the protected entities
// to avoid giving regular entities protected names
func New() *EntityManager {
	return initList()
}

// IsEntityInList : Check if the given entity name (user/group/resource) is in the entity list
func (el *EntityManager) IsEntityInList(name string) bool {
	return el.isUserInList(name) || el.isGroupInList(name) || el.isResourceInList(name)
}

// GetEntityAccount : The recommanded API function to be used for login: it handles timing attacks
// Return the entity account information if the given entity name (user/group/resource) and password are as expected
// avoid timming attacks by adding delay if one of the checks fails
func (el *EntityManager) GetEntityAccount(name string, pwd []byte) (*accounts.AmUserInfo, error) {
	return el.GetEntityAccountHandler(name, pwd, defs.PasswordThrottlingMiliSec, defs.ThrottleMaxRandomMiliSec)
}

// GetEntityAccountHandler : call GetEntityAccount with the given throttling parameters for testing
func (el *EntityManager) GetEntityAccountHandler(name string, pwd []byte, throttleMiliSec int64, randomThrottleMiliSec int64) (*accounts.AmUserInfo, error) {
	errStr := "entity name and password does not match"

	if el.IsEntityInList(name) == false {
		defs.TimingAttackSleep(throttleMiliSec, randomThrottleMiliSec)
		return nil, fmt.Errorf(errStr)
	}
	data, err := el.GetPropertyAttachedToEntity(name, defs.AmPropertyName)
	if err != nil {
		defs.TimingAttackSleep(throttleMiliSec, randomThrottleMiliSec)
		return nil, fmt.Errorf(errStr)
	}
	account := data.(*accounts.AmUserInfo)
	err = account.IsPasswordMatchHandler(pwd, throttleMiliSec, randomThrottleMiliSec)
	if err != nil {
		return nil, fmt.Errorf(errStr)
	}
	return account, nil
}

// The name is valid if the entity name is valid and the name is not in the list yet
func (el *EntityManager) isNameValid(name string) error {
	err := IsEntityNameValid(name)
	if err != nil {
		return err
	}
	if el.IsEntityInList(name) {
		return fmt.Errorf("The name '%v' is already in the Entity list", name)
	}
	return nil
}

// AddUser : Add a new user to the EntityManager (only for valid user name)
func (el *EntityManager) AddUser(name string) error {
	lock.Lock()
	defer lock.Unlock()

	err := el.isNameValid(name)
	if err != nil {
		return err
	}
	u, _ := newUser(name)
	el.Users[name] = u
	return nil
}

// AddGroup : Add a new group to the EntityManager (only for valid group name)
func (el *EntityManager) AddGroup(name string) error {
	lock.Lock()
	defer lock.Unlock()

	err := el.isNameValid(name)
	if err != nil {
		return err
	}
	g, _ := newGroup(name)
	el.Groups[name] = g
	return nil
}

// AddResource : Add a new resource to the EntityManager (only for valid resource name)
func (el *EntityManager) AddResource(name string) error {
	lock.Lock()
	defer lock.Unlock()

	err := el.isNameValid(name)
	if err != nil {
		return err
	}
	r, _ := newResource(name)
	el.Resources[name] = r
	return nil
}

// RemoveUser : Remove the given user from the EntityManager, from all the groups it is a part of
// and from all the ACLs that give it permissions
func (el *EntityManager) RemoveUser(name string) error {
	lock.Lock()
	defer lock.Unlock()

	for _, eName := range protectedEntityManager {
		if name == eName {
			return fmt.Errorf("%v '%v', cannot be removed because it is a protected name", userTypeStr, name)
		}
	}
	_, exist := el.Users[name]
	if exist == false {
		return fmt.Errorf("Cannot remove %v '%v', it is not part of the users in the entity list", userTypeStr, name)
	}
	// remove the entity from all the groups it belongs to
	for _, e := range el.Groups {
		e.removeUserFromGroup(name)
	}
	// remove the entity from all the ACL entries
	if RemoveEntityFromAcl != nil {
		RemoveEntityFromAcl(el, name)
	}
	delete(el.Users, name)
	return nil
}

// RemoveGroup : Remove the given group from the EntityManager
// and from all the ACLs that give it permissions
func (el *EntityManager) RemoveGroup(name string) error {
	lock.Lock()
	defer lock.Unlock()

	_, exist := el.Groups[name]
	if exist == false {
		return fmt.Errorf("Cannot remove %v '%v', it is not part of the groups in the entity list", groupTypeStr, name)
	}
	// remove the entity from all the ACL entries
	if RemoveEntityFromAcl != nil {
		RemoveEntityFromAcl(el, name)
	}
	delete(el.Groups, name)
	return nil
}

// RemoveResource : Remove the given resource from the EntityManager
func (el *EntityManager) RemoveResource(name string) error {
	lock.Lock()
	defer lock.Unlock()

	_, exist := el.Resources[name]
	if exist == false {
		return fmt.Errorf("Cannot remove %v '%v', it is not part of the resources in the entity list", resourceTypeStr, name)
	}
	delete(el.Resources, name)
	return nil
}

// Return the user from the EntityManager using the given user name
func (el EntityManager) getUser(name string) (*User, error) {
	e, exist := el.Users[name]
	if !exist {
		return nil, fmt.Errorf("%v '%v' is not in the entity list", userTypeStr, name)
	}
	return e, nil
}

// Return the group from the EntityManager using the given user name
func (el EntityManager) getGroup(name string) (*Group, error) {
	e, exist := el.Groups[name]
	if !exist {
		return nil, fmt.Errorf("%v '%v' is not in the entity list", groupTypeStr, name)
	}
	return e, nil
}

// Return the resource from the EntityManager using the given user name
func (el EntityManager) getResource(name string) (*Resource, error) {
	e, exist := el.Resources[name]
	if !exist {
		return nil, fmt.Errorf("%v '%v' is not in the entity list", resourceTypeStr, name)
	}
	return e, nil
}

// AddUserToGroup : Add a new user to the given group
// the user name must be in the EntityManager before it can be added as a user of a group
func (el *EntityManager) AddUserToGroup(groupName string, name string) error {
	e, err := el.getGroup(groupName)
	if err != nil {
		return err
	}
	_, exist := el.Users[name]
	if exist == false {
		return fmt.Errorf("User '%v' is not in the entity users list yet", name)
	}
	return e.addUserToGroup(name)
}

// IsUserPartOfAGroup : Check if the given user is part of the given group
func (el *EntityManager) IsUserPartOfAGroup(groupName string, userName string) bool {
	g, err := el.getGroup(groupName)
	if err != nil {
		return false
	}
	return g.isUserInGroup(userName)
}

// GetGroupUsers : Get the group users
func (el *EntityManager) GetGroupUsers(groupName string) []string {
	var groupUsers []string

	g, err := el.getGroup(groupName)
	if err != nil {
		return nil
	}
	for name := range g.Group {
		groupUsers = append(groupUsers, name)
	}
	return groupUsers
}

// RemoveUserFromGroup : Remove the given user name from the group's users
func (el *EntityManager) RemoveUserFromGroup(groupName string, name string) error {
	e, err := el.getGroup(groupName)
	if err != nil {
		return err
	}
	return e.removeUserFromGroup(name)
}

// Check if the given user name is in the EntityManager
func (el EntityManager) isUserInList(name string) bool {
	_, exist := el.Users[name]
	return exist
}

// Check if the given group name is in the EntityManager
func (el EntityManager) isGroupInList(name string) bool {
	_, exist := el.Groups[name]
	return exist
}

// Check if the given resource name is in the EntityManager
func (el EntityManager) isResourceInList(name string) bool {
	_, exist := el.Resources[name]
	return exist
}

func isEntityNameAndPropertyNameValid(name string, propertyName string) error {
	if len(propertyName) == 0 || len(name) == 0 {
		return fmt.Errorf("The '%v' and the property name '%v' cannot be removed as they are nil", name, propertyName)
	}
	return nil
}

// AddPropertyToEntity : Add the given property to the entity using the given property name
func (el *EntityManager) AddPropertyToEntity(name string, propertyName string, data interface{}) error {
	lock.Lock()
	defer lock.Unlock()

	if data == nil {
		return fmt.Errorf("Cannot add property '%v': it is nil", propertyName)
	}
	ret := isEntityNameAndPropertyNameValid(name, propertyName)
	if ret != nil {
		return ret
	}
	if el.isUserInList(name) {
		if propertyName == defs.AclPropertyName {
			return fmt.Errorf("Cannot add ACL property to %v, it is ilegal", userTypeStr)
		}
		return el.Users[name].addProperty(propertyName, data)
	} else if el.isGroupInList(name) {
		if propertyName == defs.AclPropertyName {
			return fmt.Errorf("Cannot add ACL property to %v, it is ilegal", groupTypeStr)
		}
		return el.Groups[name].addProperty(propertyName, data)
	} else if el.isResourceInList(name) {
		return el.Resources[name].addProperty(propertyName, data)
	}
	return fmt.Errorf("Property '%v', cannot be added, the entity '%v' is not in the entity list", propertyName, name)
}

// GetPropertyAttachedToEntity : Return the given property name property from the entity (User/Group/Resource)
func (el *EntityManager) GetPropertyAttachedToEntity(name string, propertyName string) (interface{}, error) {
	ret := isEntityNameAndPropertyNameValid(name, propertyName)
	if ret != nil {
		return nil, ret
	}
	if el.isUserInList(name) {
		return el.Users[name].getProperty(propertyName)
	} else if el.isGroupInList(name) {
		return el.Groups[name].getProperty(propertyName)
	} else if el.isResourceInList(name) {
		return el.Resources[name].getProperty(propertyName)
	}
	return nil, fmt.Errorf("Property '%v', cannot be returned, the entity '%v' is not in entity list", propertyName, name)
}

// RemovePropertyFromEntity : Remove the given property name property from the user
func (el *EntityManager) RemovePropertyFromEntity(name string, propertyName string) error {
	lock.Lock()
	defer lock.Unlock()

	ret := isEntityNameAndPropertyNameValid(name, propertyName)
	if ret != nil {
		return ret
	}
	if el.isUserInList(name) {
		return el.Users[name].removeProperty(propertyName)
	} else if el.isGroupInList(name) {
		return el.Groups[name].removeProperty(propertyName)
	} else if el.isResourceInList(name) {
		return el.Resources[name].removeProperty(propertyName)
	}
	return fmt.Errorf("Property '%v', cannot be removed, the entity '%v' is not in the entity list", propertyName, name)
}

func getEntityStoreFmt(prefix string, propertyName string, entityName string) string {
	return prefix + "-" + propertyName + "-" + entityName
}

func getPropertyStoreFmt(propertyName string, entityName string) string {
	return propertyName + "-" + entityName
}

func addUserResourceToStorage(typeStr string, name string, e Entity, prefix string, storage *ss.SecureStorage) error {
	err := e.addEntityToStorage(getEntityStoreFmt(typeStr+prefix, entityToken, name), storage)
	if err != nil {
		return err
	}
	for propertyName := range e.EntityProperties {
		data, _ := e.getProperty(propertyName)
		err = defs.Serializers[propertyName].AddToStorage(getPropertyStoreFmt(propertyName, name), data, storage)
		if err != nil {
			return fmt.Errorf("While storing to property '%v', error: %v", propertyName, err)
		}
	}
	return nil
}

func addGroupToStorage(typeStr string, name string, g *Group, prefix string, storage *ss.SecureStorage) error {
	err := g.addGroupToStorage(getEntityStoreFmt(typeStr+prefix, entityToken, name), storage)
	if err != nil {
		return err
	}
	for propertyName := range g.EntityProperties {
		data, _ := g.getProperty(propertyName)
		err = defs.Serializers[propertyName].AddToStorage(getPropertyStoreFmt(propertyName, name), data, storage)
		if err != nil {
			return fmt.Errorf("While storing to property '%v', error: %v", propertyName, err)
		}
	}
	return nil
}

// LoadInfo : Load the EntityManager data from the storage
// and constract/reconstract the EntityManager
func LoadInfo(filePath string, secret []byte, el *EntityManager) error {
	prefix := ""
	if el == nil {
		return fmt.Errorf("Internal error: Entity list is nil")
	}
	stStorage, err := ss.LoadInfo(filePath, secret)
	if err != nil {
		logger.Error.Printf("%v", err)
		return fmt.Errorf("%v", err)
	}
	storage := stStorage.GetDecryptStorageData()
	if storage == nil {
		return fmt.Errorf("loadInfo: Storage is nil")
	}
	for key, value := range storage.Data {
		userType := strings.HasPrefix(key, getEntityStoreFmt(userTypeStr+prefix, entityToken, ""))
		groupType := strings.HasPrefix(key, getEntityStoreFmt(groupTypeStr+prefix, entityToken, ""))
		resourceType := strings.HasPrefix(key, getEntityStoreFmt(resourceTypeStr+prefix, entityToken, ""))
		permissionType := strings.HasPrefix(key, getEntityStoreFmt(permissionTypeStr+prefix, "", ""))
		var err error
		var name string
		var permission Permission
		var e *Entity
		var g *Group
		if userType {
			e, err = readEntityFromStorage(key, storage)
			name = e.Name
			el.Users[name] = &User{Entity: *e}
		} else if groupType {
			g, err = readGroupFromStorage(key, storage)
			name = g.Name
			el.Groups[name] = g
		} else if resourceType {
			e, err = readEntityFromStorage(key, storage)
			name = e.Name
			el.Resources[name] = &(Resource{Entity: *e})
		} else if permissionType {
			permission, err = readPermissionFromStorage(key, storage)
		}
		if err != nil {
			return fmt.Errorf("Error while reading file: '%s', string: '%s', error: %s", filePath, value, err)
		}
		// fmt.Println("key:", key, "Value:", value, "error:", err)
		if userType || groupType || resourceType {
			for propertyName, property := range defs.Serializers {
				data, err := property.ReadFromStorage(getPropertyStoreFmt(propertyName, name), storage)
				if err == nil { // the item exist for this entity
					err = el.AddPropertyToEntity(name, propertyName, data)
					if err != nil {
						fmt.Println("while reading property data", propertyName, "for entity", name, "error:", err)
						return err
					}
				}
			}
		}else if permissionType {
			el.AddPermission(permission)
		}
	}
	return nil
}

// StoreInfo : Store all the data of all the entities in the list including their properties in the secure storage
func (el *EntityManager) StoreInfo(filePath string, secret []byte, checkSecretStrength bool) error {
	lock.Lock()
	defer lock.Unlock()

	prefix := ""
	storage, err := ss.NewStorage(secret, checkSecretStrength)
	if err != nil {
		logger.Error.Printf("Fatal error: Cannot create storage, error: %v", err)
		return fmt.Errorf("Fatal error: Cannot create storage, error: %v", err)
	}
	for name, e := range el.Users {
		err := addUserResourceToStorage(userTypeStr, name, e.Entity, prefix, storage)
		if err != nil {
			return err
		}
	}
	for name, e := range el.Groups {
		err := addGroupToStorage(groupTypeStr, name, e, prefix, storage)
		if err != nil {
			return err
		}
	}
	for name, e := range el.Resources {
		err := addUserResourceToStorage(resourceTypeStr, name, e.Entity, prefix, storage)
		if err != nil {
			return err
		}
	}
	for name := range el.Permissions {
		err := addPermissionToStorage(name, prefix, storage)
		if err != nil {
			return err
		}
	}
	logger.Info.Println("Store Security Tool data to file:", filePath)
	return storage.StoreInfo(filePath)
}

//------------------- ACL global Permissions list handler

func (el EntityManager) getPermissions() string {
	pArray := make([]string, 0, len(el.Permissions))

	for p := range el.Permissions {
		pArray = append(pArray, string(p))
	}
	return fmt.Sprintf("Permissions: %v", strings.Join(pArray, ","))
}

// IsEqual : Check if the given permission list is equal to the EntityManager permissions list
func (p pList) IsEqual(p1 pList) bool {
	return (reflect.DeepEqual(p, p1) == true)
}

// IsPermissionInList : Check if the given permission is in the permissions list
func (el *EntityManager) IsPermissionInList(permission Permission) bool {
	_, exist := el.Permissions[permission]
	return exist
}

// isPermissionValid : Check if the given permission is valid: length is OK and it is not in the list
func (el EntityManager) isPermissionValid(permission Permission) error {
	if len(permission) == 0 {
		return fmt.Errorf("permission is not valid, its length must be larger than 0")
	}
	return nil
}

// AddPermission : Add a new permission to the EntityManager permisions list (only for valid permissions)
func (el *EntityManager)  AddPermission(permission Permission) error {
	lock.Lock()
	defer lock.Unlock()

	err := el.isPermissionValid(permission)
	if err != nil {
		return err
	}
	_, exist := el.Permissions[permission]
	if exist == true {
		return fmt.Errorf("Cannot add permission '%v': Already exists in the permissions set", permission)
	}
	el.Permissions[permission] = ""
	logger.Trace.Println("Add permission:", permission, "to permissions list")
	return nil
}

// RemovePermission the given permission from the EntityManager permissions list
func (el *EntityManager) RemovePermission(permission Permission) error {
	lock.Lock()
	defer lock.Unlock()

	err := el.isPermissionValid(permission)
	if err != nil {
		return err
	}
	_, exist := el.Permissions[permission]
	if exist == false {
		return fmt.Errorf("Cannot remove permission '%v': Does not exist in the permissions list", permission)
	}
	logger.Trace.Println("Remove permission:", permission, "from permissions list")
	delete(el.Permissions, permission)
	return nil
}

// Read the permission name from disk (in JSON format)
func readPermissionFromStorage(key string, storage *ss.SecureStorage) (Permission, error) {
	if storage == nil {
		return "", fmt.Errorf("Cannot read permission from storage: Storage is nil")
	}
	permission, exist := storage.Data[key]
	if exist == false {
		return "", fmt.Errorf("Key '%v' was not found", key)
	}
	// remove the added ""
	p1 := strings.TrimPrefix(permission, "\"")
	p2 := strings.TrimSuffix(p1, "\"")
	return Permission(p2), nil
}

func addPermissionToStorage(permission Permission, prefix string, storage *ss.SecureStorage) error {
	if storage == nil {
		return fmt.Errorf("Cannot add to storage: Storage is nil")
	}
	val, _ := json.Marshal(permission)
	return storage.AddItem(getEntityStoreFmt(permissionTypeStr+prefix, "", string(permission)), string(val))
}
