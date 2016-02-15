package acl

import (
	"fmt"
	"sync"

	en "github.com/ibm-security-innovation/libsecurity-go/entity"
)

// PermissionsMap : hash to check if a premission was defined
type PermissionsMap map[en.Permission]interface{}

var pLock sync.Mutex

// Entry : structure that holds the entity name and the set of permissions associated to this entry
type Entry struct {
	EntityName  string
	Permissions PermissionsMap
}

func (a Entry) String() string {
	return fmt.Sprintf("Name: %v, permissions: %v", a.EntityName, a.Permissions)
}

func isPermissionValid(permission en.Permission) error {
	if len(permission) == 0 {
		return fmt.Errorf("Permission is not valid: Length must be larger than 0")
	}
	return nil
}

// NewEntry : Generate a new ACL entry structure
func NewEntry(name string) (*Entry, error) {
	err := en.IsEntityNameValid(name)
	if err != nil {
		return nil, err
	}
	a := Entry{EntityName: name, Permissions: make(PermissionsMap)}
	return &a, nil
}

// AddPermission : If the permission is valid and was not set yet, add it to the entry's permission list
func (a *Entry) AddPermission(permission en.Permission) (bool, error) {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPermissionValid(permission)
	if err != nil {
		return false, err
	}
	_, exist := a.Permissions[permission]
	if exist {
		return false, fmt.Errorf("Cannot add permission: '%v', it already exists in the permission list", permission)
	}
	a.Permissions[permission] = ""
	return true, nil
}

// RemovePermission : Remove the given permission from the ACL entry
func (a *Entry) RemovePermission(permission en.Permission) error {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPermissionValid(permission)
	if err != nil {
		return err
	}
	_, exist := a.Permissions[permission]
	if exist == false {
		return fmt.Errorf("Cannot remove permission: '%v', it does not exist in the permission list", permission)
	}
	delete(a.Permissions, permission)
	return nil
}

// CheckPermission : Check if a given permission is in the entry's list
func (a Entry) CheckPermission(permission en.Permission) (bool, error) {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPermissionValid(permission)
	if err != nil {
		return false, err
	}
	_, exist := a.Permissions[permission]
	return exist, nil
}
