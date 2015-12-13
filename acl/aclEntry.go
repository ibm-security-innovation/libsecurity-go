package acl

import (
	"fmt"
	"sync"

	en "github.com/ibm-security-innovation/libsecurity-go/entity"
)

// Permission could be any string
type Permission string

type PermissionsMap map[Permission]interface{}

var pLock sync.Mutex

type AclEntry struct {
	EntityName  string
	Permissions PermissionsMap
}

func (a AclEntry) String() string {
	return fmt.Sprintf("Name: %v, permissions: %v", a.EntityName, a.Permissions)
}

func isPermissionValid(permission Permission) error {
	if len(permission) == 0 {
		return fmt.Errorf("permission is not valid, its length must be larger than 0")
	}
	return nil
}

func NewEntry(name string) (*AclEntry, error) {
	err := en.IsEntityNameValid(name)
	if err != nil {
		return nil, err
	}
	a := AclEntry{EntityName: name, Permissions: make(PermissionsMap)}
	return &a, nil
}

// If the permission is valid and was not set yet, add it to the entry's permission list
func (a *AclEntry) AddPermission(permission Permission) (bool, error) {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPermissionValid(permission)
	if err != nil {
		return false, err
	}
	_, exist := a.Permissions[permission]
	if exist {
		return false, fmt.Errorf("can't add permission: '%v', it already exists in the permission list", permission)
	}
	a.Permissions[permission] = ""
	return true, nil
}

func (a *AclEntry) RemovePermission(permission Permission) error {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPermissionValid(permission)
	if err != nil {
		return err
	}
	_, exist := a.Permissions[permission]
	if exist == false {
		return fmt.Errorf("can't remove permission: '%v', it does not exist in the permission list", permission)
	}
	delete(a.Permissions, permission)
	return nil
}

// Check if a given permission is in the entry's list
func (a AclEntry) CheckPermission(permission Permission) (bool, error) {
	pLock.Lock()
	defer pLock.Unlock()

	err := isPermissionValid(permission)
	if err != nil {
		return false, err
	}
	_, exist := a.Permissions[permission]
	return exist, nil
}
