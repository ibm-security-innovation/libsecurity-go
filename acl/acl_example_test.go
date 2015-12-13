package acl_test

import (
	"fmt"

	"github.com/ibm-security-innovation/libsecurity-go/acl"
	stc "github.com/ibm-security-innovation/libsecurity-go/defs"
	en "github.com/ibm-security-innovation/libsecurity-go/entity"
)

const (
	userName1         = "User1"
	userName2         = "User2"
	resourceName      = "Camera"
	userInGroupName1  = "gUser1"
	userInGroupName2  = userName2
	groupName         = "support"
	canUsePermission  = "Can use"
	allPermission     = "All can use it"
	usersPermission   = "for users only"
	supportPermission = "Can take"
	unsetPermission   = "This permission is not allowed"
)

var (
	usersName      = []string{userName1, userName2}
	groupUsersName = []string{userInGroupName1, userInGroupName2}
)

func initEntityManager() *en.EntityManager {
	entityManager := en.New()
	for _, name := range usersName {
		entityManager.AddUser(name)
	}
	entityManager.AddGroup(groupName)
	for _, name := range groupUsersName {
		entityManager.AddUser(name)
		entityManager.AddUserToGroup(groupName, name)
	}
	entityManager.AddResource(resourceName)
	a := acl.NewACL()
	entityManager.AddPropertyToEntity(resourceName, stc.AclPropertyName, a)
	return entityManager
}

// Shows how to add/check/remove permissions for a n entity (resource) of a user or a group entity
func Example_acl() {
	entityManager := initEntityManager()
	fmt.Println("ExampleShowACLAddCheckRemovePermissions")
	fmt.Printf("User: %q, permission %q is: %v\n", userName1, canUsePermission,
		acl.CheckUserPermission(entityManager, userName1, resourceName, acl.Permission(canUsePermission)))
	data, _ := entityManager.GetPropertyAttachedToEntity(resourceName, stc.AclPropertyName)
	a, ok := data.(*acl.Acl)
	if ok == false {
		fmt.Println("Error: can't get property", stc.AclPropertyName, "attached to resource", resourceName)
		return
	}
	a.AddPermissionToResource(entityManager, userName1, acl.Permission(canUsePermission))
	fmt.Printf("User: %q, permission %q is: %v\n", userName1, canUsePermission,
		acl.CheckUserPermission(entityManager, userName1, resourceName, acl.Permission(canUsePermission)))
	a.AddPermissionToResource(entityManager, groupName, acl.Permission(supportPermission))
	a.AddPermissionToResource(entityManager, groupName, acl.Permission(canUsePermission))
	a.AddPermissionToResource(entityManager, stc.AclAllEntryName, acl.Permission(allPermission))
	a.AddPermissionToResource(entityManager, userInGroupName1, acl.Permission(usersPermission))
	permissions, _ := acl.GetUserPermissions(entityManager, userInGroupName1, resourceName)
	fmt.Printf("All the permissions for user: %q, on resource %q are: %q\n",
		userInGroupName1, resourceName, permissions)
	permissions, _ = acl.GetUserPermissions(entityManager, groupName, resourceName)
	fmt.Printf("All the permissions for group %q on resource %q are: %q\n", groupName, resourceName, permissions)
	a.RemovePermissionFromEntity(groupName, acl.Permission(canUsePermission))
	fmt.Printf("After remove permission: %q from group %q\n", canUsePermission, groupName)
	fmt.Printf("User: %q, permission %q is: %v\n", userInGroupName1, canUsePermission,
		acl.CheckUserPermission(entityManager, userInGroupName1, resourceName, acl.Permission(canUsePermission)))
	fmt.Printf("All the permissions are: %q\n", a.GetAllPermissions())
}
