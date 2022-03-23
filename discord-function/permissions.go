package discord_function

import (
	"fmt"
	"log"
	"strings"

	"cloud.google.com/go/firestore"
	casbin "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	casfs "github.com/reedom/casbin-firestore-adapter"
)

type PermissionManager struct {
	enforcer *casbin.Enforcer
}

func NewPermissionManager(rootUserID string, firestoreClient *firestore.Client) (*PermissionManager, error) {
	modelString := `[request_definition]
r = sub, dom, obj, act
	
[policy_definition]
p = sub, dom, obj, act
	
[role_definition]
g = _, _, _
	
[policy_effect]
e = some(where (p.eft == allow))
	
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act`
	if rootUserID != "" {
		modelString = fmt.Sprintf(`[request_definition]
r = sub, dom, obj, act
			
[policy_definition]
p = sub, dom, obj, act
			
[role_definition]
g = _, _, _
			
[policy_effect]
e = some(where (p.eft == allow))
			
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act || r.sub == "%v"`, rootUserID)
	} else {
		log.Printf("ROOT ID FOUND: %v", rootUserID)
	}

	model, err := model.NewModelFromString(modelString)
	if err != nil {
		return nil, fmt.Errorf("Error: NewModelFromString: %v", err)
	}
	adapter := casfs.NewAdapter(firestoreClient)
	enf, err := casbin.NewCachedEnforcer()
	if err != nil {
		return nil, fmt.Errorf("Error: NewEnforcer: %v", err)
	}
	err = enf.InitWithModelAndAdapter(model, adapter)
	if err != nil {
		return nil, fmt.Errorf("Error: NewEnforcer: %v", err)
	}
	err = enf.LoadPolicy()
	if err != nil {
		return nil, fmt.Errorf("Error: LoadPolicy: %v", err)
	}
	return &PermissionManager{
		enforcer: enf,
	}, nil
}

func (p PermissionManager) CheckServerOp(user, server, op string) (bool, error) {
	if strings.HasSuffix(user, "_role") {
		return false, fmt.Errorf("checkUserAllowed: Invalid User name: %v", user)
	}
	allowed, err := p.enforcer.Enforce(user, "server", server, op)
	if err != nil {
		return false, fmt.Errorf("checkUserAllowed: %v", err)
	}
	return allowed, err
}

func (p PermissionManager) CheckUserOp(user, targetUser, op string) (bool, error) {
	if strings.HasSuffix(user, "_role") {
		return false, fmt.Errorf("checkUserAllowed: Invalid User name: %v", user)
	}
	allowed, err := p.enforcer.Enforce(user, "permissions", targetUser, op)
	if err != nil {
		return false, fmt.Errorf("checkUserAllowed: %v", err)
	}
	return allowed, err
}

func (p PermissionManager) CreateServerPermissions(server string) (bool, error) {
	roleName := ServerNameToRole(server)
	success, err := p.enforcer.AddPermissionForUser(roleName, "server", server, "start")
	if err != nil {
		return false, fmt.Errorf("AddPermissionForUser(start): %v", err)
	}
	if !success {
		log.Printf("Permission `start` already existed for %v", roleName)
	}
	result := success
	success, err = p.enforcer.AddPermissionForUser(roleName, "server", server, "stop")
	if err != nil {
		return false, fmt.Errorf("AddPermissionForUser(stop): %v", err)
	}
	if !success {
		log.Printf("Permission `stop` already existed for %v", roleName)
	}
	result = success && result
	return result, nil
}

func (p PermissionManager) DeleteServerPermissions(server string) (bool, error) {
	roleName := ServerNameToRole(server)
	success, err := p.enforcer.DeletePermissionsForUser(roleName)
	if err != nil {
		return false, fmt.Errorf("DeletePermissionForUser(%v): %v", server, err)
	}
	if !success {
		log.Printf("WARN: %v did not have any permissions but tried to delete them", roleName)
	}
	return success, nil
}

func (p PermissionManager) AddUserToServer(user, server string) (bool, error) {
	log.Printf("Adding user, %v, to role %v", user, server)
	roleName := ServerNameToRole(server)
	success, err := p.enforcer.AddRoleForUserInDomain(user, roleName, "server")
	if err != nil {
		return false, fmt.Errorf("AddRoleForUserInDomain: %v", err)
	}
	return success, err
}

func (p PermissionManager) RemoveUserFromServer(user, server string) (bool, error) {
	log.Printf("Removing user, %v, from role %v", user, server)
	roleName := ServerNameToRole(server)
	success, err := p.enforcer.DeleteRoleForUserInDomain(user, roleName, "server")
	if err != nil {
		return false, fmt.Errorf("AddRoleForUserInDomain: %v", err)
	}
	return success, err
}

func ServerNameToRole(name string) string {
	return fmt.Sprintf("%v_role", name)
}
