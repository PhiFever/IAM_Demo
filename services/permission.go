package services

import (
	"errors"
	"fmt"
	"sync"

	"IAM_Demo/models" // 替换为实际的项目路径
)

var (
	ErrInvalidResource = errors.New("invalid resource type")
	ErrInvalidAction   = errors.New("invalid action type")
	ErrRoleNotFound    = errors.New("role not found")
)

type PermissionService struct {
	roles map[string]models.Role
	mutex sync.RWMutex
}

func NewPermissionService() *PermissionService {
	return &PermissionService{
		roles: make(map[string]models.Role),
	}
}

// AddRole 添加或更新角色及其权限
func (s *PermissionService) AddRole(role models.Role) error {
	// 验证所有权限的有效性
	for _, perm := range role.Permissions {
		if !perm.Resource.IsValid() {
			return fmt.Errorf("%w: %s", ErrInvalidResource, perm.Resource)
		}
		if !perm.Action.IsValid() {
			return fmt.Errorf("%w: %s", ErrInvalidAction, perm.Action)
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.roles[role.Name] = role
	return nil
}

// RemoveRole 移除角色
func (s *PermissionService) RemoveRole(roleName string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.roles, roleName)
}

// CheckPermission 检查角色是否拥有特定资源的特定操作权限
func (s *PermissionService) CheckPermission(roleName string, resource models.ResourceType, action models.ActionType) error {
	if !resource.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidResource, resource)
	}
	if !action.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidAction, action)
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	role, exists := s.roles[roleName]
	if !exists {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, roleName)
	}

	for _, perm := range role.Permissions {
		if perm.Resource == resource && perm.Action == action {
			return nil // 找到匹配的权限
		}
	}

	return fmt.Errorf("permission denied for role %s to %s %s", roleName, action, resource)
}

// GetRolePermissions 获取角色的所有权限
func (s *PermissionService) GetRolePermissions(roleName string) ([]models.Permission, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	role, exists := s.roles[roleName]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotFound, roleName)
	}

	// 返回权限切片的副本以避免外部修改
	permissions := make([]models.Permission, len(role.Permissions))
	copy(permissions, role.Permissions)
	return permissions, nil
}

// HasRole 检查角色是否存在
func (s *PermissionService) HasRole(roleName string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	_, exists := s.roles[roleName]
	return exists
}
