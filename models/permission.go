package models

// ActionType 表示可进行的操作类型
type ActionType string

const (
	// 基础操作
	ActionRead  ActionType = "read"
	ActionWrite ActionType = "write"

	// 特殊操作
	ActionList    ActionType = "list"
	ActionExport  ActionType = "export"
	ActionImport  ActionType = "import"
	ActionApprove ActionType = "approve"
)

// IsValid 验证操作类型是否有效
func (a ActionType) IsValid() bool {
	switch a {
	case ActionRead, ActionWrite, ActionList, ActionExport, ActionImport, ActionApprove:
		return true
	}
	return false
}

// String 实现 Stringer 接口
func (a ActionType) String() string {
	return string(a)
}

// ResourceType 表示系统中的资源类型
type ResourceType string

const (
	// 用户相关资源
	ResourceUser       ResourceType = "user"
	ResourceRole       ResourceType = "role"
	ResourcePermission ResourceType = "permission"

	// 业务相关资源
	ResourceProduct  ResourceType = "product"
	ResourceOrder    ResourceType = "order"
	ResourceCustomer ResourceType = "customer"

	// 系统相关资源
	ResourceSystem  ResourceType = "system"
	ResourceLog     ResourceType = "log"
	ResourceReport  ResourceType = "report"
	ResourceSetting ResourceType = "setting"
)

// IsValid 验证资源类型是否有效
func (r ResourceType) IsValid() bool {
	switch r {
	case ResourceUser, ResourceRole, ResourcePermission,
		ResourceProduct, ResourceOrder, ResourceCustomer,
		ResourceSystem, ResourceLog, ResourceReport, ResourceSetting:
		return true
	}
	return false
}

// String 实现 Stringer 接口
func (r ResourceType) String() string {
	return string(r)
}

// Permission 结构体使用 ResourceType
type Permission struct {
	Resource    ResourceType `json:"resource" binding:"required"`
	Action      ActionType   `json:"action" binding:"required"`
	Description string       `json:"description"`
}

type RoleType string

const (
	RoleAdmin RoleType = "admin"
	RoleUser  RoleType = "user"
)

type Role struct {
	ID          uint         `json:"id"`
	Name        string       `json:"name" binding:"required"`
	Type        RoleType     `json:"type" binding:"required"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}
