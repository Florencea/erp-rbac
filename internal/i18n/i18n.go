package i18n

import (
	"net/http"
	"strings"
)

const (
	LocaleZhTW       = "zh-TW"
	LocaleEnUS       = "en-US"
	LocaleCookieName = "erp_rbac_locale"
)

// Messages defines the compile-time checked translation schema.
type Messages struct {
	LangCode string
	AppTitle string

	Common struct {
		Home           string
		Logout         string
		Submit         string
		ChangeLanguage string
		Create         string
		Edit           string
		Delete         string
		Cancel         string
		Save           string
		Confirm        string
		Actions        string
		Search         string
		Reset          string
		Filter         string
		Status         string
		NoRecords      string
		Back           string
		Navigation     string
		MainMenu       string
		Required       string
		WelcomeUser    string
		WelcomeSystem  string
		PleaseEnter    string
		ConfirmDelete  string
		CreatedAt      string
		UpdatedAt      string
		SystemTag      string
		Yes            string
		No             string
		PageInfo       string
		Previous       string
		Next           string
	}

	Auth struct {
		Login            string
		LoginDescription string
		Account          string
		Password         string
		SwitchToOther    string
	}

	Routes struct {
		Home        string
		Login       string
		Users       string
		Departments string
		Roles       string
		AuditLogs   string
		Forbidden   string
	}

	Dept struct {
		Title         string
		Name          string
		Parent        string
		Root          string
		Path          string
		Sort          string
		Leader        string
		Create        string
		Edit          string
		Delete        string
		DeleteConfirm string
		Saved         string
		Deleted       string
	}

	Role struct {
		Title           string
		Code            string
		Name            string
		Description     string
		DataScope       string
		Sort            string
		Permissions     string
		CustomDepts     string
		CustomDeptsHint string
		Create          string
		Edit            string
		Delete          string
		DeleteConfirm   string
		Saved           string
		Deleted         string
		Scopes          struct {
			ALL          string
			DEPTAndChild string
			DEPT         string
			SELF         string
			CUSTOM       string
		}
	}

	User struct {
		Title               string
		Account             string
		Name                string
		EmployeeNo          string
		JobTitle            string
		Password            string
		PasswordPlaceholder string
		PasswordRequired    string
		Department          string
		Roles               string
		Create              string
		Edit                string
		Delete              string
		DeleteConfirm       string
		Saved               string
		Deleted             string
		StatusActive        string
		StatusInactive      string
		StatusSuspended     string
		AllStatuses         string
		SearchPlaceholder   string
	}

	Audit struct {
		Title        string
		OccurredAt   string
		Actor        string
		Action       string
		Resource     string
		Outcome      string
		IPAddress    string
		Detail       string
		AllOutcomes  string
		OutcomeOK    string
		OutcomeFail  string
		OutcomeDeny  string
		ReadOnlyHint string
	}

	Forbidden struct {
		Title       string
		Description string
		BackHome    string
	}

	Errors struct {
		InvalidCredentials  string
		AccountDisabled     string
		Unauthorized        string
		Forbidden           string
		CSRFRejected        string
		InvalidRequest      string
		InternalServerError string
		DeptNotFound        string
		DeptParentInvalid   string
		DeptHasChildren     string
		DeptHasUsers        string
		RoleNotFound        string
		RoleCodeExists      string
		RoleSystemProtected string
		UserNotFound        string
		UserAccountExists   string
		UserSystemProtected string
		UserSelfDelete      string
		UserPasswordMinLen  string
		PrivilegeEscalation string
	}
}

// ResolveLocale determines the user's preferred locale from the request cookie.
func ResolveLocale(r *http.Request, defaultLocale string) string {
	if r != nil {
		if c, err := r.Cookie(LocaleCookieName); err == nil {
			switch strings.TrimSpace(c.Value) {
			case LocaleZhTW:
				return LocaleZhTW
			case LocaleEnUS:
				return LocaleEnUS
			}
		}
	}
	if defaultLocale == LocaleEnUS {
		return LocaleEnUS
	}
	return LocaleZhTW
}

// Catalog returns the strongly typed translation dictionary for the given locale.
func Catalog(locale string) Messages {
	if locale == LocaleEnUS {
		return enUS
	}
	return zhTW
}

// DataScopeLabel returns the localized label for a data scope code.
func (m Messages) DataScopeLabel(scope string) string {
	switch scope {
	case "ALL":
		return m.Role.Scopes.ALL
	case "DEPT_AND_CHILD":
		return m.Role.Scopes.DEPTAndChild
	case "DEPT":
		return m.Role.Scopes.DEPT
	case "SELF":
		return m.Role.Scopes.SELF
	case "CUSTOM":
		return m.Role.Scopes.CUSTOM
	default:
		return scope
	}
}

// UserStatusLabel returns the localized label for a user account status.
func (m Messages) UserStatusLabel(status string) string {
	switch status {
	case "active":
		return m.User.StatusActive
	case "inactive":
		return m.User.StatusInactive
	case "suspended":
		return m.User.StatusSuspended
	default:
		return status
	}
}

var zhTW = func() Messages {
	var m Messages
	m.LangCode = LocaleZhTW
	m.AppTitle = "企業內部 ERP RBAC 管理系統"

	m.Common.Home = "首頁"
	m.Common.Logout = "登出"
	m.Common.Submit = "送出"
	m.Common.ChangeLanguage = "English"
	m.Common.Create = "新增"
	m.Common.Edit = "編輯"
	m.Common.Delete = "刪除"
	m.Common.Cancel = "取消"
	m.Common.Save = "儲存"
	m.Common.Confirm = "確定"
	m.Common.Actions = "操作"
	m.Common.Search = "搜尋"
	m.Common.Reset = "重設"
	m.Common.Filter = "篩選"
	m.Common.Status = "狀態"
	m.Common.NoRecords = "查無符合條件的資料"
	m.Common.Back = "返回"
	m.Common.Navigation = "導覽列"
	m.Common.MainMenu = "主功能選單"
	m.Common.Required = "必填欄位"
	m.Common.WelcomeUser = "歡迎回來，"
	m.Common.WelcomeSystem = "單一執行檔、純 Bootstrap 5、雙 SQLite 企業權限核心"
	m.Common.PleaseEnter = "請輸入"
	m.Common.ConfirmDelete = "確定要刪除此項目嗎？此操作無法復原。"
	m.Common.CreatedAt = "建立時間"
	m.Common.UpdatedAt = "更新時間"
	m.Common.SystemTag = "系統預設"
	m.Common.Yes = "是"
	m.Common.No = "否"
	m.Common.PageInfo = "頁次"
	m.Common.Previous = "上一頁"
	m.Common.Next = "下一頁"

	m.Auth.Login = "登入"
	m.Auth.LoginDescription = "請輸入帳號與密碼以存取系統工作區"
	m.Auth.Account = "帳號"
	m.Auth.Password = "密碼"
	m.Auth.SwitchToOther = "切換語言"

	m.Routes.Home = "歡迎"
	m.Routes.Login = "登入"
	m.Routes.Users = "使用者管理"
	m.Routes.Departments = "組織架構"
	m.Routes.Roles = "角色與權限"
	m.Routes.AuditLogs = "稽核日誌"
	m.Routes.Forbidden = "無權限訪問"

	m.Dept.Title = "組織架構"
	m.Dept.Name = "部門名稱"
	m.Dept.Parent = "上級部門"
	m.Dept.Root = "無（作為頂層部門）"
	m.Dept.Path = "組織路徑"
	m.Dept.Sort = "排序"
	m.Dept.Leader = "部門負責人"
	m.Dept.Create = "新增部門"
	m.Dept.Edit = "編輯部門"
	m.Dept.Delete = "刪除部門"
	m.Dept.DeleteConfirm = "確定要刪除此部門嗎？"
	m.Dept.Saved = "部門資料已儲存"
	m.Dept.Deleted = "部門已刪除"

	m.Role.Title = "角色與權限"
	m.Role.Code = "角色標識"
	m.Role.Name = "角色名稱"
	m.Role.Description = "角色描述"
	m.Role.DataScope = "資料範圍"
	m.Role.Sort = "排序"
	m.Role.Permissions = "功能權限"
	m.Role.CustomDepts = "自訂授權部門"
	m.Role.CustomDeptsHint = "僅在資料範圍選擇「自訂部門」時套用下方勾選項目"
	m.Role.Create = "新增角色"
	m.Role.Edit = "編輯角色"
	m.Role.Delete = "刪除角色"
	m.Role.DeleteConfirm = "確定要刪除此角色嗎？"
	m.Role.Saved = "角色資料已儲存"
	m.Role.Deleted = "角色已刪除"
	m.Role.Scopes.ALL = "全部資料"
	m.Role.Scopes.DEPTAndChild = "本部門及子部門"
	m.Role.Scopes.DEPT = "僅本部門"
	m.Role.Scopes.SELF = "僅本人資料"
	m.Role.Scopes.CUSTOM = "自訂部門"

	m.User.Title = "使用者管理"
	m.User.Account = "帳號"
	m.User.Name = "姓名"
	m.User.EmployeeNo = "工號"
	m.User.JobTitle = "職稱"
	m.User.Password = "密碼"
	m.User.PasswordPlaceholder = "留空則維持原密碼不變"
	m.User.PasswordRequired = "密碼長度至少須為 8 個字元"
	m.User.Department = "所屬部門"
	m.User.Roles = "指派角色"
	m.User.Create = "新增使用者"
	m.User.Edit = "編輯使用者"
	m.User.Delete = "刪除使用者"
	m.User.DeleteConfirm = "確定要刪除此使用者帳號嗎？"
	m.User.Saved = "使用者資料已儲存"
	m.User.Deleted = "使用者已刪除"
	m.User.StatusActive = "正常"
	m.User.StatusInactive = "停用"
	m.User.StatusSuspended = "凍結"
	m.User.AllStatuses = "全部狀態"
	m.User.SearchPlaceholder = "搜尋帳號、姓名或工號"

	m.Audit.Title = "安全稽核日誌"
	m.Audit.OccurredAt = "發生時間 (UTC)"
	m.Audit.Actor = "操作帳號"
	m.Audit.Action = "動作"
	m.Audit.Resource = "目標資源"
	m.Audit.Outcome = "結果"
	m.Audit.IPAddress = "來源 IP"
	m.Audit.Detail = "明細"
	m.Audit.AllOutcomes = "全部結果"
	m.Audit.OutcomeOK = "成功"
	m.Audit.OutcomeFail = "失敗"
	m.Audit.OutcomeDeny = "拒絕"
	m.Audit.ReadOnlyHint = "日誌儲存於獨立唯讀稽核資料庫 (audit.sqlite)，不提供修改或刪除功能。"

	m.Forbidden.Title = "403 禁止訪問"
	m.Forbidden.Description = "您目前沒有足夠權限存取此頁面或執行該項操作。"
	m.Forbidden.BackHome = "返回首頁"

	m.Errors.InvalidCredentials = "帳號或密碼錯誤"
	m.Errors.AccountDisabled = "此帳號已停用或凍結，請聯絡系統管理員"
	m.Errors.Unauthorized = "請先登入系統"
	m.Errors.Forbidden = "存取被拒絕：權限不足"
	m.Errors.CSRFRejected = "安全驗證失敗：拒絕跨站請求"
	m.Errors.InvalidRequest = "請求格式或參數無效"
	m.Errors.InternalServerError = "系統內部錯誤，請稍後再試"
	m.Errors.DeptNotFound = "找不到指定部門"
	m.Errors.DeptParentInvalid = "無效的上級部門（不可選擇自身或下級部門）"
	m.Errors.DeptHasChildren = "此部門仍包含子部門，無法刪除"
	m.Errors.DeptHasUsers = "此部門仍有所屬成員，無法刪除"
	m.Errors.RoleNotFound = "找不到指定角色"
	m.Errors.RoleCodeExists = "角色標識已存在"
	m.Errors.RoleSystemProtected = "系統預設角色受保護，不可刪除或變更標識"
	m.Errors.UserNotFound = "找不到指定使用者"
	m.Errors.UserAccountExists = "該帳號名稱已存在"
	m.Errors.UserSystemProtected = "系統內建管理員帳號受保護，不可刪除"
	m.Errors.UserSelfDelete = "不可刪除目前登入中的帳號"
	m.Errors.UserPasswordMinLen = "密碼長度至少需要 8 個字元"
	m.Errors.PrivilegeEscalation = "權限不足：無法異動高於自身權限的角色或系統帳號"

	return m
}()

var enUS = func() Messages {
	var m Messages
	m.LangCode = LocaleEnUS
	m.AppTitle = "ERP RBAC Administration"

	m.Common.Home = "Home"
	m.Common.Logout = "Logout"
	m.Common.Submit = "Submit"
	m.Common.ChangeLanguage = "繁體中文"
	m.Common.Create = "Create"
	m.Common.Edit = "Edit"
	m.Common.Delete = "Delete"
	m.Common.Cancel = "Cancel"
	m.Common.Save = "Save"
	m.Common.Confirm = "Confirm"
	m.Common.Actions = "Actions"
	m.Common.Search = "Search"
	m.Common.Reset = "Reset"
	m.Common.Filter = "Filter"
	m.Common.Status = "Status"
	m.Common.NoRecords = "No matching records found"
	m.Common.Back = "Back"
	m.Common.Navigation = "Navigation"
	m.Common.MainMenu = "Main Menu"
	m.Common.Required = "This field is required"
	m.Common.WelcomeUser = "Welcome back, "
	m.Common.WelcomeSystem = "Single-binary, CSS-only Bootstrap 5, Dual-SQLite RBAC Core"
	m.Common.PleaseEnter = "Please enter "
	m.Common.ConfirmDelete = "Are you sure you want to delete this item? This action cannot be undone."
	m.Common.CreatedAt = "Created"
	m.Common.UpdatedAt = "Updated"
	m.Common.SystemTag = "System"
	m.Common.Yes = "Yes"
	m.Common.No = "No"
	m.Common.PageInfo = "Page"
	m.Common.Previous = "Previous"
	m.Common.Next = "Next"

	m.Auth.Login = "Sign In"
	m.Auth.LoginDescription = "Sign in with your account and password"
	m.Auth.Account = "Account"
	m.Auth.Password = "Password"
	m.Auth.SwitchToOther = "Language"

	m.Routes.Home = "Welcome"
	m.Routes.Login = "Sign In"
	m.Routes.Users = "Users"
	m.Routes.Departments = "Departments"
	m.Routes.Roles = "Roles & Permissions"
	m.Routes.AuditLogs = "Audit Logs"
	m.Routes.Forbidden = "Access Denied"

	m.Dept.Title = "Departments"
	m.Dept.Name = "Department Name"
	m.Dept.Parent = "Parent Department"
	m.Dept.Root = "None (Top Level)"
	m.Dept.Path = "Path"
	m.Dept.Sort = "Sort Order"
	m.Dept.Leader = "Leader"
	m.Dept.Create = "Create Department"
	m.Dept.Edit = "Edit Department"
	m.Dept.Delete = "Delete Department"
	m.Dept.DeleteConfirm = "Confirm deletion of this department?"
	m.Dept.Saved = "Department saved"
	m.Dept.Deleted = "Department deleted"

	m.Role.Title = "Roles & Permissions"
	m.Role.Code = "Role Code"
	m.Role.Name = "Role Name"
	m.Role.Description = "Description"
	m.Role.DataScope = "Data Scope"
	m.Role.Sort = "Sort Order"
	m.Role.Permissions = "Permissions"
	m.Role.CustomDepts = "Custom Departments"
	m.Role.CustomDeptsHint = "Applied only when Data Scope is set to Custom Departments"
	m.Role.Create = "Create Role"
	m.Role.Edit = "Edit Role"
	m.Role.Delete = "Delete Role"
	m.Role.DeleteConfirm = "Confirm deletion of this role?"
	m.Role.Saved = "Role saved"
	m.Role.Deleted = "Role deleted"
	m.Role.Scopes.ALL = "All Data"
	m.Role.Scopes.DEPTAndChild = "Department & Children"
	m.Role.Scopes.DEPT = "Current Department Only"
	m.Role.Scopes.SELF = "Self Only"
	m.Role.Scopes.CUSTOM = "Custom Departments"

	m.User.Title = "Users"
	m.User.Account = "Account"
	m.User.Name = "Name"
	m.User.EmployeeNo = "Employee No."
	m.User.JobTitle = "Title"
	m.User.Password = "Password"
	m.User.PasswordPlaceholder = "Leave blank to keep existing password"
	m.User.PasswordRequired = "Password must be at least 8 characters"
	m.User.Department = "Department"
	m.User.Roles = "Assigned Roles"
	m.User.Create = "Create User"
	m.User.Edit = "Edit User"
	m.User.Delete = "Delete User"
	m.User.DeleteConfirm = "Confirm deletion of this user account?"
	m.User.Saved = "User saved"
	m.User.Deleted = "User deleted"
	m.User.StatusActive = "Active"
	m.User.StatusInactive = "Inactive"
	m.User.StatusSuspended = "Suspended"
	m.User.AllStatuses = "All Statuses"
	m.User.SearchPlaceholder = "Search account, name, or employee no."

	m.Audit.Title = "Security Audit Logs"
	m.Audit.OccurredAt = "Timestamp (UTC)"
	m.Audit.Actor = "Actor"
	m.Audit.Action = "Action"
	m.Audit.Resource = "Resource"
	m.Audit.Outcome = "Outcome"
	m.Audit.IPAddress = "Source IP"
	m.Audit.Detail = "Details"
	m.Audit.AllOutcomes = "All Outcomes"
	m.Audit.OutcomeOK = "Success"
	m.Audit.OutcomeFail = "Failure"
	m.Audit.OutcomeDeny = "Denied"
	m.Audit.ReadOnlyHint = "Stored in an isolated audit SQLite database (audit.sqlite); records are append-only."

	m.Forbidden.Title = "403 Forbidden"
	m.Forbidden.Description = "You do not have permission to access this resource."
	m.Forbidden.BackHome = "Back to Home"

	m.Errors.InvalidCredentials = "Invalid account or password"
	m.Errors.AccountDisabled = "This account is inactive or suspended"
	m.Errors.Unauthorized = "Authentication required"
	m.Errors.Forbidden = "Access denied: insufficient permissions"
	m.Errors.CSRFRejected = "Security check failed: cross-origin request rejected"
	m.Errors.InvalidRequest = "Invalid request parameters"
	m.Errors.InternalServerError = "Internal server error"
	m.Errors.DeptNotFound = "Department not found"
	m.Errors.DeptParentInvalid = "Invalid parent department (cannot select self or descendant)"
	m.Errors.DeptHasChildren = "Cannot delete department with child departments"
	m.Errors.DeptHasUsers = "Cannot delete department with assigned users"
	m.Errors.RoleNotFound = "Role not found"
	m.Errors.RoleCodeExists = "Role code already exists"
	m.Errors.RoleSystemProtected = "System role cannot be deleted or have its code changed"
	m.Errors.UserNotFound = "User not found"
	m.Errors.UserAccountExists = "Account already exists"
	m.Errors.UserSystemProtected = "System administrator account cannot be deleted"
	m.Errors.UserSelfDelete = "Cannot delete the currently logged-in account"
	m.Errors.UserPasswordMinLen = "Password must be at least 8 characters"
	m.Errors.PrivilegeEscalation = "Insufficient privileges to modify protected roles or accounts"

	return m
}()
