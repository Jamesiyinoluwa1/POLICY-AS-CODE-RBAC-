package access-control.rbac 

import future.keywords.if
import future.keywords.in

default allow = false

roles := {
    "admin": {
        "permissions": ["read", "write", "delete", "manage_users", "manage_roles", "view_logs"],
        "resources": ["*"]  
    },
    "developer": {
        "permissions": ["read", "write", "deploy"],
        "resources": ["applications", "repositories", "staging"]
    },
    "security_engineer": {
        "permissions": ["read", "write", "audit", "view_logs", "manage_policies"],
        "resources": ["security", "logs", "policies", "compliance"]
    },
    "support": {
        "permissions": ["read", "comment"],
        "resources": ["tickets", "documentation", "users"]
    }
}

allow if{
    user_role := input.user.role

    roles[user_role]

    requested_action := input.action
    requested_resource := input.resources

    has_permission(user_role, requested_action)
    has_resource_access(user_role, requested_resource)
}

has_permission(role, action) if {
    action in roles[role].permissions
}

has_resource_access(role, resource) if {
    "*" in roles[role].resources
}

has_resource_access(role, resource) if {
    resource in roles[role].resources
}

deny contains msg if {
    not allow
    not roles[input.user.role]
    msg := sprintf("Invalid role: '%v'. User '%v' has an unrecognized role.", 
        [input.user.role, input.user.name])
}

    deny contains msg if {
        not allow
        roles[input.user.role]
        not has_permission(input.user.role, input.action)
           msg := sprintf("Permission denied: User '%v' with role '%v' cannot perform action '%v'", 
        [input.user.name, input.user.role, input.action])
}

deny contains msg if {
    not allow
    roles[input.user.role]
    has_permission(input.user.role, input.action)
    not has_resource_access(input.user.role, input.resource)
    msg := sprintf("Resource access denied: User '%v' cannot access resource '%v'", 
        [input.user.name, input.resource])
}    

user_permissions contains permission if {
    user_role := input.user.role
    roles[user_role]
    permission := roles[user_role].permissions[_]
}


user_resources contains resource if {
    user_role := input.user.role
    roles[user_role]
    resource := roles[user_role].resources[_]
}    