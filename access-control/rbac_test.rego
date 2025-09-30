package access_control.rbac

import future.keywords.if



test_admin_can_delete_any_resource if {
    allow with input as {
        "user": {"name": "admin@test.com", "role": "admin"},
        "action": "delete",
        "resource": "production"
    }
}

test_admin_can_manage_users if {
    allow with input as {
        "user": {"name": "admin@test.com", "role": "admin"},
        "action": "manage_users",
        "resource": "users"
    }
}


test_developer_can_write_to_applications if {
    allow with input as {
        "user": {"name": "dev@test.com", "role": "developer"},
        "action": "write",
        "resource": "applications"
    }
}

test_developer_can_deploy_to_staging if {
    allow with input as {
        "user": {"name": "dev@test.com", "role": "developer"},
        "action": "deploy",
        "resource": "staging"
    }
}

test_developer_cannot_access_production if {
    not allow with input as {
        "user": {"name": "dev@test.com", "role": "developer"},
        "action": "write",
        "resource": "production"
    }
}

test_developer_cannot_delete if {
    not allow with input as {
        "user": {"name": "dev@test.com", "role": "developer"},
        "action": "delete",
        "resource": "applications"
    }
}


test_security_engineer_can_manage_policies if {
    allow with input as {
        "user": {"name": "security@test.com", "role": "security_engineer"},
        "action": "manage_policies",
        "resource": "policies"
    }
}

test_security_engineer_can_audit if {
    allow with input as {
        "user": {"name": "security@test.com", "role": "security_engineer"},
        "action": "audit",
        "resource": "logs"
    }
}


test_support_can_read_tickets if {
    allow with input as {
        "user": {"name": "support@test.com", "role": "support"},
        "action": "read",
        "resource": "tickets"
    }
}

test_support_cannot_access_applications if {
    not allow with input as {
        "user": {"name": "support@test.com", "role": "support"},
        "action": "read",
        "resource": "applications"
    }
}


test_invalid_role_denied if {
    not allow with input as {
        "user": {"name": "hacker@test.com", "role": "superuser"},
        "action": "read",
        "resource": "applications"
    }
}



test_permission_deny_message if {
    expected := "Permission denied: User 'dev@test.com' with role 'developer' cannot perform action 'delete'"
    deny[expected] with input as {
        "user": {"name": "dev@test.com", "role": "developer"},
        "action": "delete",
        "resource": "applications"
    }
}

test_resource_deny_message if {
    expected := "Resource access denied: User 'dev@test.com' cannot access resource 'production'"
    deny[expected] with input as {
        "user": {"name": "dev@test.com", "role": "developer"},
        "action": "write",
        "resource": "production"
    }
}