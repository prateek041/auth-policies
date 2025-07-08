package iam.authz

import future.keywords.in

# Allow if any of the user's assigned roles grant the required permission
# for the action on the resource, considering the scope.
# By default, deny access
allow { # No 'if' here, directly defines the rule
    # 1. Ensure user and resource belong to the same organization (Data Seclusion)
    input.user.organization_id == input.resource.owning_organization_id

    # 2. Iterate over the user's assigned roles
    some role_assignment in input.user.assigned_roles

    # 3. Find the definition for this assigned role
    role_def := data.role_definitions[_]
    role_def.id == role_assignment.role_id

    # 4. Check if the role's permissions include the requested action (with wildcard support)
    permission_is_granted(role_def.permissions, input.action)

    # 5. Validate the scope of the role assignment against the resource
    is_scope_valid(role_assignment, role_def, input.resource)
}

# --- Helper rule for permission checking (direct match or wildcard match) ---
permission_is_granted(defined_permissions, requested_action) if { # Added 'if'
    # Attempt direct match first
    defined_permissions[_] == requested_action
}

permission_is_granted(defined_permissions, requested_action) if { # Added 'if'
    # Attempt wildcard match (e.g., "document:*" should match "document:read")
    wildcard_permission := defined_permissions[_]
    endswith(wildcard_permission, ":*") # Ensures it's a resource_type:* pattern
    prefix := trim_suffix(wildcard_permission, "*") # Gets "resource_type:"
    startswith(requested_action, prefix) # Checks if requested_action starts with that prefix
}

# --- Helper rules for scope validation ---

# Scope is valid if the role is an organization-level role AND its scope matches the resource's organization
is_scope_valid(role_assignment, role_def, resource) if { # Added 'if'
    role_def.applies_to_scope_type == "organization"
    role_assignment.scope_id == resource.owning_organization_id
}

# Scope is valid if the role is a team-level role AND its scope matches the resource's owning team
is_scope_valid(role_assignment, role_def, resource) if { # Added 'if'
    role_def.applies_to_scope_type == "team"
    # Ensure the resource actually has an owning team if the role is team-scoped
    # and the resource is the one being checked for team ownership.
    resource.owning_team_id # This implicitly checks if owning_team_id is not null/undefined
    role_assignment.scope_id == resource.owning_team_id
}

# By default, deny access
default allow = false
