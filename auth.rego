package iam.authz

import future.keywords.in
import future.keywords.if

# By default, deny access if no 'allow' rule evaluates to true.
default allow = false

# Allow if any of the user's assigned roles grant the required permission
# for the action on the resource, considering the scope.
allow = true { # <--- ADDED '= true' here to make it a boolean rule
    # 1. Ensure user and resource belong to the same organization (Data Seclusion)
    input.user.organization_id == input.resource.owning_organization_id

    # 2. Iterate over the user's assigned roles
    some role_assignment in input.user.assigned_roles

    # 3. Find the definition for this assigned role
    some i
    role_def := data.role_definitions[i]
    role_def.id == role_assignment.role_id

    # 4. Check if the role's permissions include the requested action (with wildcard support)
    permission_is_granted(role_def.permissions, input.action)

    # 5. Validate the scope of the role assignment against the resource
    is_scope_valid(role_assignment, role_def, input.resource)
}

# --- Helper rule for permission checking (direct match or wildcard match) ---
permission_is_granted(defined_permissions, requested_action) {
    # Attempt direct match first
    some p_idx
    defined_permissions[p_idx] == requested_action
}

permission_is_granted(defined_permissions, requested_action) {
    # Attempt wildcard match (e.g., "document:*" should match "document:read")
    some p_idx
    wildcard_permission := defined_permissions[p_idx]
    endswith(wildcard_permission, ":*")
    prefix := trim_suffix(wildcard_permission, "*")
    startswith(requested_action, prefix)
}

# --- Helper rules for scope validation ---

# Scope is valid if the role is an organization-level role AND its scope matches the resource's organization
is_scope_valid(role_assignment, role_def, resource) {
    role_def.applies_to_scope_type == "organization"
    role_assignment.scope_id == resource.owning_organization_id
}

# Scope is valid if the role is a team-level role AND its scope matches the resource's owning team
is_scope_valid(role_assignment, role_def, resource) {
    role_def.applies_to_scope_type == "team"
    resource.owning_team_id
    role_assignment.scope_id == resource.owning_team_id
}

