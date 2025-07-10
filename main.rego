package iam.authz

import future.keywords

# By default, deny access if no 'allow' rule evaluates to true.
default allow = false

# Allow if any of the user's assigned roles grant the required permission
# for the action on the resource, considering the scope.
allow {
    # 1. Data Seclusion: Ensure user and resource belong to the same organization.
    input.user.organization_id == input.resource.owning_organization_id

    # 2. Iterate over the roles assigned to the user.
    some assigned_role in input.user.assigned_roles

    # 3. Find the full definition for this role from our data file.
    role_def := get_role_definition(assigned_role.role_id)

    # 4. Delegate to check if the role grants the requested permission.
    permission_is_granted(role_def.permissions, input.action)

    # 5. Delegate to check if the role's scope is valid for this resource.
    scope_is_valid(assigned_role, input.resource)
}

# Helper rule to find a role definition by its ID
get_role_definition(role_id) = role {
    some i
    role := data.role_definitions[i]
    role.role_id == role_id
}
