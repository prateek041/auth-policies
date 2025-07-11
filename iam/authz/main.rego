package iam.authz

import rego.v1

# By default, deny access if no 'allow' rule evaluates to true.
default allow := false

# Allow if any of the user's assigned roles grant the required permission
# for the action on the resource, considering the scope.
allow if {
	# 1. Data Seclusion: Ensure user and resource belong to the same organisation.
	input.user.organisation_id == input.resource.owning_organisation_id

	# 2. Iterate over the roles assigned to the user.
	some assigned_role in input.user.assigned_roles

	# 3. Find the full definition for this role from our data file.
	role_def := role_definition(assigned_role.role_id)

	# 4. Delegate to check if the role grants the requested permission.
	permission_is_granted(role_def.permissions, input.action)

	# 5. Delegate to check if the role's scope is valid for this resource.
	scope_is_valid(assigned_role, input.resource)
}

# Helper rule to find a role definition by its ID
role_definition(role_id) := role if {
	some role in data.role_definitions
	role.role_id == role_id
}
