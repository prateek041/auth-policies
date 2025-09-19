package iam.authz

import rego.v1

# Scope is valid if the role is an organisation-level role AND
# its scope ID matches the resource's owning organisation.
scope_is_valid(assigned_role, resource) if {
	assigned_role.scope_id == resource.owning_organisation_id
}

# Scope is also valid if the role is a team-level role AND
# its scope ID matches the resource's owning team.
scope_is_valid(assigned_role, resource) if {
	# This check correctly fails if resource.owning_team_id does not exist,
	# preventing a team-scoped role from accessing an org-level resource.
	assigned_role.scope_id == resource.owning_team_id
}

is_resource_owner(user, resource) if {
  user.id == resource.owner_id
}
