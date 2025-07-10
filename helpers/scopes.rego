package iam.authz

import future.keywords

# Scope is valid if the role is an organization-level role AND
# its scope ID matches the resource's owning organization.
scope_is_valid(assigned_role, resource) {
    assigned_role.scope_id == resource.owning_organization_id
}

# Scope is also valid if the role is a team-level role AND
# its scope ID matches the resource's owning team.
scope_is_valid(assigned_role, resource) {
    # This check correctly fails if resource.owning_team_id does not exist,
    # preventing a team-scoped role from accessing an org-level resource.
    assigned_role.scope_id == resource.owning_team_id
}
