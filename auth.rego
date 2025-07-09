# The package defines the "path" to this policy's rules.
package play.authz

import future.keywords.in

# By default, deny everything. This is a crucial security principle.
default allow = false

# The 'allow' rule will be true if the conditions inside the curly braces are met.
allow {
    # 1. Get the user's role from the input document.
    user_role := input.user.role

    # 2. Look up the list of permissions for that role from the data document.
    permissions_for_role := data.roles[user_role]

    # 3. Check if the action from the input is in the list of permissions we just found.
    input.action in permissions_for_role
}
