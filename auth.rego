package hello

import future.keywords.in

# By default, deny everything.
default allow = false

# Allow if the user's role has the requested permission in our data file.
allow {
    # 1. Get the user's role from the input document.
    user_role := input.user.role

    # 2. Look up the list of permissions for that role from data.json.
    permissions_for_role := data.roles[user_role]

    # 3. Check if the action from the input is in the list of permissions.
    input.action in permissions_for_role
}
