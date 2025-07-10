package iam.authz

import future.keywords

# Grant permission if there is a direct, exact match.
permission_is_granted(defined_permissions, requested_action) {
    requested_action in defined_permissions
}

# Grant permission if a wildcard matches. e.g., "kb:*" matches "kb:create".
permission_is_granted(defined_permissions, requested_action) {
    # Find a permission in the list that ends with ":*"
    some permission in defined_permissions
    endswith(permission, ":*")

    # Check if the requested action starts with the part before the wildcard.
    prefix := trim_suffix(permission, "*")
    startswith(requested_action, prefix)
}
