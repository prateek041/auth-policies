package hello

# By default, access is denied.
default allow = false

# Allow access ONLY if the input user is "admin".
allow {
    input.user == "admin"
}
