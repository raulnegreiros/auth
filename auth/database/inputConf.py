# here is defined the maximun input lenhgtś of some
# database ffielfs.
# All user input is verified against these limits are verified


# user limits
class UserLimits:
    name = 90
    username = 40
    service = 30
    email = 254
    profile = 30


# permissions limits
class PermissionLimits:
    path = 254
    method = 30


# groups limits
class GroupLimits:
    name = 30
