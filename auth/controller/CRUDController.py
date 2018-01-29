# This file contains function to create, search, update and
# delete Users, groups and permissions
import re

import sqlalchemy.orm.exc as orm_exceptions

import controller.PasswordController as password
from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.flaskAlchemyInit import HTTPRequestError
from database.inputConf import UserLimits, PermissionLimits, GroupLimits
import database.Cache as cache
import database.historicModels as inactiveTables
import conf
from database.flaskAlchemyInit import log


# Helper function to check user fields
def check_user(user):
    if not user.get('username', ""):
        raise HTTPRequestError(400, "Missing username")

    if len(user['username']) > UserLimits.username:
        raise HTTPRequestError(400, "Username too long")

    if re.match(r'^[a-z]+[a-z0-9_]', user['username']) is None:
        raise HTTPRequestError(400,
                               'Invalid username. Usernames should start with'
                               ' a letter and only lowercase,'
                               ' alphanumeric and underscores are allowed')

    if not user.get('service', ""):
        raise HTTPRequestError(400, "Missing service")
    if len(user['service']) > UserLimits.service:
        raise HTTPRequestError(400, "Service too long")
    if re.match(r'^[a-z0-9_]+$', user['username']) is None:
        raise HTTPRequestError(400,
                               'Invalid username, only alphanumeric'
                               ' and underscores allowed')

    if not user.get('email', ""):
        raise HTTPRequestError(400, "Missing email")
    if len(user['email']) > UserLimits.email:
        raise HTTPRequestError(400, "E-mail too long")
    if re.match(
            r'(^[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$)',
            user['email']
    ) is None:
        raise HTTPRequestError(400, "Invalid e-mail address")

    if not user.get('name', ""):
        raise HTTPRequestError(400, "Missing user's name (full name)")
    if len(user['name']) > UserLimits.name:
        raise HTTPRequestError(400, "Name too long")

    if not user.get('profile', ""):
        raise HTTPRequestError(400, "Missing profile")
    if len(user['profile']) > UserLimits.profile:
        raise HTTPRequestError(400, "Profile name too long")

    return user


def create_user(db_session, user, requester):
    # drop invalid fields
    user = {k: user[k] for k in user if k in User.fillable}
    check_user(user)

    another_user = db_session.query(User.id) \
        .filter_by(username=user['username']).one_or_none()
    if another_user:
        raise HTTPRequestError(400, "username '"
                               + user['username']
                               + "' is in use.")

    another_user = db_session.query(User.id) \
        .filter_by(email=user['email']).one_or_none()
    if another_user:
        raise HTTPRequestError(400, "Email '" + user['email'] + "' is in use.")

    if conf.emailHost == 'NOEMAIL':
        user['salt'], user['hash'] = password.create_pwd(conf.temporaryPassword)

    user['created_by'] = requester['userid']
    new_user = User(**user)
    log().info('user ' + user['username'] + ' created by '
               + requester['username'],
               new_user.safeDict())
    return new_user


def search_user(db_session, username=None):
    user_query = db_session.query(User)

    if username:
        user_query = user_query.filter(User.username.like('%' + username + '%'))

    users = user_query.all()
    if not users:
        raise HTTPRequestError(404, "No results found with these filters")
    return users


def get_user(db_session, user):
    try:
        user = User.getByNameOrID(user)
        return user
    except (orm_exceptions.NoResultFound, ValueError):
        raise HTTPRequestError(404, "No user found with this ID")


def update_user(db_session, user, updated_info, requester):
    # Drop invalid fields
    updated_info = {
        k: updated_info[k]
        for k in updated_info
        if k in User.fillable
    }
    old_user = User.getByNameOrID(user)
    old_service = old_user.service

    if 'username' in updated_info.keys() \
            and updated_info['username'] != old_user.username:
        raise HTTPRequestError(400, "usernames can't be updated")

    check_user(updated_info)

    # Verify if the email is in use by another user
    if 'email' in updated_info.keys() and updated_info['email'] != old_user.email:
        another_user = db_session.query(User) \
            .filter_by(email=updated_info['email']) \
            .one_or_none()
        if another_user:
            raise HTTPRequestError(400, "email already in use")

    log().info('user ' + old_user.username + ' updated by '
               + requester['username'],
               {'oldUser': old_user.safeDict(), 'newUser': updated_info})
    if 'name' in updated_info.keys():
        old_user.name = updated_info['name']
    if 'service' in updated_info.keys():
        old_user.service = updated_info['service']
    if 'email' in updated_info.keys():
        old_user.email = updated_info['email']

    return (old_user, old_service)


def delete_user(db_session, user, requester):
    try:
        user = User.getByNameOrID(user)
        if user.id == requester['userid']:
            raise HTTPRequestError(400, "a user can't remove himself")
        db_session.execute(
            UserPermission.__table__.delete(UserPermission.user_id == user.id)
        )
        db_session.execute(
            UserGroup.__table__.delete(UserGroup.user_id == user.id)
        )
        cache.delete_key(userid=user.id)

        # The user is not hardDeleted.
        # it should be copied to inactiveUser table
        inactiveTables.PasswdInactive.createInactiveFromUser(db_session,
                                                             user, )
        inactiveTables.UserInactive.createInactiveFromUser(db_session,
                                                           user,
                                                           requester['userid'])
        password.expire_password_reset_requests(db_session, user.id)
        db_session.delete(user)
        log().info('user ' + user.username + ' deleted by '
                   + requester['username'],
                   user.safeDict())
        return user;
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID")


# Helper function to check permission fields
def check_perm(perm):
    if 'name' not in perm.keys() or len(perm['name']) == 0:
        raise HTTPRequestError(400, "Missing permission name")
    if len(perm['path']) > PermissionLimits.path:
        raise HTTPRequestError(400, "Path too long")
    if re.match(r'^[a-z]+[a-z0-9_]', perm['name']) is None:
        raise HTTPRequestError(400,
                               'Invalid name. permission names should start'
                               ' with a letter and only lowercase,'
                               ' alhpanumeric and underscores are allowed')

    if 'permission' in perm.keys():
        if perm['permission'] not in [p.value for p in PermissionEnum]:
            raise HTTPRequestError(400,
                                   "An access control rule can not return '"
                                   + perm['permission']
                                   + "'")
    else:
        # Default value if permission is omitted
        perm['permission'] = 'permit'

    if 'path' not in perm.keys() or len(perm['path']) == 0:
        raise HTTPRequestError(400, "Missing permission Path")
    if len(perm['path']) > PermissionLimits.path:
        raise HTTPRequestError(400, "Path too long")

    if 'method' not in perm.keys() or len(perm['method']) == 0:
        raise HTTPRequestError(400, "Missing permission method")
    if len(perm['method']) > PermissionLimits.method:
        raise HTTPRequestError(400, "Method too long")

    try:
        re.match(r'(^' + perm['method'] + ')', "")
    except re.error:
        raise HTTPRequestError(400, perm['method']
                               + " is not a valid regular expression.")

    try:
        re.match(r'(^' + perm['path'] + ')', "")
    except re.error:
        raise HTTPRequestError(400, perm['method']
                               + " is not a valid regular expression.")


def create_perm(db_session, permission, requester):
    permission = {
        k: permission[k]
        for k in permission
        if k in Permission.fillable
    }
    check_perm(permission)
    permission['created_by'] = requester['userid']
    perm = Permission(**permission)
    log().info('permission ' + perm.name + ' deleted by '
               + requester['username'],
               perm.safeDict())
    return perm


def search_perm(db_session, path=None, method=None, permission=None):
    perm_query = db_session.query(Permission)
    if path:
        perm_query = perm_query.filter(Permission.path.like('%' + path + '%'))
    if method:
        perm_query = perm_query.filter(
            Permission.method.like('%' + method + '%'))
    if permission:
        if permission not in [p.value for p in PermissionEnum]:
            raise HTTPRequestError(400,
                                   "Invalid filter. Permission can't be '"
                                   + permission + "'")
        perm_query = perm_query.filter_by(permission=permission)

    perms = perm_query.all()
    if not perms:
        raise HTTPRequestError(404, "No results found with these filters")
    return perms


def get_perm(db_session, permission):
    try:
        perm = Permission.getByNameOrID(permission)
        return perm
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")


def update_perm(db_session, permission, perm_data, requester):
    perm_data = {k: perm_data[k] for k in perm_data if k in Permission.fillable}
    check_perm(perm_data)
    try:
        perm = Permission.getByNameOrID(permission)
        if 'name' in perm_data.keys() and perm.name != perm_data['name']:
            raise HTTPRequestError(400, "permission name can't be changed")
        for key, value in perm_data.items():
            setattr(perm, key, value)
        db_session.add(perm)
        log().info('permission ' + perm.name + ' updated by '
                   + requester['username'],
                   perm_data)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")


def delete_perm(db_session, permission, requester):
    try:
        perm = Permission.getByNameOrID(permission)
        db_session.execute(
            UserPermission.__table__.delete(UserPermission.permission_id == perm.id)
        )
        db_session.execute(
            GroupPermission.__table__.delete(GroupPermission.permission_id == perm.id)
        )
        cache.delete_key(action=perm.method, resource=perm.path)
        log().info('permission ' + str(perm.name) + ' deleted by '
                   + requester['username'],
                   perm.safeDict())
        db_session.delete(perm)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID or name")


def check_group(group):
    if not group.get('name', ""):
        raise HTTPRequestError(400, 'Missing group name')
    if len(group['name']) > GroupLimits.name:
        raise HTTPRequestError(400, "Group name too long")

    if re.match(r'^[a-zA-Z0-9]+$', group['name']) is None:
        raise HTTPRequestError(400,
                               'Invalid group name, only alphanumeric allowed')

    if 'desc' in group.keys() and len(group['desc']) > GroupLimits.description:
        raise HTTPRequestError(400, "Group description is too long")


def create_group(db_session, group_data, requester):
    group_data = {k: group_data[k] for k in group_data if k in Group.fillable}
    check_group(group_data)

    another_group = db_session.query(Group.id) \
        .filter_by(name=group_data['name']).one_or_none()
    if another_group:
        raise HTTPRequestError(400, "Group name '"
                               + group_data['name'] + "' is in use.")

    group_data['created_by'] = requester['userid']
    g = Group(**group_data)
    log().info('group ' + g.name + ' created by '
               + requester['username'],
               g.safeDict())
    return g


def search_group(db_session, name=None):
    group_query = db_session.query(Group)
    if name:
        group_query = group_query.filter(Group.name.like('%' + name + '%'))

    groups = group_query.all()
    if not groups:
        raise HTTPRequestError(404, "No results found with these filters")

    return groups


def get_group(db_session, group):
    try:
        group = Group.getByNameOrID(group)
        return group
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID")


def update_group(db_session, group, group_data, requester):
    group_data = {k: group_data[k] for k in group_data if k in Group.fillable}
    check_group(group_data)
    try:
        group = Group.getByNameOrID(group)
        if 'name' in group_data.keys() and group.name != group_data['name']:
            raise HTTPRequestError(400, "groups name can't be changed")
        for key, value in group_data.items():
            setattr(group, key, value)
        db_session.add(group)
        log().info('group ' + group.name + ' updated by '
                   + requester['username'],
                   group_data)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID")


def delete_group(db_session, group, requester):
    try:
        group = Group.getByNameOrID(group)
        db_session.execute(
            GroupPermission.__table__.delete(GroupPermission.group_id == group.id)
        )
        db_session.execute(
            UserGroup.__table__.delete(UserGroup.group_id == group.id)
        )
        cache.delete_key()
        log().info('group ' + group.name + ' deleted by '
                   + requester['username'],
                   group.safeDict())
        db_session.delete(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID")

def count_tenant_users(db_session, tenant):
    try:
        return db_session.query(User).filter(User.service == tenant).count()
    except orm_exceptions.NoResultFound:
        return 0


def list_tenants(db_session):
    try:
        tenants = []
        for tenant in db_session.query(User.service).distinct():
            tenants.append(tenant[0])
        return tenants
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No registered tenants found")
