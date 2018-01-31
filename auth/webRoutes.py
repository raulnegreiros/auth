#!/usr/bin/python3
# This file contains the available endpoints
# functions here focus on extract data from HTTP requests
# and format responses and errors to JSON
# These functions should be as smaller as possible
# most of the input validation is done on the controllers

from flask import request
import json

import conf
import controller.CRUDController as crud
import controller.RelationshipController as rship
import controller.PDPController as pdpc
import controller.AuthenticationController as auth
import controller.ReportController as reports
import controller.PasswordController as pwdc
import kongUtils as kong
from database.flaskAlchemyInit import app, db, format_response, \
    HTTPRequestError, make_response, load_json_from_request
from database.Models import MVUserPermission, MVGroupPermission
import database.Cache as cache

from utils.serialization import json_serial
from database.flaskAlchemyInit import log
from controller.KafkaPublisher import send_notification


# Authentication endpoint
@app.route('/', methods=['POST'])
def authenticate():
    try:
        auth_data = load_json_from_request(request)
        jwt = auth.authenticate(db.session, auth_data)
        return make_response(json.dumps({'jwt': jwt}), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


# User CRUD
@app.route('/user', methods=['POST'])
def create_user():
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        auth_data = load_json_from_request(request)

        # Create user
        new_user = crud.create_user(db.session, auth_data, requester)

        # If no problems occur to create user (no exceptions), configure kong
        kong_data = kong.configure_kong(new_user.username)
        if kong_data is None:
            return format_response(500, 'failed to configure verification subsystem')
        new_user.secret = kong_data['secret']
        new_user.key = kong_data['key']
        new_user.kongId = kong_data['kongid']

        db.session.add(new_user)
        db.session.commit()
        group_success = []
        group_failed = []
        if 'profile' in auth_data.keys():
            group_success, group_failed = rship. \
                add_user_many_groups(db.session, new_user.id,
                                     auth_data['profile'], requester)
        db.session.commit()
        if conf.emailHost != 'NOEMAIL':
            pwdc.create_password_set_request(db.session, new_user)
            db.session.commit()

        if crud.count_tenant_users(db.session, new_user.service) == 1:
            log().info("will emit tenant lifecycle event {} - CREATE".format(new_user.service))
            send_notification({"type": 'CREATE', 'tenant': new_user.service})

        return make_response(json.dumps({
            "user": new_user.safeDict(),
            "groups": group_success,
            "could not add": group_failed,
            "message": "user created"
        }, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/user', methods=['GET'])
def list_users():
    try:
        users = crud.search_user(
            db.session,
            # Optional search filters
            request.args['username'] if 'username' in request.args else None
        )
        users_safe = list(map(lambda u: u.safeDict(), users))
        return make_response(json.dumps({"users": users_safe}, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/user/<user>', methods=['GET'])
def get_user(user):
    try:
        user = crud.get_user(db.session, user)
        return make_response(json.dumps({"user": user.safeDict()}, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/user/<user>', methods=['PUT'])
def update_user(user):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        auth_data = load_json_from_request(request)
        updated_user, old_service = crud.update_user(db.session, user, auth_data, requester)

        # Create a new kong secret and delete the old one
        kong_data = kong.configure_kong(updated_user.username)
        if kong_data is None:
            return format_response(500, 'failed to configure verification subsystem')

        kong.revoke_kong_secret(updated_user.username, updated_user.kongId)
        updated_user.secret = kong_data['secret']
        updated_user.key = kong_data['key']
        updated_user.kongid = kong_data['kongid']
        db.session.add(updated_user)
        db.session.commit()

        if crud.count_tenant_users(db.session, old_service) == 0:
            log().info("will emit tenant lifecycle event {} - DELETE".format(old_service))
            send_notification({"type": 'DELETE', 'tenant': old_service})

        if crud.count_tenant_users(db.session, updated_user.service) == 1:
            log().info("will emit tenant lifecycle event {} - CREATE".format(updated_user.service))
            send_notification({"type": 'CREATE', 'tenant': updated_user.service})
        return format_response(200)

    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/user/<user>', methods=['DELETE'])
def remove_user(user):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        old_username = crud.get_user(db.session, user).username
        old_user = crud.delete_user(db.session, user, requester)
        kong.remove_from_kong(old_username)
        MVUserPermission.refresh()
        MVGroupPermission.refresh()
        db.session.commit()

        if crud.count_tenant_users(db.session, old_user.service) == 0:
            log().info("will emit tenant lifecycle event {} - DELETE".format(old_user.service))
            send_notification({"type": 'DELETE', 'tenant': old_user.service})

        return format_response(200, "User removed")
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


# Permission CRUD
@app.route('/pap/permission', methods=['POST'])
def create_permission():
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        perm_data = load_json_from_request(request)
        new_perm = crud.create_perm(db.session, perm_data, requester)
        db.session.add(new_perm)
        db.session.commit()
        return make_response(json.dumps({
            "status": 200,
            "id": new_perm.id
        }, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/permission', methods=['GET'])
def list_permissions():
    try:
        permissions = crud.search_perm(
            db.session,

            # search filters
            request.args['path'] if 'path' in request.args else None,
            request.args['method'] if 'method' in request.args else None,
            request.args['permission']
            if 'permission' in request.args else None
        )
        permissions_safe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({"permissions": permissions_safe}, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/permission/<permid>', methods=['GET'])
def get_permission(permid):
    try:
        perm = crud.get_perm(db.session, permid)
        return make_response(json.dumps(perm.safeDict(), default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/permission/<permid>', methods=['PUT'])
def update_permission(permid):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        perm_data = load_json_from_request(request)
        crud.update_perm(db.session, permid, perm_data, requester)
        db.session.commit()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/permission/<permid>', methods=['DELETE'])
def delete_permission(permid):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        crud.get_perm(db.session, permid)
        crud.delete_perm(db.session, permid, requester)
        db.session.commit()
        MVUserPermission.refresh()
        MVGroupPermission.refresh()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


# Group CRUD
@app.route('/pap/group', methods=['POST'])
def create_group():
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        group_data = load_json_from_request(request)
        new_group = crud.create_group(db.session, group_data, requester)
        db.session.add(new_group)
        db.session.commit()
        return make_response(json.dumps({
            "status": 200,
            "id": new_group.id
        }, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/group', methods=['GET'])
def list_group():
    try:
        groups = crud.search_group(
            db.session,

            # search filters
            request.args['name'] if 'name' in request.args else None
        )
        groups_safe = list(map(lambda p: p.safeDict(), groups))
        for g in groups_safe:
            g['created_date'] = g['created_date'].isoformat()
        return make_response(json.dumps({"groups": groups_safe}, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/group/<group>', methods=['GET'])
def get_group(group):
    try:
        group = crud.get_group(db.session, group)
        group = group.safeDict()
        group['created_date'] = group['created_date'].isoformat()
        return make_response(json.dumps(group, default=json_serial), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/group/<group>', methods=['PUT'])
def update_group(group):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        group_data = load_json_from_request(request)
        crud.update_group(db.session, group, group_data, requester)
        db.session.commit()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/group/<group>', methods=['DELETE'])
def delete_group(group):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        crud.delete_group(db.session, group, requester)
        MVGroupPermission.refresh()
        db.session.commit()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/usergroup/<user>/<group>', methods=['POST', 'DELETE'])
def add_user_to_group(user, group):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        if request.method == 'POST':
            rship.add_user_group(db.session, user, group, requester)
        else:
            rship.remove_user_group(db.session, user, group, requester)
        db.session.commit()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/grouppermissions/<group>/<permission>', methods=['POST', 'DELETE'])
def add_group_permission(group, permission):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        if request.method == 'POST':
            rship.add_group_permission(db.session, group, permission, requester)
        else:
            rship.remove_group_permission(db.session, group,
                                          permission, requester)
        MVGroupPermission.refresh()
        db.session.commit()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pap/userpermissions/<user>/<permission>', methods=['POST', 'DELETE'])
def add_user_permission(user, permission):
    try:
        requester = auth.get_jwt_payload(request.headers.get('Authorization'))
        if request.method == 'POST':
            rship.add_user_permission(db.session, user, permission, requester)
        else:
            rship.remove_user_permission(db.session, user,
                                         permission, requester)
        MVUserPermission.refresh()
        db.session.commit()
        return format_response(200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


@app.route('/pdp', methods=['POST'])
def pdp_request():
    try:
        pdp_data = load_json_from_request(request)
        veredict = pdpc.pdp_main(db.session, pdp_data)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        return make_response(json.dumps({
            "decision": veredict,
            "status": "ok"
        }, default=json_serial), 200)


#  Reports endpoints
@app.route('/pap/user/<user>/directpermissions', methods=['GET'])
def get_user_direct_permissions(user):
    try:
        permissions = reports.get_user_direct_permissions(db.session, user)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        permissions_safe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({"permissions": permissions_safe}, default=json_serial), 200)


@app.route('/pap/user/<user>/allpermissions', methods=['GET'])
def get_all_user_permissions(user):
    try:
        permissions = reports.get_all_user_permissions(db.session, user)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        permissions_safe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({"permissions": permissions_safe}, default=json_serial), 200)


@app.route('/pap/user/<user>/groups', methods=['GET'])
def get_user_grups(user):
    try:
        groups = reports.get_user_groups(db.session, user)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        groups_safe = list(map(lambda p: p.safeDict(), groups))
        return make_response(json.dumps({"groups": groups_safe}, default=json_serial), 200)


@app.route('/pap/group/<group>/permissions', methods=['GET'])
def get_group_permissions(group):
    try:
        permissions = reports.get_group_permissions(db.session, group)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        permissions_safe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({"permissions": permissions_safe}, default=json_serial), 200)


@app.route('/pap/group/<group>/users', methods=['GET'])
def get_group_users(group):
    try:
        users = reports.get_group_users(db.session, group)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        users_safe = list(map(lambda p: p.safeDict(), users))
        return make_response(json.dumps({"users": users_safe}, default=json_serial), 200)


# password related endpoints
@app.route('/password/reset/<username>', methods=['POST'])
def passwd_reset_request(username):
    if conf.emailHost == 'NOEMAIL':
        return format_response(501, "Feature not configured")
    try:
        pwdc.create_password_reset_request(db.session, username)
        db.session.commit()
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        return format_response(200)


# password related endpoints
@app.route('/password/resetlink', methods=['POST'])
def password_reset():
    try:
        link = request.args.get('link')
        reset_data = load_json_from_request(request)
        updating_user = pwdc.reset_password(db.session, link, reset_data)

        # password updated. Should reconfigure kong and Invalidate
        # all previous logins
        kong_data = kong.configure_kong(updating_user.username)
        if kong_data is None:
            return format_response(500,
                                   'failed to configure verification subsystem')

        kong.revoke_kong_secret(updating_user.username, updating_user.kongId)
        updating_user.secret = kong_data['secret']
        updating_user.key = kong_data['key']
        updating_user.kongid = kong_data['kongid']
        db.session.add(updating_user)
        db.session.commit()
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        return format_response(200)


@app.route('/password/update', methods=['POST'])
def update_password():
    try:
        user_id = auth.user_id_from_jwt(request.headers.get('Authorization'))
        update_data = load_json_from_request(request)
        pwdc.update_endpoint(db.session, user_id, update_data)
        db.session.commit()
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)
    else:
        return format_response(200)


# TODO: When to remove this endpoint?
# endpoint for development use. Should be blocked on prodution
@app.route('/admin/dropcache', methods=['DELETE'])
def drop_cache():
    cache.delete_key()
    return format_response(200)


@app.route('/admin/tenants', methods=['GET'])
def list_tenants():
    """Returns a list containing all existing tenants in the system"""

    try:
        tenants = crud.list_tenants(db.session)
        return make_response(json.dumps({"tenants": tenants}), 200)
    except HTTPRequestError as err:
        return format_response(err.errorCode, err.message)


if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)
