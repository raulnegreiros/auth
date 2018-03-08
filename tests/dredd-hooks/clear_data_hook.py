import dredd_hooks as hooks
import controller.CRUDController as crud
from database.flaskAlchemyInit import db
from database.flaskAlchemyInit import HTTPRequestError


@hooks.before_all
def auth_clear_permissions_and_groups(transaction):
    requester = {
        "userid": 0,
        "username": "dredd"
    }
    try:
        users = crud.search_user(db.session, None)
        # Delete all users
        for user in users:
            crud.delete_user(db.session, user.username, requester)
    except HTTPRequestError:
        pass

    try:
        permissions = crud.search_perm(db.session)
        for permission in permissions:
            crud.delete_perm(db.session, permission.name, requester)
    except HTTPRequestError as e:
        pass

    try:
        groups = crud.search_group(db.session)
        for group in groups:
            crud.delete_group(db.session, group.name, requester)
    except HTTPRequestError as e:
        pass


@hooks.after_each
def auth_clear_everything_hook(transaction):
    requester = {
        "userid": 0,
        "username": "dredd"
    }
    try:
        users = crud.search_user(db.session, None)
        # Delete all users
        for user in users:
            crud.delete_user(db.session, user.username, requester)
    except HTTPRequestError:
        pass

    try:
        permissions = crud.search_perm(db.session)
        for permission in permissions:
            crud.delete_perm(db.session, permission.name, requester)
    except HTTPRequestError as e:
        pass

    try:
        groups = crud.search_group(db.session)
        for group in groups:
            crud.delete_group(db.session, group.name, requester)
    except HTTPRequestError as e:
        pass
