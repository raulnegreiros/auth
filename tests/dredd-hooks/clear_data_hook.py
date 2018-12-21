import dredd_hooks as hooks
import controller.CRUDController as crud
from database.Models import PermissionTypeEnum
from database.flaskAlchemyInit import db
from database.flaskAlchemyInit import HTTPRequestError

from database.flaskAlchemyInit import log


@hooks.before_all
def auth_clear_permissions_and_groups(transaction):
    requester = {
        "userid": 0,
        "username": "dredd"
    }
    log().info(">>>>>>> Limpando cenario para proxima execucao...")
    try:
        users = crud.search_user(db.session, None)
        # Delete all users
        for user in users:
            crud.delete_user(db.session, user.username, requester)
    except HTTPRequestError:
        pass

    try:
        permissions = crud.search_perm(db.session)
        log().info(">>>>>>> Removendo permissao: ")
        for permission in permissions:
            log().info(">>>>>>> Permissao: " + permission.name + ", tipo: " + permission.type.value)
            if permission.type != PermissionTypeEnum.system:
                crud.delete_perm(db.session, permission.name, requester)
    except HTTPRequestError as e:
        log().error(">>>>> Excecao durante remocao de permissao: " + e)
        # pass

    try:
        groups = crud.search_group(db.session)
        for group in groups:
            crud.delete_group(db.session, group.name, requester)
    except HTTPRequestError as e:
        pass

    log().info(">>>>>>> ... cenario foi limpo.")


@hooks.after_each
def auth_clear_everything_hook(transaction):
    requester = {
        "userid": 0,
        "username": "dredd"
    }
    log().info(">>>>>>> Limpando cenario apos execucao de caso de teste...")
    try:
        users = crud.search_user(db.session, None)
        # Delete all users
        for user in users:
            crud.delete_user(db.session, user.username, requester)
    except HTTPRequestError:
        pass

    try:
        permissions = crud.search_perm(db.session)
        log().info(">>>>>>> Removendo permissao: ")
        for permission in permissions:
            log().info(">>>>>>> Permissao: " + permission.name + ", tipo: " + permission.type.value)
            if permission.type != PermissionTypeEnum.system:
                crud.delete_perm(db.session, permission.name, requester)
    except HTTPRequestError as e:
        log().error(">>>>> Excecao durante remocao de permissao: " + e)
        # pass

    try:
        groups = crud.search_group(db.session)
        for group in groups:
            crud.delete_group(db.session, group.name, requester)
    except HTTPRequestError as e:
        pass

    log().info(">>>>>>> ... cenario foi limpo apos execucao de caso de teste.")