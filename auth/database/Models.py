from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, Boolean, DateTime
from sqlalchemy import ForeignKey, Enum, PrimaryKeyConstraint
from sqlalchemy.orm import relationship, backref
from sqlalchemy.orm import sessionmaker
from flask_sqlalchemy import SQLAlchemy
import enum
import datetime

import conf as dbconf
from .inputConf import UserLimits, PermissionLimits, GroupLimits
from .flaskAlchemyInit import app, db
from .materialized_view_factory import create_mat_view
from .materialized_view_factory import refresh_mat_view


class PermissionEnum(enum.Enum):
    permit = 'permit'
    deny = 'deny'
    notApplicable = 'notApplicable'


# Model for the database tables
class Permission(db.Model):
    __tablename__ = 'permission'

    # fields that can be filled by user input
    fillable = ['name', 'path', 'method', 'permission']

    # serialize
    def as_dict(self):
        tmpDict = {
                    c.name: getattr(self, c.name)
                    for c in self.__table__.columns
                  }
        if type(tmpDict['permission']) != str:
            tmpDict['permission'] = tmpDict['permission'].value
        return tmpDict

    def safeDict(self):
        return self.as_dict()

    def getByNameOrID(nameOrId):
        try:
            return db.session.query(Permission). \
                        filter_by(id=int(nameOrId)).one()
        except ValueError:
            return db.session.query(Permission).filter_by(name=nameOrId).one()

    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String(PermissionLimits.path), nullable=False)
    name = Column(String(PermissionLimits.name), nullable=False,
                  unique=True, index=True)
    method = Column(String(PermissionLimits.method), nullable=False)
    permission = Column(Enum(PermissionEnum), nullable=False)

    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(Integer, nullable=False)

    users = relationship('User', secondary='user_permission')
    groups = relationship('Group',
                          secondary='group_permission')


class User(db.Model):
    __tablename__ = 'user'
    # Fields that should not be returned to the user
    sensibleFields = ['hash', 'salt', 'secret', 'kongId', 'key']

    # Fields that can be filled by user input
    fillable = ['name', 'username', 'service', 'email', 'profile']

    # serialize class as python dictionary
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def safeDict(self):
        # serialize, but drop sensible fields
        return {
                c.name: str(getattr(self, c.name))
                for c in self.__table__.columns
                if c.name not in self.sensibleFields
            }

    def getByNameOrID(nameOrId):
        try:
            return db.session.query(User).filter_by(id=int(nameOrId)).one()
        except ValueError:
            return db.session.query(User).filter_by(username=nameOrId).one()

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(UserLimits.name), nullable=False)
    username = Column(String(UserLimits.username), unique=True, nullable=False)
    service = Column(String(UserLimits.service), nullable=False)
    email = Column(String(UserLimits.email), nullable=False, unique=True)
    profile = Column(String(UserLimits.profile), nullable=False)
    hash = Column(String, nullable=True)
    salt = Column(String, nullable=True)

    # These fields are configured by kong after user creation
    secret = Column(String, nullable=False)
    key = Column(String, nullable=False)
    kongId = Column(String, nullable=False)

    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(Integer, nullable=False)

    # Table Relationships
    permissions = relationship('Permission',
                               secondary='user_permission')
    groups = relationship('Group', secondary='user_group')


class Group(db.Model):
    __tablename__ = 'group'

    fillable = ['name', 'description']

    # serialize class as python dictionary
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def safeDict(self):
        return self.as_dict()

    def getByNameOrID(nameOrId):
        try:
            return db.session.query(Group).filter_by(id=int(nameOrId)).one()
        except ValueError:
            return db.session.query(Group).filter_by(name=nameOrId).one()

    def safeDict(self):
        return self.as_dict()

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(GroupLimits.name), unique=True, nullable=False)
    description = Column(String(GroupLimits.description), nullable=True)

    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    created_by = Column(Integer, nullable=False)

    # Table ralationships
    permissions = relationship('Permission',
                               secondary='group_permission')
    users = relationship('User', secondary='user_group')


class UserPermission(db.Model):
    __tablename__ = 'user_permission'
    permission_id = Column(Integer,
                           ForeignKey('permission.id'),
                           primary_key=True, index=True)
    user_id = Column(Integer,
                     ForeignKey('user.id'),
                     primary_key=True, index=True)


class GroupPermission(db.Model):
    __tablename__ = 'group_permission'
    permission_id = Column(Integer,
                           ForeignKey('permission.id'),
                           primary_key=True, index=True)
    group_id = Column(Integer,
                      ForeignKey('group.id'),
                      primary_key=True, index=True)


class UserGroup(db.Model):
    __tablename__ = 'user_group'
    user_id = Column(Integer,
                     ForeignKey('user.id'),
                     primary_key=True, index=True)
    group_id = Column(Integer,
                      ForeignKey('group.id'),
                      primary_key=True, index=True)


# table to keep the temporary password reset links
class PasswordRequest(db.Model):
    __tablename__ = 'passwd_request'

    user_id = Column(Integer, primary_key=True, autoincrement=False)
    link = Column(String, nullable=False, index=True)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)


class MVUserPermission(db.Model):
    selectClause = db.select([UserPermission.user_id,
                             Permission.id,
                             Permission.path,
                             Permission.method,
                             Permission.permission, ]
                             ).select_from(db.join(UserPermission, Permission))

    __table__ = create_mat_view('mv_user_permission',
                                selectClause)

    # SQLAlchemy require a unique primary key to map ORM objects
    __table_args__ = (
        PrimaryKeyConstraint('user_id', 'id'),
        {},
    )

    def refresh(concurrently=False):
        refresh_mat_view('mv_user_permission', concurrently)


db.Index('mv_user_permission_user_idx', MVUserPermission.user_id, unique=False)


class MVGroupPermission(db.Model):
    selectClause = db.select([GroupPermission.group_id,
                             Permission.id,
                             Permission.path,
                             Permission.method,
                             Permission.permission, ]
                             ).select_from(db.join(GroupPermission,
                                                   Permission))

    __table__ = create_mat_view('mv_group_permission',
                                selectClause)

    # SQLAlchemy require a unique primary key to map ORM objects
    __table_args__ = (
        PrimaryKeyConstraint('group_id', 'id'),
        {},
    )

    def refresh(concurrently=False):
        refresh_mat_view('mv_group_permission', concurrently)


db.Index('mv_group_permission_user_idx',
         MVGroupPermission.group_id, unique=False)
