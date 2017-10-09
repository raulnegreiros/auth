from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship, backref
from sqlalchemy.orm import sessionmaker
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
import enum

import conf as dbconf
from flaskAlchemyInit import app, db

class PermissionEnum(enum.Enum):
    permit = 'permit'
    deny = 'deny'


#Model for the database tables
class Permission(db.Model):
    __tablename__ = 'permission'

    # fields that can be filled by user input
    fillable = ['path', 'method', 'permission']

    #serialise
    def as_dict(self):
        return {c.name: str( getattr(self, c.name) ) for c in self.__table__.columns}

    def safeDict(self):
        return self.as_dict()

    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(String, nullable=False)
    method = Column(String(30), nullable=False)
    permission =  Column( Enum(PermissionEnum), nullable=False)
    users = relationship('User', secondary='user_permission',cascade="delete")
    groups = relationship('Group', secondary='group_permission',cascade="delete")


class User(db.Model):
    __tablename__ = 'user'
    # fields that should not be returned to the user
    sensibleFields = [ 'hash', 'salt', 'secret', 'kongId', 'key' ]

    # fields that can be filled by user input
    fillable = ['name', 'username', 'service', 'email', 'profile']

    #serialise
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def safeDict(self):
        #don´t serialise sensible fields
        return {c.name: str( getattr(self, c.name) ) for c in self.__table__.columns \
            if c.name  not in self.sensibleFields }

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    username = Column(String(50), unique=True, nullable=False)
    service = Column(String, nullable=False)
    email = Column(String, nullable=False)
    profile  = Column(String, nullable=False)
    hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)

    #these fields are configured by kong after user creation
    secret = Column(String, nullable=False)
    key = Column(String, nullable=False)
    kongId = Column(String, nullable=False)

    #relationships
    permissions = relationship('Permission', secondary='user_permission', cascade="delete")
    groups = relationship('Group', secondary='user_group', cascade="delete")

class Group(db.Model):
    __tablename__ = 'group'

    fillable = ['name', 'description']

    #serialise
    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def safeDict(self):
        return self.as_dict()

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String, nullable=True)
    #role = Column(Boolean)
    permissions = relationship('Permission', secondary='group_permission', cascade="delete")
    users = relationship('User', secondary='user_group', cascade="delete")

class UserPermission(db.Model):
    __tablename__ = 'user_permission'
    permission_id = Column(Integer, ForeignKey('permission.id'), primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('user.id'), primary_key=True, index=True)

class GroupPermission(db.Model):
    __tablename__ = 'group_permission'
    permission_id = Column(Integer, ForeignKey('permission.id'), primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey('group.id'), primary_key=True, index=True)

class UserGroup(db.Model):
    __tablename__ = 'user_group'
    user_id = Column(Integer, ForeignKey('user.id'), primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey('group.id'), primary_key=True, index=True)
