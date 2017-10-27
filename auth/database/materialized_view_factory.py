# based on Jeff Widman tutorial. Avalible at:
# http://www.jeffwidman.com/blog/847/using-sqlalchemy-to-create-and-manage-postgresql-materialized-views/
# materialized_view_factory.py

from sqlalchemy.ext import compiler
from sqlalchemy.schema import DDLElement

from .flaskAlchemyInit import app, db


class CreateMaterializedView(DDLElement):
    def __init__(self, name, selectable):
        self.name = name
        self.selectable = selectable


@compiler.compiles(CreateMaterializedView)
def compile(element, compiler, **kw):
    # Could use "CREATE OR REPLACE MATERIALIZED VIEW..."
    # but I'd rather have noisy errors
    return 'CREATE MATERIALIZED VIEW %s AS %s' % (
         element.name,
         compiler.sql_compiler.process(element.selectable, literal_binds=True))


def create_mat_view(name, selectable, metadata=db.metadata):
    _mt = db.MetaData()  # temp metadata just for initial Table object creation

    # the actual mat view class is bound to db.metadata
    t = db.Table(name, _mt)
    for c in selectable.c:
        t.append_column(db.Column(c.name, c.type, primary_key=c.primary_key))

    db.event.listen(
        metadata, 'after_create',
        CreateMaterializedView(name, selectable)
    )

    @db.event.listens_for(metadata, 'after_create')
    def create_indexes(target, connection, **kw):
        for idx in t.indexes:
            idx.create(connection)

    db.event.listen(
        metadata, 'before_drop',
        db.DDL('DROP MATERIALIZED VIEW IF EXISTS ' + name)
    )
    return t


def refresh_mat_view(name, concurrently):
    # since session.execute() bypasses autoflush, must manually flush in order
    # to include newly-created/modified objects in the refresh
    db.session.flush()
    _con = 'CONCURRENTLY ' if concurrently else ''
    db.session.execute('REFRESH MATERIALIZED VIEW ' + _con + name)


class MaterializedView(db.Model):
    __abstract__ = True

    @classmethod
    def refresh(cls, concurrently=True):
        '''Refreshes the current materialized view'''
        refresh_mat_view(cls.__table__.fullname, concurrently)
