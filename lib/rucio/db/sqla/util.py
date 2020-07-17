# Copyright 2015-2019 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Mario Lassnig <mario@lassnig.net>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function
from base64 import b64encode
from datetime import datetime
from hashlib import sha256
from os import urandom
from traceback import format_exc

from alembic import command
from alembic.config import Config

from six import PY3

from sqlalchemy import func
from sqlalchemy.engine import reflection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateSchema, MetaData, Table, DropTable, ForeignKeyConstraint, DropConstraint, AddConstraint
from sqlalchemy.sql import bindparam
from sqlalchemy.sql.expression import cast, select, text
from sqlalchemy.types import CHAR

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount
from rucio.core.account import del_account
from rucio.core.account_counter import create_counters_for_new_account
from rucio.core.vo import list_vos
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import AccountStatus, AccountType, IdentityType


def build_database(echo=True, tests=False):
    """ Applies the schema to the database. Run this command once to build the database. """
    engine = session.get_engine(echo=echo)

    schema = config_get('database', 'schema', raise_exception=False)
    if schema:
        print('Schema set in config, trying to create schema:', schema)
        try:
            engine.execute(CreateSchema(schema))
        except Exception as e:
            print('Cannot create schema, please validate manually if schema creation is needed, continuing:', e)

    models.register_models(engine)

    # Put the database under version control
    alembic_cfg = Config(config_get('alembic', 'cfg'))
    command.stamp(alembic_cfg, "head")


def dump_schema():
    """ Creates a schema dump to a specific database. """
    engine = session.get_dump_engine()
    models.register_models(engine)


def destroy_database(echo=True):
    """ Removes the schema from the database. Only useful for test cases or malicious intents. """
    engine = session.get_engine(echo=echo)

    try:
        models.unregister_models(engine)
    except Exception as e:
        print('Cannot destroy schema -- assuming already gone, continuing:', e)


def drop_everything(echo=True):
    """ Pre-gather all named constraints and table names, and drop everything. This is better than using metadata.reflect();
        metadata.drop_all() as it handles cyclical constraints between tables.
        Ref. http://www.sqlalchemy.org/trac/wiki/UsageRecipes/DropEverything
    """
    engine = session.get_engine(echo=echo)
    conn = engine.connect()

    # the transaction only applies if the DB supports
    # transactional DDL, i.e. Postgresql, MS SQL Server
    trans = conn.begin()

    inspector = reflection.Inspector.from_engine(engine)

    # gather all data first before dropping anything.
    # some DBs lock after things have been dropped in
    # a transaction.
    metadata = MetaData()

    tbs = []
    all_fks = []

    for table_name in inspector.get_table_names():
        fks = []
        for fk in inspector.get_foreign_keys(table_name):
            if not fk['name']:
                continue
            fks.append(ForeignKeyConstraint((), (), name=fk['name']))
        t = Table(table_name, metadata, *fks)
        tbs.append(t)
        all_fks.extend(fks)

    for fkc in all_fks:
        try:
            print(str(DropConstraint(fkc)) + ';')
            conn.execute(DropConstraint(fkc))
        except:
            print(format_exc())

    for table in tbs:
        try:
            print(str(DropTable(table)).strip() + ';')
            conn.execute(DropTable(table))
        except:
            print(format_exc())

    trans.commit()


def create_base_vo():
    """ Creates the base VO """

    s = session.get_session()

    vo = models.VO(vo='def', description='Default base VO', email='N/A')

    s.add_all([vo])
    s.commit()


def create_root_account():
    """ Inserts the default root account to an existing database. Make sure to change the default password later. """

    multi_vo = bool(config_get('common', 'multi_vo', False, False))

    up_id = 'ddmlab'
    up_pwd = 'secret'
    up_email = 'ph-adp-ddm-lab@cern.ch'
    x509_id = '/C=CH/ST=Geneva/O=CERN/OU=PH-ADP-CO/CN=DDMLAB Client Certificate/emailAddress=ph-adp-ddm-lab@cern.ch'
    x509_email = 'ph-adp-ddm-lab@cern.ch'
    gss_id = 'ddmlab@CERN.CH'
    gss_email = 'ph-adp-ddm-lab@cern.ch'
    ssh_id = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq5LySllrQFpPL614sulXQ7wnIr1aGhGtl8b+HCB/'\
             '0FhMSMTHwSjX78UbfqEorZV16rXrWPgUpvcbp2hqctw6eCbxwqcgu3uGWaeS5A0iWRw7oXUh6ydn'\
             'Vy89zGzX1FJFFDZ+AgiZ3ytp55tg1bjqqhK1OSC0pJxdNe878TRVVo5MLI0S/rZY2UovCSGFaQG2'\
             'iLj14wz/YqI7NFMUuJFR4e6xmNsOP7fCZ4bGMsmnhR0GmY0dWYTupNiP5WdYXAfKExlnvFLTlDI5'\
             'Mgh4Z11NraQ8pv4YE1woolYpqOc/IMMBBXFniTT4tC7cgikxWb9ZmFe+r4t6yCDpX4IL8L5GOQ== ddmlab'
    ssh_email = 'ph-adp-ddm-lab@cern.ch'

    try:
        up_id = config_get('bootstrap', 'userpass_identity')
        up_pwd = config_get('bootstrap', 'userpass_pwd')
        up_email = config_get('bootstrap', 'userpass_email')
        x509_id = config_get('bootstrap', 'x509_identity')
        x509_email = config_get('bootstrap', 'x509_email')
        gss_id = config_get('bootstrap', 'gss_identity')
        gss_email = config_get('bootstrap', 'gss_email')
        ssh_id = config_get('bootstrap', 'ssh_identity')
        ssh_email = config_get('bootstrap', 'ssh_email')
    except:
        pass
        # print 'Config values are missing (check rucio.cfg{.template}). Using hardcoded defaults.'

    s = session.get_session()

    if multi_vo:
        access = 'super_root'
    else:
        access = 'root'

    account = models.Account(account=InternalAccount(access, 'def'), account_type=AccountType.SERVICE, status=AccountStatus.ACTIVE)

    salt = urandom(255)
    if PY3:
        decoded_salt = b64encode(salt).decode()
        salted_password = ('%s%s' % (decoded_salt, up_pwd)).encode()
    else:
        salted_password = '%s%s' % (salt, str(up_pwd))
    hashed_password = sha256(salted_password).hexdigest()
    identity1 = models.Identity(identity=up_id, identity_type=IdentityType.USERPASS, password=hashed_password, salt=salt, email=up_email)
    iaa1 = models.IdentityAccountAssociation(identity=identity1.identity, identity_type=identity1.identity_type, account=account.account, is_default=True)

    # X509 authentication
    identity2 = models.Identity(identity=x509_id, identity_type=IdentityType.X509, email=x509_email)
    iaa2 = models.IdentityAccountAssociation(identity=identity2.identity, identity_type=identity2.identity_type, account=account.account, is_default=True)

    # GSS authentication
    identity3 = models.Identity(identity=gss_id, identity_type=IdentityType.GSS, email=gss_email)
    iaa3 = models.IdentityAccountAssociation(identity=identity3.identity, identity_type=identity3.identity_type, account=account.account, is_default=True)

    # SSH authentication
    identity4 = models.Identity(identity=ssh_id, identity_type=IdentityType.SSH, email=ssh_email)
    iaa4 = models.IdentityAccountAssociation(identity=identity4.identity, identity_type=identity4.identity_type, account=account.account, is_default=True)

    # Apply
    for identity in [identity1, identity2, identity3, identity4]:
        try:
            s.add(identity)
            s.commit()
        except IntegrityError:
            # Identities may already be in the DB when running multi-VO conversion
            s.rollback()
            pass
    s.add(account)
    s.commit()
    s.add_all([iaa1, iaa2, iaa3, iaa4])
    s.commit()

    # Account counters
    create_counters_for_new_account(account=account.account, session=s)
    s.close()


def get_db_time():
    """ Gives the utc time on the db. """
    s = session.get_session()
    try:
        storage_date_format = None
        if s.bind.dialect.name == 'oracle':
            query = select([text("sys_extract_utc(systimestamp)")])
        elif s.bind.dialect.name == 'mysql':
            query = select([text("utc_timestamp()")])
        elif s.bind.dialect.name == 'sqlite':
            query = select([text("datetime('now', 'utc')")])
            storage_date_format = '%Y-%m-%d  %H:%M:%S'
        else:
            query = select([func.current_date()])

        for now, in s.execute(query):
            if storage_date_format:
                return datetime.strptime(now, storage_date_format)
            return now

    finally:
        s.remove()


def get_count(q):
    """
    Fast way to get count in SQLAlchemy
    Source: https://gist.github.com/hest/8798884
    Some limits, see a more thorough version above
    """

    count_q = q.statement.with_only_columns([func.count()]).order_by(None)
    count = q.session.execute(count_q).scalar()
    return count


def split_vo(dialect, column, return_vo=False):
    """
    Utility script for extracting the name and VO from InternalAccount/Scope entries in the DB.

    :param dialect:   The dialct of the DB.
    :param column:    The column to perform the operation on.
    :param return_vo: If True, return the 3 characters after the '@' symbol, else return everything before it.
    """
    if dialect == 'postgresql':
        if return_vo:
            return func.split_part(column, bindparam('split_character'), bindparam('int_2'))
        else:
            return func.split_part(column, bindparam('split_character'), bindparam('int_1'))
    else:
        # Dialects other than postgresql haven't been tested
        i = func.INSTR(column, bindparam('split_character'))
        if return_vo:
            return func.SUBSTR(column, i + 1)
        else:
            return func.SUBSTR(column, bindparam('int_1'), i - 1)


def rename_vo(old_vo, new_vo, insert_new_vo=False, description=None, email=None, commit_changes=False, echo=True):
    """
    Updates rows so that entries associated with `old_vo` are now associated with `new_vo` as part of multi-VO migration.

    :param old_vo:         The 3 character string for the current VO (for a single-VO instance this will be 'def').
    :param new_vo:         The 3 character string for the new VO.
    :param insert_new_vo:  If True then an entry for `new_vo` is created in the database.
    :param description:    Full description of the new VO, unused if `insert_new_vo` is False.
    :param email:          Admin email for the new VO, unused if `insert_new_vo` is False.
    :param commit_changes: If True then changes are made against the database directly.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    """
    success = True
    engine = session.get_engine(echo=echo)
    conn = engine.connect()
    trans = conn.begin()
    inspector = reflection.Inspector.from_engine(engine)
    metadata = MetaData(bind=conn, reflect=True)
    dialect = engine.dialect.name

    # Gather all the columns that need updating and all relevant foreign key constraints
    all_fks = []
    tables_and_columns = []
    for table_name in inspector.get_table_names():
        fks = []
        table = Table(table_name, metadata)
        for column in table.c:
            if 'scope' in column.name or 'account' == column.name:
                tables_and_columns.append((table, column))
        for fk in inspector.get_foreign_keys(table_name):
            if not fk['name']:
                continue
            if 'scope' in fk['referred_columns'] or 'account' in fk['referred_columns']:
                fks.append(ForeignKeyConstraint(fk['constrained_columns'], [fk['referred_table'] + '.' + r for r in fk['referred_columns']],
                                                name=fk['name'], table=table, **fk['options']))
        all_fks.extend(fks)

    try:
        bound_params = {'old_vo': old_vo,
                        'new_vo': new_vo,
                        'old_vo_suffix': '' if old_vo == 'def' else old_vo,
                        'new_vo_suffix': '' if new_vo == 'def' else '@%s' % new_vo,
                        'split_character': '@',
                        'int_1': 1,
                        'int_2': 2,
                        'description': description,
                        'email': email,
                        'datetime': datetime.utcnow()}

        bound_params_text = {}
        for key in bound_params:
            if type(bound_params[key]) is int:
                bound_params_text[key] = bound_params[key]
            else:
                bound_params_text[key] = "'%s'" % bound_params[key]

        if insert_new_vo:
            table = Table('vos', metadata)
            insert_command = table.insert().values(vo=bindparam('new_vo'),
                                                   description=bindparam('description'),
                                                   email=bindparam('email'),
                                                   updated_at=bindparam('datetime'),
                                                   created_at=bindparam('datetime'))
            print(str(insert_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(insert_command, bound_params)

        # Drop all FKCs affecting InternalAccounts/Scopes
        for fk in all_fks:
            print(str(DropConstraint(fk)) + ';')
            if commit_changes:
                conn.execute(DropConstraint(fk))

        # Update columns
        for table, column in tables_and_columns:
            update_command = table.update().where(split_vo(dialect, column, return_vo=True) == bindparam('old_vo_suffix'))

            if new_vo == 'def':
                update_command = update_command.values({column.name: split_vo(dialect, column)})
            else:
                update_command = update_command.values({column.name: split_vo(dialect, column) + cast(bindparam('new_vo_suffix'), CHAR(4))})

            print(str(update_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(update_command, bound_params)

        table = Table('rses', metadata)
        update_command = table.update().where(table.c.vo == bindparam('old_vo')).values(vo=bindparam('new_vo'))
        print(str(update_command) % bound_params_text + ';')
        if commit_changes:
            conn.execute(update_command, bound_params)

        # Re-add the FKCs we dropped
        for fkc in all_fks:
            print(str(AddConstraint(fkc)) + ';')
            if commit_changes:
                conn.execute(AddConstraint(fkc))
    except:
        success = False
        print(format_exc())
        print('Exception occured, changes not committed to DB.')

    if commit_changes and success:
        trans.commit()
    trans.close()


def remove_vo(vo, commit_changes=False, echo=True):
    """
    Deletes rows associated with `vo` as part of multi-VO migration.

    :param vo:             The 3 character string for the VO being removed from the DB.
    :param commit_changes: If True then changes are made against the database directly.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    """
    success = True
    engine = session.get_engine(echo=echo)
    conn = engine.connect()
    trans = conn.begin()
    inspector = reflection.Inspector.from_engine(engine)
    metadata = MetaData(bind=conn, reflect=True)
    dialect = engine.dialect.name

    # Gather all the columns that need deleting and all relevant foreign key constraints
    all_fks = []
    tables_and_columns = []
    tables_and_columns_rse = []
    for table_name in inspector.get_table_names():
        fks = []
        table = Table(table_name, metadata)
        for column in table.c:
            if 'scope' in column.name or 'account' == column.name:
                tables_and_columns.append((table, column))
            if 'rse_id' in column.name:
                tables_and_columns_rse.append((table, column))
        for fk in inspector.get_foreign_keys(table_name):
            if not fk['name']:
                continue
            if 'scope' in fk['referred_columns'] or 'account' in fk['referred_columns'] or ('rse' in fk['referred_table'] and 'id' in fk['referred_columns']):
                fks.append(ForeignKeyConstraint(fk['constrained_columns'], [fk['referred_table'] + '.' + r for r in fk['referred_columns']],
                                                name=fk['name'], table=table, **fk['options']))
        all_fks.extend(fks)

    try:
        bound_params = {'vo': vo,
                        'vo_suffix': '' if vo == 'def' else vo,
                        'split_character': '@',
                        'int_1': 1,
                        'int_2': 2}

        bound_params_text = {}
        for key in bound_params:
            if type(bound_params[key]) is int:
                bound_params_text[key] = bound_params[key]
            else:
                bound_params_text[key] = "'%s'" % bound_params[key]

        # Drop all FKCs affecting InternalAccounts/Scopes or RSE IDs
        for fk in all_fks:
            print(str(DropConstraint(fk)) + ';')
            if commit_changes:
                conn.execute(DropConstraint(fk))

        # Delete rows
        for table, column in tables_and_columns:
            delete_command = table.delete().where(split_vo(dialect, column, return_vo=True) == bindparam('vo_suffix'))
            print(str(delete_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(delete_command, bound_params)

        rse_table = Table('rses', metadata)
        for table, column in tables_and_columns_rse:
            delete_command = table.delete().where(column == rse_table.c.id).where(rse_table.c.vo == bindparam('vo'))
            print(str(delete_command) % bound_params_text + ';')
            if commit_changes:
                conn.execute(delete_command, bound_params)

        delete_command = rse_table.delete().where(rse_table.c.vo == bindparam('vo'))
        print(str(delete_command) % bound_params_text + ';')
        if commit_changes:
            conn.execute(delete_command, bound_params)

        table = Table('vos', metadata)
        delete_command = table.delete().where(table.c.vo == bindparam('vo'))
        print(str(delete_command) % bound_params_text + ';')
        if commit_changes:
            conn.execute(delete_command, bound_params)

        # Re-add the FKCs we dropped
        for fkc in all_fks:
            print(str(AddConstraint(fkc)) + ';')
            if commit_changes:
                conn.execute(AddConstraint(fkc))
    except:
        success = False
        print(format_exc())
        print('Exception occured, changes not committed to DB.')

    if commit_changes and success:
        trans.commit()
    trans.close()


def convert_to_mvo(new_vo, description, email, commit_changes=False, echo=True):
    """
    Converts a single-VO database to a multi-VO one with the specified VO details.

    :param new_vo:         The 3 character string for the new VO.
    :param description:    Full description of the new VO.
    :param email:          Admin email for the new VO.
    :param commit_changes: If True then changes are made against the database directly, and a super_root account is created.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    """
    if not config_get_bool('common', 'multi_vo', False, False):
        print('Multi-VO mode is not enabled in the config file, aborting conversion.')
        return

    s = session.get_session()
    vos = [vo['vo'] for vo in list_vos(session=s)]
    if new_vo not in vos:
        insert_new_vo = True
    else:
        insert_new_vo = False

    rename_vo('def', new_vo, insert_new_vo=insert_new_vo, description=description, email=email, commit_changes=commit_changes, echo=echo)
    if commit_changes:
        create_root_account()
    s.close()


def convert_to_svo(old_vo, delete_vos=False, commit_changes=False, echo=True):
    """
    Converts a multi-VO database to a single-VO one by renaming the given VO and (optionally) deleting entries for other VOs and the super_root.
    Intended to be run on a copy of the original database that contains several VOs.

    :param old_vo:         The 3 character string for the old VO.
    :param delete_vos:     If True then all entries associated with a VO other than `old_vo` will be deleted.
    :param commit_changes: If True then changes are made against the database directly and the old super_root account will be (soft) deleted.
                           If False, then nothing is commited and the commands needed are dumped to be run later.
    """
    if not config_get_bool('common', 'multi_vo', False, False):
        print('Multi-VO mode is not enabled in the config file, aborting conversion.')
        return

    rename_vo(old_vo, 'def', commit_changes=commit_changes, echo=echo)
    s = session.get_session()
    if delete_vos:
        for vo in list_vos(session=s):
            if vo['vo'] != 'def':
                remove_vo(vo['vo'], commit_changes=commit_changes, echo=echo)
        if commit_changes:
            del_account(InternalAccount('super_root', vo='def'), session=s)
    s.close()
