Converting Existing Instances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As opposed to starting a new M-VO instance from scratch, it may be desirable to
convert the database for an existing (S-VO) Rucio instance into a M-VO instance
so that additional VOs can be added without disrupting the original VO or
needing to create a second instance. Conversely, one VO within a M-VO instance may
grow to the point where it needs its own dedicated instance, and so converting
data from M-VO to S-VO may also be desirable. These operations can be performed
using utility functions included with Rucio.

As mentioned above, in order to configure a M-VO instance of Rucio only the
config file needs to change. However for an existing instance any entries already
in the database will not be associated with a VO (or associated with their old
one if previously in M-VO mode). In order to change these, direct operations on
the database are required. These commands are generated using SQLAlchemy, and
can either be run directly on the database or printed out and run manually.

Practicalities
--------------

Before attempting to convert existing data, it is recommended that a backup of
the database is taken in case an issue arises. Furthermore, of the databases
supported by Rucio, only PostgreSQL has been tested on real data. Based on this
test (which was performed on a machine with 64GB memory and four Intel Xeon E5-2430 v2),
the tables with 2 columns that needed updating were converted at a rate of 5GB
of data per hour. However many tables do not need any changes, so the process
will likely be faster than this in practice. Another approach to speed up the
conversion is to skip the "history" tables, as these can be very large. Unlike
other tables these do not have foreign key constraints set, and so do not need
to be updated in order to use the database. While the history will be
inaccessible from the new VO, it will still exist in the database and could be
accessed using the ``super_root`` account if needed.

S-VO to M-VO
------------

Before starting, ensure that ``multi_vo`` is set to ``True`` in the config file.
The SQL commands needed to convert the database involve dropping foreign key
constraints that affect accounts/scopes, then altering the relevant columns,
before re-adding the constraints::

  $ python
  >>> from rucio.db.sqla.util import convert_to_mvo
  >>> convert_to_mvo(new_vo='abc', description='New VO for existing data', email='rucio@email.com',
                     commit_changes=False, skip_history=False)
  ALTER TABLE account_limits DROP CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK";
  ...
  UPDATE account_limits SET account=(split_part(account_limits.account, '@', 1) || CAST('@abc' AS CHAR(4))) WHERE split_part(account_limits.account, '@', 2) = '';
  ...
  ALTER TABLE account_limits ADD CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account);

In this example, no changes will be made to the database by running the script,
and so the SQL will need to be run manually. After running the commands, a 
``super_root`` account should be setup to allow administrative functions like
adding more VOs::

  $ python
  >>> from rucio.db.sqla.util import create_root_account
  >>> create_root_account()

Alternatively by setting ``commit_changes=True`` the script will attempt to
modify the database as it runs, however this requires the account used by the
Rucio instance to access the database to have sufficient permissions to alter
the tables. In this case, the ``super_root`` account is added as part of the
script. If there is an error during the conversion, then none of the changes
will be committed.

M-VO to S-VO
------------

Before starting, ensure that ``multi_vo`` is set to ``True`` in the config file
(this option can be removed after completing the conversion). The first stage
of the conversion is the same as before, dropping foreign key constraints and
renaming the entries that were associated with ``old_vo``::

  $ python
  >>> from rucio.db.sqla.util import convert_to_svo
  >>> convert_to_svo(olf_vo='abc', delete_vos=False,
                     commit_changes=False, skip_history=False)
  ALTER TABLE account_limits DROP CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK";
  ...
  UPDATE account_limits SET account=split_part(account_limits.account, '@', 1) WHERE split_part(account_limits.account, '@', 2) = 'abc';
  ...
  ALTER TABLE account_limits ADD CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account);

By default data associated with any other VOs is left in the database, but will be
inaccessible to Rucio users. By setting ``delete_vos=True``, these entries will
be deleted from the database completely::

  >>> convert_to_svo(olf_vo='abc', delete_vos=True,
                     commit_changes=False, skip_history=False)
  ...
  DELETE FROM account_limits WHERE split_part(account_limits.account, '@', 2) = 'xyz';
  ...
  DELETE FROM account_limits WHERE split_part(account_limits.account, '@', 2) = '123';
  ...

Once again, the commands can be run directly against the database using the
``commit_changes`` argument, and if this is not set then the ``super_root``
account should be manually deleted after running the SQL::

  $ python
  >>> from rucio.common.types import InternalAccount
  >>> from rucio.core.account import del_account
  >>> del_account(InternalAccount('super_root', vo='def'))