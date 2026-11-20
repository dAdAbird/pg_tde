use strict;
use warnings FATAL => 'all';
use pgtde;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $stdout;

my $keydir = PostgreSQL::Test::Utils::tempdir;

my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf(
	'postgresql.conf', q{
checkpoint_timeout = 1h
shared_preload_libraries = 'pg_tde'
});
$node->start;

$node->safe_psql(
	'postgres', qq(
	CREATE EXTENSION pg_tde;

	SELECT pg_tde_add_global_key_provider_file('global_keyring', '$keydir/global.keys');
	SELECT pg_tde_create_key_using_global_key_provider('wal_encryption_key', 'global_keyring');
	SELECT pg_tde_set_server_key_using_global_key_provider('wal_encryption_key', 'global_keyring');

	SELECT pg_tde_add_database_key_provider_file('db_keyring', '$keydir/db.keys');
	SELECT pg_tde_create_key_using_database_key_provider('db_key', 'db_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('db_key', 'db_keyring');

	CREATE TABLE test_enc (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_enc (x) VALUES (1), (2);

	CREATE TABLE test_plain (x int PRIMARY KEY) USING heap;
	INSERT INTO test_plain (x) VALUES (3), (4);

	ALTER SYSTEM SET pg_tde.wal_encrypt = 'on';
));

$node->kill9;

# check that we can do a crash recovery of the pg_tde setup
PGTDE::poll_start($node);

# rotate wal key and insert
$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_create_key_using_global_key_provider('wal_encryption_key_1', 'global_keyring');
	SELECT pg_tde_set_server_key_using_global_key_provider('wal_encryption_key_1', 'global_keyring');
	SELECT pg_tde_create_key_using_database_key_provider('db_key_1', 'db_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('db_key_1', 'db_keyring');

	INSERT INTO test_enc (x) VALUES (3), (4);
));

$node->kill9;

# check that pg_tde_save_principal_key_redo hasn't destroyed a WAL key created during the server start
PGTDE::poll_start($node);

# rotate wal key and insert
$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_create_key_using_global_key_provider('wal_encryption_key_2', 'global_keyring');
	SELECT pg_tde_set_server_key_using_global_key_provider('wal_encryption_key_2', 'global_keyring');
	SELECT pg_tde_create_key_using_database_key_provider('db_key_2', 'db_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('db_key_2', 'db_keyring');

	INSERT INTO test_enc (x) VALUES (5), (6);
));

$node->kill9;

# check that the key rotation hasn't destroyed a WAL key created during the server start
PGTDE::poll_start($node);

$stdout = $node->safe_psql('postgres', 'TABLE test_enc;');
is($stdout, "1\n2\n3\n4\n5\n6", 'can still read data');

$node->safe_psql('postgres',
	'CREATE TABLE test_enc2 (x int PRIMARY KEY) USING tde_heap;');

$node->kill9;

# check redo of the smgr internal key creation when the key is on disk
PGTDE::poll_start($node);

$node->safe_psql('postgres', 'INSERT INTO test_enc (x) VALUES (7), (8);');

$node->kill9;

$node->append_conf(
	'postgresql.conf', q{
pg_tde.cipher = 'aes_256'
});

# check redo when cipher was changed after the server crash
PGTDE::poll_start($node);

$stdout = $node->safe_psql('postgres', 'TABLE test_enc;');
is($stdout, "1\n2\n3\n4\n5\n6\n7\n8", 'can still read data');

# Use an unlogged sequence owned by the encrypted table to ensure the sequence
# is also encrypted. This is to verify that WAL replay doesn't overwrite the key
# of an unlogged object's init fork, which would cause it to be unrecoverable
# after crash recovery. We cannot use a regular relation in this test, because
# their init forks is a 0 byte file so the wrong key being used isn't an issue
# for them.
$node->safe_psql(
	'postgres', qq(
	CREATE UNLOGGED SEQUENCE seq_unlogged OWNED BY test_enc.x;
	SELECT nextval('seq_unlogged');
	SELECT nextval('seq_unlogged');
));

# Sanity check to see that we are testing somthing useful
$stdout =
  $node->safe_psql('postgres', "SELECT pg_tde_is_encrypted('seq_unlogged');");
is($stdout, 't', 'sequence is encrypted');

$node->kill9;

PGTDE::poll_start($node);

$stdout = $node->safe_psql('postgres', "SELECT nextval('seq_unlogged');");
is($stdout, '1', 'sequence has been reset and can be used');

# A database starts using the default key when its first relation key is
# created, rather than with a call of an SQL function. Check that redo of the
# preceding key deletion doesn't leave the relation key without the principal
# key. The checkpoint is needed as redo of the extension creation removes all
# the key files of the database.
$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_create_key_using_global_key_provider('default_key', 'global_keyring');
	SELECT pg_tde_set_default_key_using_global_key_provider('default_key', 'global_keyring');
	CREATE DATABASE other;
));
$node->safe_psql(
	'other', qq(
	CREATE EXTENSION pg_tde;

	SELECT pg_tde_add_database_key_provider_file('other_keyring', '$keydir/other.keys');
	SELECT pg_tde_create_key_using_database_key_provider('other_key', 'other_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('other_key', 'other_keyring');
	CHECKPOINT;
	SELECT pg_tde_delete_key();

	CREATE TABLE test_default (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_default (x) VALUES (1), (2);
));

$node->kill9;

PGTDE::poll_start($node);

$stdout = $node->safe_psql('other', 'TABLE test_default;');
is($stdout, "1\n2", 'can read data encrypted with the default key');

$stdout = $node->safe_psql('other', 'SELECT key_name FROM pg_tde_key_info();');
is($stdout, 'default_key', 'database still uses the default key');

# The key files and the key providers may be newer than the WAL records being
# replayed. Check redo of a key rotation when the key provider of the new key
# has been deleted since, and when the principal key has been deleted since.
$node->safe_psql('postgres', 'CREATE DATABASE empty;');
$node->safe_psql(
	'empty', qq(
	CREATE EXTENSION pg_tde;

	SELECT pg_tde_add_database_key_provider_file('empty_keyring', '$keydir/empty.keys');
	SELECT pg_tde_create_key_using_database_key_provider('empty_key', 'empty_keyring');
	SELECT pg_tde_create_key_using_database_key_provider('empty_key_1', 'empty_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('empty_key', 'empty_keyring');
));
$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_add_database_key_provider_file('tmp_keyring', '$keydir/tmp.keys');
	SELECT pg_tde_create_key_using_database_key_provider('tmp_key', 'tmp_keyring');
	SELECT pg_tde_create_key_using_database_key_provider('db_key_3', 'db_keyring');
	CHECKPOINT;

	SELECT pg_tde_set_key_using_database_key_provider('tmp_key', 'tmp_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('db_key_3', 'db_keyring');
	SELECT pg_tde_delete_database_key_provider('tmp_keyring');
));
$node->safe_psql(
	'empty', qq(
	SELECT pg_tde_set_key_using_database_key_provider('empty_key_1', 'empty_keyring');
	SELECT pg_tde_delete_key();
));

$node->kill9;

PGTDE::poll_start($node);

$stdout = $node->safe_psql('postgres', 'TABLE test_enc;');
is($stdout, "1\n2\n3\n4\n5\n6\n7\n8",
	'can read data after redo of the key rotations');

$stdout =
  $node->safe_psql('postgres', 'SELECT key_name FROM pg_tde_key_info();');
is($stdout, 'db_key_3', 'database uses the key it was rotated to last');

$stdout =
  $node->safe_psql('empty', 'SELECT key_name FROM pg_tde_key_info();');
is($stdout, '', 'database still has no principal key');

# Check that redo leaves alone the principal key that was set later than the
# record being replayed. Otherwise, the rotation moves the relation key to the
# old principal key and the deletion leaves it without any.
$node->safe_psql(
	'empty', qq(
	SELECT pg_tde_create_key_using_database_key_provider('empty_key_2', 'empty_keyring');
	SELECT pg_tde_set_key_using_database_key_provider('empty_key', 'empty_keyring');
	CHECKPOINT;

	SELECT pg_tde_set_key_using_database_key_provider('empty_key_1', 'empty_keyring');
	SELECT pg_tde_delete_key();
	SELECT pg_tde_set_key_using_database_key_provider('empty_key_2', 'empty_keyring');

	CREATE TABLE test_newer (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_newer (x) VALUES (1), (2);
));

$node->kill9;

PGTDE::poll_start($node);

$stdout = $node->safe_psql('empty', 'TABLE test_newer;');
is($stdout, "1\n2",
	'can read data after redo of the changes preceding the current key');

$stdout =
  $node->safe_psql('empty', 'SELECT key_name FROM pg_tde_key_info();');
is($stdout, 'empty_key_2', 'database uses the key that was set last');

# The start location of a WAL key is set by the first WAL write that uses it.
# After a clean restart, that is the write of the record of the server key
# rotation, which happens while the WAL keys file is being replaced with its
# re-encrypted copy. Check that the location gets into the new file. Otherwise,
# the WAL written with this key can't be read after the crash.
$node->safe_psql('postgres',
	"SELECT pg_tde_create_key_using_global_key_provider('wal_encryption_key_3', 'global_keyring');"
);
$node->restart;

$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_set_server_key_using_global_key_provider('wal_encryption_key_3', 'global_keyring');
	INSERT INTO test_enc (x) VALUES (9), (10);
));

$node->kill9;

PGTDE::poll_start($node);

$stdout = $node->safe_psql('postgres', 'TABLE test_enc;');
is($stdout, "1\n2\n3\n4\n5\n6\n7\n8\n9\n10",
	'can read data after the server key rotation right after the restart');

$stdout = $node->safe_psql('postgres',
	'SELECT key_name FROM pg_tde_server_key_info();');
is($stdout, 'wal_encryption_key_3', 'server key is the one it was rotated to');

$node->stop;

done_testing();
