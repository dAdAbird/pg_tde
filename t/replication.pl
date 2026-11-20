use strict;
use warnings FATAL => 'all';
use pgtde;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $stdout;

my $keydir = PostgreSQL::Test::Utils::tempdir;

my $primary = PostgreSQL::Test::Cluster->new('primary');
$primary->init(allows_streaming => 1);
$primary->append_conf(
	'postgresql.conf', q{
checkpoint_timeout = 1h
shared_preload_libraries = 'pg_tde'
});
$primary->start;

$primary->backup('backup');
my $replica = PostgreSQL::Test::Cluster->new('replica');
$replica->init_from_backup($primary, 'backup', has_streaming => 1);
$replica->set_standby_mode();
$replica->start;

$primary->safe_psql(
	'postgres', qq(
	CREATE EXTENSION pg_tde;
	SELECT pg_tde_add_database_key_provider_file('file-vault', '$keydir/db.keys');
	SELECT pg_tde_create_key_using_database_key_provider('test-key', 'file-vault');
	SELECT pg_tde_set_key_using_database_key_provider('test-key', 'file-vault');

	CREATE TABLE test_enc (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_enc (x) VALUES (1), (2);

	CREATE TABLE test_plain (x int PRIMARY KEY) USING heap;
	INSERT INTO test_plain (x) VALUES (3), (4);
));

$primary->wait_for_catchup('replica');

$stdout =
  $replica->safe_psql('postgres', "SELECT pg_tde_is_encrypted('test_enc');");
is($stdout, 't', 'test_enc is encrypted on the replica');
$stdout = $replica->safe_psql('postgres',
	"SELECT pg_tde_is_encrypted('test_enc_pkey');");
is($stdout, 't', 'test_enc_pkey is encrypted on the replica');
$stdout =
  $replica->safe_psql('postgres', 'SELECT * FROM test_enc ORDER BY x;');
is($stdout, "1\n2", 'can read from test_enc on the replica');

$stdout = $replica->safe_psql('postgres',
	"SELECT pg_tde_is_encrypted('test_plain');");
is($stdout, 'f', 'test_plain is not encrypted on the replica');
$stdout = $replica->safe_psql('postgres',
	"SELECT pg_tde_is_encrypted('test_plain_pkey');");
is($stdout, 'f', 'test_plain_pkey is not encrypted on the replica');
$stdout =
  $replica->safe_psql('postgres', 'SELECT * FROM test_plain ORDER BY x;');
is($stdout, "3\n4", 'can read from test_plain on the replica');

# check that the replica deletes the server key along with the primary
$primary->safe_psql(
	'postgres', qq(
	SELECT pg_tde_add_global_key_provider_file('tmp-vault', '$keydir/tmp.key');
	SELECT pg_tde_create_key_using_global_key_provider('tmp-default-key', 'tmp-vault');
	-- Becomes the server key as well
	SELECT pg_tde_set_default_key_using_global_key_provider('tmp-default-key', 'tmp-vault');
));
$primary->wait_for_catchup('replica');

$stdout = $replica->safe_psql('postgres',
	'SELECT key_name FROM pg_tde_server_key_info();');
is($stdout, 'tmp-default-key', 'the replica has the server key');

$primary->safe_psql(
	'postgres', qq(
	SELECT pg_tde_delete_default_key();
	SELECT pg_tde_delete_global_key_provider('tmp-vault');
));
$primary->wait_for_catchup('replica');

$stdout = $replica->safe_psql('postgres',
	'SELECT key_name FROM pg_tde_server_key_info();');
is($stdout, '', 'the replica has no server key after its deletion');

# check primary crash with WAL encryption
#
# TODO: This does not seem to actually test WAL encryption
$primary->safe_psql(
	'postgres', qq(
	SELECT pg_tde_add_global_key_provider_file('file-vault', '$keydir/global.key');
	SELECT pg_tde_create_key_using_global_key_provider('test-global-key', 'file-vault');
	SELECT pg_tde_set_server_key_using_global_key_provider('test-global-key', 'file-vault');

	CREATE TABLE test_enc2 (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_enc2 (x) VALUES (1), (2);

	ALTER SYSTEM SET pg_tde.wal_encrypt = 'on';
));

$primary->kill9;

PGTDE::poll_start($primary);
$primary->wait_for_catchup('replica');

$stdout =
  $replica->safe_psql('postgres', 'SELECT * FROM test_enc2 ORDER BY x;');
is($stdout, "1\n2", 'can read from test_enc2');

# check that the replica doesn't keep using a deleted principal key
$primary->safe_psql(
	'postgres', qq(
	SELECT pg_tde_create_key_using_global_key_provider('default-key', 'file-vault');
	SELECT pg_tde_set_default_key_using_global_key_provider('default-key', 'file-vault');
	CREATE DATABASE other;
));
$primary->safe_psql(
	'other', qq(
	CREATE EXTENSION pg_tde;
	SELECT pg_tde_add_database_key_provider_file('other-vault', '$keydir/other.keys');
	SELECT pg_tde_create_key_using_database_key_provider('other-key', 'other-vault');
	SELECT pg_tde_set_key_using_database_key_provider('other-key', 'other-vault');

	-- Makes the replica load the key into the cache
	CREATE TABLE test_other (x int PRIMARY KEY) USING tde_heap;
	DROP TABLE test_other;

	SELECT pg_tde_delete_key();

	CREATE TABLE test_default (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_default (x) VALUES (1), (2);

	CHECKPOINT;
));
$primary->wait_for_catchup('replica');

# Make a restartpoint, so the replica doesn't replay the records above after
# the restart and has to rely on the key files it has written.
$replica->safe_psql('postgres', 'CHECKPOINT;');
$replica->restart;

$stdout =
  $replica->safe_psql('other', 'SELECT * FROM test_default ORDER BY x;');
is($stdout, "1\n2", 'can read from test_default after the replica restart');

# check that the replica restart doesn't replay the changes of the principal
# key over the key that was set after them
$primary->safe_psql('postgres', 'CREATE DATABASE newer;');
$primary->safe_psql(
	'newer', qq(
	CREATE EXTENSION pg_tde;
	SELECT pg_tde_add_database_key_provider_file('newer-vault', '$keydir/newer.keys');
	SELECT pg_tde_create_key_using_database_key_provider('newer-key-1', 'newer-vault');
	SELECT pg_tde_create_key_using_database_key_provider('newer-key-2', 'newer-vault');
	SELECT pg_tde_create_key_using_database_key_provider('newer-key-3', 'newer-vault');
	SELECT pg_tde_set_key_using_database_key_provider('newer-key-1', 'newer-vault');

	-- The replica starts the replay from here
	CHECKPOINT;

	SELECT pg_tde_set_key_using_database_key_provider('newer-key-2', 'newer-vault');
	SELECT pg_tde_delete_key();
	SELECT pg_tde_set_key_using_database_key_provider('newer-key-3', 'newer-vault');

	CREATE TABLE test_newer (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_newer (x) VALUES (1), (2);
));
$primary->wait_for_catchup('replica');

$replica->restart;

# The replay restores the table in shared buffers. Make a restartpoint and
# restart once again, so the table has to be written and read with the key
# files left by the replay.
$primary->safe_psql('postgres', 'CHECKPOINT;');
$primary->wait_for_catchup('replica');
$replica->safe_psql('postgres', 'CHECKPOINT;');
$replica->restart;

$stdout =
  $replica->safe_psql('newer', 'SELECT * FROM test_newer ORDER BY x;');
is($stdout, "1\n2", 'can read from test_newer after the replica restart');

$stdout =
  $replica->safe_psql('newer', 'SELECT key_name FROM pg_tde_key_info();');
is($stdout, 'newer-key-3', 'the replica uses the key that was set last');

$replica->stop;
$primary->stop;

done_testing();
