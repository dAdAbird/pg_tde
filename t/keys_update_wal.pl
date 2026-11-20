# Test migration of pg_tde/wal_keys from the format of the version 2.
#
# The current version differs from it only in the file header, which has got
# the WAL position the server key was set at as its last field. So instead of
# a pre-created data directory, the file written by the server is turned into
# the old format by cutting that field out.

use strict;
use warnings FATAL => 'all';
use pgtde;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

sub read_file
{
	my ($path) = @_;

	open(my $fh, '<:raw', $path) or die "could not open $path: $!";
	local $/;
	my $data = <$fh>;
	close($fh);

	return $data;
}

sub write_file
{
	my ($path, $data) = @_;

	open(my $fh, '>:raw', $path) or die "could not open $path: $!";
	print $fh $data;
	close($fh);
}

my $keydir = PostgreSQL::Test::Utils::tempdir;

my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_tde'");
$node->start;

$node->safe_psql(
	'postgres', qq(
	CREATE EXTENSION pg_tde;
	SELECT pg_tde_add_global_key_provider_file('global_keyring', '$keydir/global.keys');
	SELECT pg_tde_create_key_using_global_key_provider('server_key', 'global_keyring');
	SELECT pg_tde_set_server_key_using_global_key_provider('server_key', 'global_keyring');
));

my $wal_keys = $node->data_dir . '/pg_tde/wal_keys';
my $keys_version = $node->data_dir . '/pg_tde/keys_version';

# There are no WAL keys yet, so the file consists of the header only
my $header_size = -s $wal_keys;

$node->safe_psql('postgres', 'ALTER SYSTEM SET pg_tde.wal_encrypt = on;');
$node->restart;

# The table exists only in the encrypted WAL, so the server needs the migrated
# WAL keys to bring it back after the crash.
$node->safe_psql(
	'postgres', qq(
	CREATE TABLE test (x int);
	INSERT INTO test (x) VALUES (1), (2);
));

$node->kill9;

my $data = read_file($wal_keys);
cmp_ok(length($data), '>', $header_size, 'WAL keys file has keys');

# The version is the most significant byte of the magic number the file
# starts with
my $version_pos = unpack('C', pack('L', 1)) ? 3 : 0;
is(unpack('C', substr($data, $version_pos, 1)),
	3, 'WAL keys file has the current version');

substr($data, $version_pos, 1) = pack('C', 2);
write_file($wal_keys,
	substr($data, 0, $header_size - 8) . substr($data, $header_size));

# The version of the WAL keys comes second in the version file, after the one
# of the relation keys
$data = read_file($keys_version);
substr($data, 4 + $version_pos, 1) = pack('C', 2);
write_file($keys_version, $data);

PGTDE::poll_start($node);

my $stdout = $node->safe_psql('postgres', 'TABLE test;');
is($stdout, "1\n2", 'data is correct after the WAL keys migration');

$stdout = $node->safe_psql('postgres',
	'SELECT key_name FROM pg_tde_server_key_info();');
is($stdout, 'server_key', 'server key is the same after the migration');

$data = read_file($wal_keys);
is(unpack('C', substr($data, $version_pos, 1)),
	3, 'WAL keys file is updated to the current version');

# Check that the migrated file can be used further on
$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_create_key_using_global_key_provider('server_key_2', 'global_keyring');
	SELECT pg_tde_set_server_key_using_global_key_provider('server_key_2', 'global_keyring');
	INSERT INTO test (x) VALUES (3);
));

$node->kill9;

PGTDE::poll_start($node);

$stdout = $node->safe_psql('postgres', 'TABLE test;');
is($stdout, "1\n2\n3", 'data is correct after the server key rotation');

$node->stop;

done_testing();
