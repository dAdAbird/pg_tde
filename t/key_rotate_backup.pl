# A base backup copies the key files one by one while the server is running,
# with no locks taken, and it silently skips the files that vanish meanwhile.
# Check that the copy has a usable set of keys even if the principal key is
# rotated in the middle of that.
#
# The copying is done by the test itself, with the low-level backup API, to
# have the rotation exactly between the two halves of the key files.

use strict;
use warnings FATAL => 'all';
use File::Basename qw(dirname);
use File::Copy qw(copy);
use File::Find qw(find);
use File::Path qw(make_path rmtree);
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::RecursiveCopy;
use PostgreSQL::Test::Utils;
use Test::More;

my $keydir = PostgreSQL::Test::Utils::tempdir;

my $primary = PostgreSQL::Test::Cluster->new('primary');
$primary->init(has_archiving => 1, allows_streaming => 1);
$primary->append_conf('postgresql.conf',
	"shared_preload_libraries = 'pg_tde'");
$primary->start;

$primary->safe_psql(
	'postgres', qq(
	CREATE EXTENSION pg_tde;
	SELECT pg_tde_add_database_key_provider_file('file-vault', '$keydir/db.keys');
	SELECT pg_tde_create_key_using_database_key_provider('key-1', 'file-vault');
	SELECT pg_tde_create_key_using_database_key_provider('key-2', 'file-vault');
	SELECT pg_tde_set_key_using_database_key_provider('key-1', 'file-vault');

	CREATE TABLE test_1 (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_1 (x) VALUES (1), (2);
	CREATE TABLE test_2 (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_2 (x) VALUES (3), (4);
));

my $data_dir = $primary->data_dir;
my $backup_name = 'backup';
my $backup_dir = $primary->backup_dir . '/' . $backup_name;

my $psql = $primary->background_psql('postgres');
$psql->query_safe("SET client_min_messages TO WARNING");
$psql->set_query_timer_restart;
$psql->query_safe("SELECT pg_backup_start('test label', true)");

# The key files of the databases, as the one who copies them sees them when
# it gets to the directory
my @key_files;
find(
	{
		wanted => sub {
			my $path = $File::Find::name;
			$path =~ s{^\Q$data_dir\E/}{};
			push @key_files, $path if -f $_ && $path =~ m{^pg_tde/\d+/};
		},
		no_chdir => 1
	},
	"$data_dir/pg_tde");
@key_files = sort @key_files;
cmp_ok(scalar(@key_files), '>=', 5,
	'there are key files of the relations and the principal key');

# Everything but the keys of the databases
PostgreSQL::Test::RecursiveCopy::copypath(
	$data_dir,
	$backup_dir,
	filterfn => sub {
		my $path = shift;
		return $path !~ m{^pg_tde/\d+$};
	});

# Copies the files which are still there, the way a base backup does. Returns
# the number of the ones that are gone.
sub copy_key_files
{
	my $vanished = 0;

	foreach my $path (@_)
	{
		if (!-e "$data_dir/$path")
		{
			$vanished++;
			next;
		}

		make_path(dirname("$backup_dir/$path"));
		copy("$data_dir/$path", "$backup_dir/$path")
		  or BAIL_OUT("unable to copy $path");
	}

	return $vanished;
}

my $half = int(scalar(@key_files) / 2);
my $vanished = copy_key_files(@key_files[ 0 .. $half - 1 ]);

$primary->safe_psql('postgres',
	"SELECT pg_tde_set_key_using_database_key_provider('key-2', 'file-vault');"
);

$vanished += copy_key_files(@key_files[ $half .. $#key_files ]);

is($vanished, 0, 'no key file has vanished while being copied');

# The rest is what the low-level backup needs to be restored
unlink("$backup_dir/postmaster.pid")
  or BAIL_OUT("unable to unlink $backup_dir/postmaster.pid");
unlink("$backup_dir/postmaster.opts")
  or BAIL_OUT("unable to unlink $backup_dir/postmaster.opts");
unlink("$backup_dir/global/pg_control")
  or BAIL_OUT("unable to unlink $backup_dir/global/pg_control");
rmtree("$backup_dir/pg_wal")
  or BAIL_OUT("unable to unlink contents of $backup_dir/pg_wal");
mkdir("$backup_dir/pg_wal");

$primary->safe_psql('postgres', 'INSERT INTO test_1 (x) VALUES (5);');

my $segment_name = $primary->safe_psql('postgres',
	'SELECT pg_walfile_name(pg_switch_wal())');
$primary->poll_query_until('postgres',
	q{SELECT last_archived_wal FROM pg_stat_archiver},
	$segment_name)
  or die
  "Timed out while waiting for archiving of switched segment to finish";

$primary->safe_psql('postgres', 'CHECKPOINT');
copy("$data_dir/global/pg_control", "$backup_dir/global/pg_control")
  or BAIL_OUT("unable to copy global/pg_control");

my $backup_label =
  $psql->query_safe('SELECT labelfile FROM pg_backup_stop()');
$psql->quit;

open my $fh, '>>', "$backup_dir/backup_label"
  or die "could not open backup_label";
binmode $fh;
print $fh $backup_label;
close $fh;

my $replica = PostgreSQL::Test::Cluster->new('replica');
$replica->init_from_backup($primary, $backup_name, has_restoring => 1);
$replica->start;

is( $replica->safe_psql('postgres', 'SELECT x FROM test_1 ORDER BY x;'),
	"1\n2\n5",
	'can read the first table from the backup');
is( $replica->safe_psql('postgres', 'SELECT x FROM test_2 ORDER BY x;'),
	"3\n4",
	'can read the second table from the backup');
is( $replica->safe_psql(
		'postgres', 'SELECT key_name FROM pg_tde_key_info();'),
	'key-2',
	'the backup uses the key the principal key was rotated to');

$replica->stop;
$primary->stop;

done_testing();
