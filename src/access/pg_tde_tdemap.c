#include "postgres.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>

#include "access/xloginsert.h"
#include "storage/fd.h"

#include "access/pg_tde_tdemap.h"
#include "access/pg_tde_xlog.h"
#include "catalog/tde_global_space.h"
#include "catalog/tde_principal_key.h"
#include "common/file_perm.h"
#include "common/pg_tde_utils.h"
#include "encryption/enc_aes.h"
#include "encryption/enc_tde.h"
#include "pg_tde.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#else
#include "access/xact.h"
#include "access/xlog.h"
#include "miscadmin.h"
#include "storage/proc.h"
#endif

/* A useful macro when debugging key encryption/decryption */
#ifdef DEBUG
#define ELOG_KEY(_msg, _key)												\
{																			\
	int i;																	\
	char buf[1024];															\
	for (i = 0; i < sizeof(_key.key); i++)					\
		sprintf(buf+i, "%02X", _key.key[i]);				\
	buf[i] = '\0';															\
	elog(INFO, "[%s] INTERNAL KEY => %s", _msg, buf);						\
}
#endif

#define PG_TDE_PRINCIPAL_KEY_FILE	"pkey_info"
#define PG_TDE_KEY_FILE_SUFFIX		"_key"
#define PG_TDE_KEY_FILENAME			"%u_%u" PG_TDE_KEY_FILE_SUFFIX
#define PG_TDE_TMP_FILE_SUFFIX		".r"

#define PG_TDE_DB_DIR_DELETE_SUFFIX	".rm"
#define PG_TDE_GEN_DIR_NEW_SUFFIX	".new"

/*
 * Layout of the keys of a database:
 *
 *	pg_tde/<dbOid>/							directory of the database
 *	pg_tde/<dbOid>/<gen>/					key generation
 *	pg_tde/<dbOid>/<gen>/pkey_info			principal key info
 *	pg_tde/<dbOid>/<gen>/<spcOid>_<rel>_key	relation key
 *	pg_tde/<dbOid>/<gen>.new/				key generation being built
 *
 * A key generation is all the keys of the database encrypted with one
 * principal key. The generation with the highest number is the current one,
 * the only one that is read and changed. Setting or rotating the principal key
 * never re-encrypts the keys in place. It builds the next generation under a
 * temporary name, and then gives it its number with a single rename.
 *
 * It is so to keep the keys safe to copy file by file while the server is
 * running, with no locks taken. That is what a base backup does, and it
 * silently skips the files that vanish meanwhile:
 *
 * - A generation gets its number only when it is complete.
 *
 * - The keys of a generation are never re-encrypted, so whichever of its
 *   files are copied, they match its principal key. The relation keys created
 *   and removed meanwhile are covered by WAL.
 *
 * - The previous generation is not removed right away, so the one who started
 *   copying it before the rotation gets all of it. It is removed by the next
 *   change of the principal key, or on the server start.
 *
 * If the copy has got the generation that was replaced meanwhile, redo of the
 * rotation builds the next one from it.
 */

/* Principal key file on disk */
typedef struct TDEFileHeader
{
	int32		file_version;
	TDESignedPrincipalKeyInfo signed_key_info;
} TDEFileHeader;

/* SMGR key on disk */
typedef struct TDESmgrKeyEntry
{
	int32		file_version;
	uint32		cipher;			/* Part of AAD. Cipher type. We support only
								 * AES_128 and AES_256 for now. */

	/*
	 * IV and tag used when encrypting the key itself
	 *
	 * TODO: should we extend MAP_ENTRY_IV_SIZE to 192(?) bit and add an
	 * iv_size filed?
	 */
	unsigned char entry_iv[MAP_ENTRY_IV_SIZE];
	unsigned char aead_tag[MAP_ENTRY_AEAD_TAG_SIZE];

	uint8		key_base_iv[INTERNAL_KEY_IV_LEN];
	uint8		encrypted_key_data[INTERNAL_KEY_MAX_LEN];
	// uint8		encrypted_key_data[FLEXIBLE_ARRAY_MEMBER]; // TODO
} TDESmgrKeyEntry;

typedef struct TDESmgrKeyAAD
{
	uint32		cipher;
	Oid			spcOid;
	RelFileNumber relNumber;
} TDESmgrKeyAAD;

static void pg_tde_set_db_dir_path(Oid dbOid, const char *suffix, char *path);
static void pg_tde_set_gen_key_file_path(RelFileLocator rel, uint32 gen, char *path);
static bool pg_tde_parse_gen_dir_name(const char *name, uint32 *gen);
static uint32 pg_tde_get_key_gen(Oid dbOid, int elevel);
static bool pg_tde_set_key_file_path(RelFileLocator rel, char *path);
static bool pg_tde_set_pkey_file_path(Oid dbOid, char *path);
static TDESignedPrincipalKeyInfo *pg_tde_read_principal_key_file(const char *path);
static bool pg_tde_read_key_entry(const RelFileLocator *rlocator, TDESmgrKeyEntry *key_entry);
static void pg_tde_read_key_file(const char *file_path, TDESmgrKeyEntry *key_entry);
static InternalKey *tde_decrypt_rel_key(const TDEPrincipalKey *principal_key, TDESmgrKeyEntry *key_entry, const RelFileLocator *rlocator);
static void pg_tde_set_key_aad(TDESmgrKeyAAD *aad, uint32 cipher, const RelFileLocator *rlocator);
static void pg_tde_initialize_key_entry(TDESmgrKeyEntry *key_entry, const TDEPrincipalKey *principal_key, const RelFileLocator *rlocator, const InternalKey *rel_key_data);
static void pg_tde_write_file(const char *path, const void *data, size_t len, bool sync);
static void pg_tde_durable_write_file(const char *path, const void *data, size_t len);
#ifndef FRONTEND
static void pg_tde_set_gen_dir_path(Oid dbOid, uint32 gen, const char *suffix, char *path);
static uint32 pg_tde_start_key_gen(const TDESignedPrincipalKeyInfo *signed_key_info, char *new_dir);
static void pg_tde_sync_new_key_gen(Oid dbOid, const char *new_dir);
static void pg_tde_publish_key_gen(Oid dbOid, uint32 gen, const char *new_dir);
static void pg_tde_remove_old_key_gens(Oid dbOid, uint32 oldest_to_keep);
static void pg_tde_save_signed_principal_key(const TDESignedPrincipalKeyInfo *signed_key_info);
static void pg_tde_rotate_rel_key(const char *old_path, const char *new_path, const RelFileLocator *rlocator, const TDEPrincipalKey *old_principal_key, const TDEPrincipalKey *new_principal_key);
static bool pg_tde_parse_key_file_name(const char *name, Oid *spcOid, RelFileNumber *relNumber);
static List *pg_tde_list_key_files(Oid dbOid, uint32 gen, Oid spcOid);
static void pg_tde_remove_dir_if_exists(const char *path);
static bool pg_tde_is_current_principal_key(Oid dbOid, const TDEPrincipalKey *principal_key);
#endif

static void
pg_tde_set_db_dir_path(Oid dbOid, const char *suffix, char *path)
{
	snprintf(path, MAXPGPATH, "%s/%u%s", pg_tde_get_data_dir(), dbOid, suffix);
}

#ifndef FRONTEND
static void
pg_tde_set_gen_dir_path(Oid dbOid, uint32 gen, const char *suffix, char *path)
{
	snprintf(path, MAXPGPATH, "%s/%u/%u%s", pg_tde_get_data_dir(), dbOid, gen, suffix);
}
#endif

static void
pg_tde_set_gen_key_file_path(RelFileLocator rel, uint32 gen, char *path)
{
	snprintf(path, MAXPGPATH, "%s/%u/%u/" PG_TDE_KEY_FILENAME,
			 pg_tde_get_data_dir(), rel.dbOid, gen, rel.spcOid, rel.relNumber);
}

/*
 * Parses the name of a key generation directory. Returns false if it isn't
 * one, e.g. it is a generation that is still being built.
 */
static bool
pg_tde_parse_gen_dir_name(const char *name, uint32 *gen)
{
	char	   *end;
	unsigned long val;

	/* Nothing but a number without leading zeros */
	if (name[0] < '1' || name[0] > '9')
		return false;

	errno = 0;
	val = strtoul(name, &end, 10);
	if (*end != '\0' || errno != 0 || val > PG_UINT32_MAX)
		return false;

	*gen = (uint32) val;

	return true;
}

/*
 * Returns the current key generation of the database, or 0 if it has none.
 *
 * In the backend, the caller must hold tde_lwlock_enc_keys, and the result is
 * valid until the lock is released.
 *
 * elevel: how to report a failure to read the directory. If it returns, the
 * database is taken as having no keys.
 */
static uint32
pg_tde_get_key_gen(Oid dbOid, int elevel)
{
	char		db_dir[MAXPGPATH];
	DIR		   *dir;
	struct dirent *de;
	uint32		result = 0;

	pg_tde_set_db_dir_path(dbOid, "", db_dir);

	dir = AllocateDir(db_dir);

	if (dir == NULL)
	{
		if (errno != ENOENT)
			ereport(elevel,
					errcode_for_file_access(),
					errmsg("could not open directory \"%s\": %m", db_dir));

		return 0;
	}

	while ((de = ReadDirExtended(dir, db_dir, elevel)) != NULL)
	{
		uint32		gen;

		if (pg_tde_parse_gen_dir_name(de->d_name, &gen) && gen > result)
			result = gen;
	}

	FreeDir(dir);

	return result;
}

/*
 * Sets the path of the key file of the relation in the current key generation
 * of its database. Returns false if the database has no key generation, hence
 * no keys at all.
 */
static bool
pg_tde_set_key_file_path(RelFileLocator rel, char *path)
{
	uint32		gen = pg_tde_get_key_gen(rel.dbOid, ERROR);

	if (gen == 0)
		return false;

	pg_tde_set_gen_key_file_path(rel, gen, path);

	return true;
}

/*
 * Sets the path of the principal key file in the current key generation of
 * the database. Returns false if the database has no key generation.
 */
static bool
pg_tde_set_pkey_file_path(Oid dbOid, char *path)
{
	uint32		gen = pg_tde_get_key_gen(dbOid, ERROR);

	if (gen == 0)
		return false;

	snprintf(path, MAXPGPATH, "%s/%u/%u/" PG_TDE_PRINCIPAL_KEY_FILE,
			 pg_tde_get_data_dir(), dbOid, gen);

	return true;
}

static void
pg_tde_write_file(const char *path, const void *data, size_t len, bool sync)
{
	int			fd;

	fd = OpenTransientFile(path, O_RDWR | O_CREAT | O_TRUNC | PG_BINARY);

	if (fd < 0)
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not create tde file \"%s\": %m", path));
	}

	if (pg_pwrite(fd, data, len, 0) != len)
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not write tde file \"%s\": %m", path));
	}

	if (sync)
	{
		if (pg_fsync(fd) != 0)
			ereport(data_sync_elevel(ERROR),
					errcode_for_file_access(),
					errmsg("could not fsync tde file \"%s\": %m", path));
	}
#ifndef FRONTEND
	else
		pg_flush_data(fd, 0, len);
#endif

	CloseTransientFile(fd);
}

/*
 * Atomically writes or replaces the file by writing a temporary one and
 * renaming it.
 */
static void
pg_tde_durable_write_file(const char *path, const void *data, size_t len)
{
	char		path_tmp[MAXPGPATH];

	snprintf(path_tmp, MAXPGPATH, "%s" PG_TDE_TMP_FILE_SUFFIX, path);

	pg_tde_write_file(path_tmp, data, len, true);

#ifdef FRONTEND

	/* The frontend version ignores elevel */
	if (durable_rename(path_tmp, path, ERROR) != 0)
		exit(1);
#else
	durable_rename(path_tmp, path, ERROR);
#endif
}

/*
 * Saves an internal key for the given relation. If replace_existing is false,
 * the function will not overwrite an existing key for the relation, but will
 * instead do nothing.
 */
void
pg_tde_save_smgr_key(RelFileLocator rel,
					 const InternalKey *rel_key_data,
					 bool replace_existing)
{
	char		file_path[MAXPGPATH];
	LWLock	   *lock_pk = tde_lwlock_enc_keys();
	TDEPrincipalKey *principal_key;
	TDESmgrKeyEntry entry = {0};

	LWLockAcquire(lock_pk, LW_EXCLUSIVE);

	if (!replace_existing &&
		pg_tde_set_key_file_path(rel, file_path) &&
		access(file_path, F_OK) == 0)
	{
		LWLockRelease(lock_pk);
		return;
	}

	principal_key = GetPrincipalKey(rel.dbOid, LW_EXCLUSIVE);
	if (principal_key == NULL)
	{
		ereport(ERROR,
				errmsg("principal key not configured"),
				errhint("Use pg_tde_set_key_using_database_key_provider() or pg_tde_set_key_using_global_key_provider() to configure one."));
	}

	pg_tde_initialize_key_entry(&entry, principal_key, &rel, rel_key_data);

#ifdef FRONTEND
	pfree(principal_key);
#endif

	/*
	 * The path is set only now, as getting the principal key might have made
	 * the database start using the default one, which creates the key
	 * generation. Anyway, there is one if there is a principal key.
	 */
	if (!pg_tde_set_key_file_path(rel, file_path))
		elog(ERROR, "database %u has a principal key but no key generation", rel.dbOid);

	pg_tde_durable_write_file(file_path, &entry, sizeof(TDESmgrKeyEntry));

	LWLockRelease(lock_pk);
}

#ifndef FRONTEND
const char *
tde_sprint_key(InternalKey *k)
{
	static char buf[256];
	int			i;

	for (i = 0; i < sizeof(k->key); i++)
		sprintf(buf + i, "%02X", k->key[i]);

	return buf;
}

/*
 * Starts the next key generation of the database: creates its directory under
 * a temporary name and writes the principal key file there. Sets new_dir to
 * the path of the directory, and returns the number the generation gets when
 * it is published with pg_tde_publish_key_gen().
 */
static uint32
pg_tde_start_key_gen(const TDESignedPrincipalKeyInfo *signed_key_info, char *new_dir)
{
	Oid			dbOid = signed_key_info->data.databaseId;
	uint32		gen = pg_tde_get_key_gen(dbOid, ERROR) + 1;
	char		db_dir[MAXPGPATH];
	char		pkey_path[MAXPGPATH];
	TDEFileHeader fheader;

	pg_tde_set_db_dir_path(dbOid, "", db_dir);
	pg_tde_set_gen_dir_path(dbOid, gen, PG_TDE_GEN_DIR_NEW_SUFFIX, new_dir);

	if (MakePGDirectory(db_dir) != 0 && errno != EEXIST)
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not create tde directory \"%s\": %m", db_dir));

	/* Clean up a leftover of an attempt that failed with an error, if any */
	pg_tde_remove_dir_if_exists(new_dir);

	if (MakePGDirectory(new_dir) < 0)
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not create tde directory \"%s\": %m", new_dir));

	fheader.file_version = PG_TDE_SMGR_FILE_MAGIC;
	fheader.signed_key_info = *signed_key_info;

	snprintf(pkey_path, MAXPGPATH, "%s/" PG_TDE_PRINCIPAL_KEY_FILE, new_dir);
	pg_tde_write_file(pkey_path, &fheader, sizeof(TDEFileHeader), true);

	return gen;
}

/*
 * Flushes the directory of the key generation being built, along with the
 * ones above it. To be called when all the files of the generation are written
 * and flushed, before pg_tde_publish_key_gen().
 */
static void
pg_tde_sync_new_key_gen(Oid dbOid, const char *new_dir)
{
	char		db_dir[MAXPGPATH];

	pg_tde_set_db_dir_path(dbOid, "", db_dir);

	fsync_fname(new_dir, true);
	fsync_fname(db_dir, true);
	fsync_fname(pg_tde_get_data_dir(), true);
}

/*
 * Gives the key generation built in new_dir its number, which makes it the
 * current one. It is a single rename, so the generation appears with all its
 * files at once. Everything that may fail for a reason other than I/O is done
 * by this time, hence it fits a critical section.
 */
static void
pg_tde_publish_key_gen(Oid dbOid, uint32 gen, const char *new_dir)
{
	char		db_dir[MAXPGPATH];
	char		gen_dir[MAXPGPATH];

	pg_tde_set_db_dir_path(dbOid, "", db_dir);
	pg_tde_set_gen_dir_path(dbOid, gen, "", gen_dir);

	if (rename(new_dir, gen_dir) < 0)
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not rename tde directory \"%s\" to \"%s\": %m",
					   new_dir, gen_dir));

	fsync_fname(db_dir, true);
}

/*
 * Removes the key generations of the database that are older than the given
 * one, and whatever is left of the ones that were never published.
 *
 * A generation is not removed right after it is replaced with the next one:
 * someone may be in the middle of copying its files, see the comments at the
 * top of the file. So the callers keep the previous generation, and it goes
 * away with the next change of the principal key or on the server start.
 *
 * Failures are only reported, as whatever is left is removed by the next call.
 */
static void
pg_tde_remove_old_key_gens(Oid dbOid, uint32 oldest_to_keep)
{
	char		db_dir[MAXPGPATH];
	DIR		   *dir;
	struct dirent *de;
	List	   *dirs = NIL;
	const size_t suffix_len = strlen(PG_TDE_GEN_DIR_NEW_SUFFIX);

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	pg_tde_set_db_dir_path(dbOid, "", db_dir);

	dir = AllocateDir(db_dir);

	if (dir == NULL)
	{
		if (errno != ENOENT)
			ereport(WARNING,
					errcode_for_file_access(),
					errmsg("could not open directory \"%s\": %m", db_dir));

		return;
	}

	while ((de = ReadDirExtended(dir, db_dir, WARNING)) != NULL)
	{
		size_t		len = strlen(de->d_name);
		uint32		gen;

		if ((len > suffix_len && strcmp(de->d_name + len - suffix_len, PG_TDE_GEN_DIR_NEW_SUFFIX) == 0) ||
			(pg_tde_parse_gen_dir_name(de->d_name, &gen) && gen < oldest_to_keep))
			dirs = lappend(dirs, psprintf("%s/%s", db_dir, de->d_name));
	}

	FreeDir(dir);

	foreach_ptr(char, path, dirs)
	{
		if (!rmtree(path, true))
			ereport(WARNING,
					errmsg("could not remove tde directory \"%s\"", path));
	}

	list_free_deep(dirs);
}

/*
 * Saves the principal key info as the next key generation of the database,
 * with no WAL record written.
 */
static void
pg_tde_save_signed_principal_key(const TDESignedPrincipalKeyInfo *signed_key_info)
{
	Oid			dbOid = signed_key_info->data.databaseId;
	char		new_dir[MAXPGPATH];
	uint32		gen;

	gen = pg_tde_start_key_gen(signed_key_info, new_dir);
	pg_tde_sync_new_key_gen(dbOid, new_dir);
	pg_tde_publish_key_gen(dbOid, gen, new_dir);

	pg_tde_remove_old_key_gens(dbOid, gen - 1);
}

/*
 * Removes the directory with all its content if it exists.
 */
static void
pg_tde_remove_dir_if_exists(const char *path)
{
	if (access(path, F_OK) != 0)
	{
		if (errno == ENOENT)
			return;

		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not access tde directory \"%s\": %m", path));
	}

	if (!rmtree(path, true))
		ereport(ERROR,
				errmsg("could not remove tde directory \"%s\"", path));
}

/*
 * Deletes the key files for a given database.
 *
 * The directory is renamed first so the deletion is atomic. If we fail to
 * remove the renamed directory, it is removed on the next deletion of a
 * database with the same oid.
 */
void
pg_tde_delete_tde_files(Oid dbOid)
{
	char		db_dir[MAXPGPATH];
	char		rm_dir[MAXPGPATH];

	pg_tde_set_db_dir_path(dbOid, "", db_dir);
	pg_tde_set_db_dir_path(dbOid, PG_TDE_DB_DIR_DELETE_SUFFIX, rm_dir);

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	/*
	 * Clean up a leftover of a previous deletion that failed with an error,
	 * if any. We proceed with the rename attempt even if rm_dir existed as
	 * there is a possibility that both db_dir and rm_dir exist (crash before
	 * fsync).
	 */
	pg_tde_remove_dir_if_exists(rm_dir);

	if (rename(db_dir, rm_dir) < 0)
	{
		if (errno != ENOENT)
			ereport(ERROR,
					errcode_for_file_access(),
					errmsg("delete tde directory: could not rename \"%s\" to \"%s\": %m",
						   db_dir, rm_dir));
	}
	else
	{
		fsync_fname(pg_tde_get_data_dir(), true);
		pg_tde_remove_dir_if_exists(rm_dir);
	}

	LWLockRelease(tde_lwlock_enc_keys());
}

/*
 * Checks if the database already uses the given principal key. Creation time
 * is ignored as it differs when the rotation is replayed from WAL.
 */
static bool
pg_tde_is_current_principal_key(Oid dbOid, const TDEPrincipalKey *principal_key)
{
	TDESignedPrincipalKeyInfo *current;
	bool		result;

	current = pg_tde_get_principal_key_info(dbOid);
	if (current == NULL)
		return false;

	result = current->data.databaseId == principal_key->keyInfo.databaseId &&
		current->data.keyringId == principal_key->keyInfo.keyringId &&
		strncmp(current->data.name, principal_key->keyInfo.name, PRINCIPAL_KEY_NAME_LEN) == 0;

	pfree(current);

	return result;
}

/*
 * Removes the key generations that are not needed anymore: all but the
 * current one of every database, and whatever is left of the ones that were
 * never published.
 *
 * The previous generation is kept after a change of the principal key for the
 * sake of those who copy the key files while the server is running. Nobody
 * does when it starts, so this is the time to get rid of them.
 *
 * Nothing has to be fixed here for redo: a generation that was not published
 * before a crash is built again by redo of its WAL record.
 *
 * Should be called on server start.
 */
void
pg_tde_ensure_key_dirs_on_start(void)
{
	const char *data_dir = pg_tde_get_data_dir();
	DIR		   *dir;
	struct dirent *de;
	List	   *db_oids = NIL;

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	dir = AllocateDir(data_dir);
	if (dir == NULL)
	{
		if (errno != ENOENT)
			ereport(ERROR,
					errcode_for_file_access(),
					errmsg("could not open directory \"%s\": %m", data_dir));

		LWLockRelease(tde_lwlock_enc_keys());
		return;
	}

	while ((de = ReadDir(dir, data_dir)) != NULL)
	{
		Oid			dbOid;

		/* The directory of a database is named with its oid, as a generation */
		if (pg_tde_parse_gen_dir_name(de->d_name, &dbOid))
			db_oids = lappend_oid(db_oids, dbOid);
	}

	FreeDir(dir);

	foreach_oid(dbOid, db_oids)
		pg_tde_remove_old_key_gens(dbOid, pg_tde_get_key_gen(dbOid, ERROR));

	LWLockRelease(tde_lwlock_enc_keys());

	list_free(db_oids);
}

/*
 * It doesn't overwrite an existing principal key. The file may already hold a
 * newer (rotated) key when we're replaying an old record.
 */
void
pg_tde_save_principal_key_redo(const TDESignedPrincipalKeyInfo *signed_key_info)
{
	char		pkey_path[MAXPGPATH];

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	if (!pg_tde_set_pkey_file_path(signed_key_info->data.databaseId, pkey_path) ||
		access(pkey_path, F_OK) != 0)
		pg_tde_save_signed_principal_key(signed_key_info);

	LWLockRelease(tde_lwlock_enc_keys());
}

/*
 * Saves the principal key information as the next key generation of the
 * database.
 *
 * Errors out if the database has encrypted relations, as their keys are
 * encrypted with the existing principal key.
 *
 * The caller must have an EXCLUSIVE LOCK on the files before calling this function.
 *
 * write_xlog: if true, the function will write an XLOG record about the
 * principal key addition. We may want to skip this during server recovery/startup
 * or in some other cases when WAL writes are not allowed.
 */
void
pg_tde_save_principal_key(const TDEPrincipalKey *principal_key, bool write_xlog)
{
	Oid			dbOid = principal_key->keyInfo.databaseId;
	TDESignedPrincipalKeyInfo signed_key_info;
	char		new_dir[MAXPGPATH];
	uint32		gen;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	/*
	 * Should not happen, but if it does, the existing keys and encrypted data
	 * become unreadable. So better be safe.
	 */
	if (pg_tde_count_encryption_keys(dbOid, InvalidOid) != 0)
		ereport(ERROR,
				errcode(ERRCODE_OBJECT_IN_USE),
				errmsg("cannot set principal key of database %u", dbOid),
				errdetail("There are encrypted relations in the database."));

	pg_tde_sign_principal_key_info(&signed_key_info, principal_key);

	if (!write_xlog)
	{
		pg_tde_save_signed_principal_key(&signed_key_info);
		return;
	}

	/* Everything that may fail is done before the record is written */
	gen = pg_tde_start_key_gen(&signed_key_info, new_dir);
	pg_tde_sync_new_key_gen(dbOid, new_dir);

	PG_TDE_START_XLOG_CHANGE(XLOG_TDE_ADD_PRINCIPAL_KEY,
							 &signed_key_info, sizeof(TDESignedPrincipalKeyInfo));
	{
		pg_tde_publish_key_gen(dbOid, gen, new_dir);
	}
	PG_TDE_END_XLOG_CHANGE();

	pg_tde_remove_old_key_gens(dbOid, gen - 1);
}

/*
 * Removes the key file of the relation.
 *
 * This function is called by the pg_tde SMGR when storage is unlinked on
 * transaction commit/abort.
 *
 * WARNING not ERROR following mdunlink():
 *   Note: any failure should be reported as WARNING not ERROR, because
 *   we are usually not in a transaction anymore when this is called. 
 */
void
pg_tde_delete_rel_key(const RelFileLocator rlocator)
{
	char		file_path[MAXPGPATH];
	char		gen_dir[MAXPGPATH];
	uint32		gen;
	bool		removed = false;

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	gen = pg_tde_get_key_gen(rlocator.dbOid, WARNING);

	if (gen != 0)
	{
		pg_tde_set_gen_key_file_path(rlocator, gen, file_path);
		pg_tde_set_gen_dir_path(rlocator.dbOid, gen, "", gen_dir);

		if (unlink(file_path) == 0)
			removed = true;
		else if (errno != ENOENT)
			ereport(WARNING,
					errcode_for_file_access(),
					errmsg("could not remove tde file \"%s\": %m", file_path));
	}

	LWLockRelease(tde_lwlock_enc_keys());

	if (removed)
		fsync_fname_ext(gen_dir, true, false, WARNING);
}

/*
 * Re-encrypts the relation key in old_path with the new principal key and
 * writes it to new_path. The new file isn't fsync'd, the caller has to do it.
 */
static void
pg_tde_rotate_rel_key(const char *old_path, const char *new_path,
					  const RelFileLocator *rlocator,
					  const TDEPrincipalKey *old_principal_key,
					  const TDEPrincipalKey *new_principal_key)
{
	TDESmgrKeyEntry key_entry;
	TDESmgrKeyEntry new_key_entry = {0};
	InternalKey *rel_key_data;

	pg_tde_read_key_file(old_path, &key_entry);

	rel_key_data = tde_decrypt_rel_key(old_principal_key, &key_entry, rlocator);
	pg_tde_initialize_key_entry(&new_key_entry, new_principal_key, rlocator, rel_key_data);
	pfree(rel_key_data);

	pg_tde_write_file(new_path, &new_key_entry, sizeof(TDESmgrKeyEntry), false);
}

/*
 * Rotate keys and generates the WAL record for it.
 *
 * The keys of the current key generation are re-encrypted into the next one,
 * which is then published. The current generation is left as is, it is
 * removed later, see pg_tde_remove_old_key_gens().
 */
void
pg_tde_perform_rotate_key(const TDEPrincipalKey *principal_key, const TDEPrincipalKey *new_principal_key, bool write_xlog)
{
	Oid			dbOid = new_principal_key->keyInfo.databaseId;
	TDESignedPrincipalKeyInfo signed_key_info;
	uint32		old_gen;
	uint32		new_gen;
	char		old_dir[MAXPGPATH];
	char		new_dir[MAXPGPATH];
	char		old_path[MAXPGPATH];
	char		new_path[MAXPGPATH];
	List	   *key_files;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));
	Assert(principal_key);
	/* This function cannot be used to rotate the server key. */
	Assert(principal_key->keyInfo.databaseId != GLOBAL_DATA_TDE_OID);
	Assert(principal_key->keyInfo.databaseId == dbOid);

	/* Should have been created along with the current principal key file */
	old_gen = pg_tde_get_key_gen(dbOid, ERROR);
	Assert(old_gen != 0);

	/*
	 * When replaying, there is nothing to do if the database already uses the
	 * new key, i.e. its generation was published before the crash.
	 */
	if (!write_xlog && pg_tde_is_current_principal_key(dbOid, new_principal_key))
		return;

	pg_tde_sign_principal_key_info(&signed_key_info, new_principal_key);

	new_gen = pg_tde_start_key_gen(&signed_key_info, new_dir);
	pg_tde_set_gen_dir_path(dbOid, old_gen, "", old_dir);

	key_files = pg_tde_list_key_files(dbOid, old_gen, InvalidOid);
	foreach_ptr(char, file_name, key_files)
	{
		RelFileLocator rloc = {.dbOid = dbOid};
		bool		parsed PG_USED_FOR_ASSERTS_ONLY;

		parsed = pg_tde_parse_key_file_name(file_name, &rloc.spcOid, &rloc.relNumber);
		Assert(parsed);

		snprintf(old_path, MAXPGPATH, "%s/%s", old_dir, file_name);
		snprintf(new_path, MAXPGPATH, "%s/%s", new_dir, file_name);

		pg_tde_rotate_rel_key(old_path, new_path, &rloc, principal_key, new_principal_key);
	}

	/*
	 * Fsync the key files in a separate loop. pg_tde_rotate_rel_key() has
	 * already advised kernel to flush them so now fsync is cheaper. Shows
	 * a significant performance improvement.
	 */
	foreach_ptr(char, file_name, key_files)
	{
		snprintf(new_path, MAXPGPATH, "%s/%s", new_dir, file_name);
		fsync_fname(new_path, false);
	}
	list_free_deep(key_files);

	pg_tde_sync_new_key_gen(dbOid, new_dir);

	if (write_xlog)
	{
		XLogPrincipalKeyRotate xlrec;

		xlrec.databaseId = new_principal_key->keyInfo.databaseId;
		xlrec.keyringId = new_principal_key->keyInfo.keyringId;
		memcpy(xlrec.keyName, new_principal_key->keyInfo.name, sizeof(new_principal_key->keyInfo.name));

		PG_TDE_START_XLOG_CHANGE(XLOG_TDE_ROTATE_PRINCIPAL_KEY,
								 &xlrec, sizeof(XLogPrincipalKeyRotate));
		{
			pg_tde_publish_key_gen(dbOid, new_gen, new_dir);
		}
		PG_TDE_END_XLOG_CHANGE();
	}
	else
	{
		pg_tde_publish_key_gen(dbOid, new_gen, new_dir);
	}

	/* Keeps the generation we have just replaced */
	pg_tde_remove_old_key_gens(dbOid, old_gen);
}

/*
 * Removes the principal key file. The key generation stays, with no keys in
 * it. The caller must hold an exclusive tde_lwlock_enc_keys and remove the key
 * from the cache.
 */
void
pg_tde_delete_principal_key_redo(Oid dbOid)
{
	char		pkey_path[MAXPGPATH];

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	/* The file is gone already when it is newer than the record */
	if (pg_tde_set_pkey_file_path(dbOid, pkey_path) &&
		(access(pkey_path, F_OK) == 0 || errno != ENOENT))
		durable_unlink(pkey_path, WARNING);
}

/*
 * Deletes the principal key for the database. Errors out if there are still
 * encrypted relations in the database.
 */
void
pg_tde_delete_principal_key(Oid dbOid)
{
	char		pkey_path[MAXPGPATH];

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	if (pg_tde_count_encryption_keys(dbOid, InvalidOid) != 0)
		ereport(ERROR,
				errcode(ERRCODE_OBJECT_IN_USE),
				errmsg("cannot delete principal key of database %u", dbOid),
				errdetail("There are encrypted relations in the database."));

	if (!pg_tde_set_pkey_file_path(dbOid, pkey_path))
		ereport(ERROR,
				errmsg("database %u has no principal key", dbOid));

	if (access(pkey_path, F_OK) != 0)
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not access tde file \"%s\": %m", pkey_path));

	PG_TDE_START_XLOG_CHANGE(XLOG_TDE_DELETE_PRINCIPAL_KEY, &dbOid, sizeof(Oid));
	{
		durable_unlink(pkey_path, ERROR);
	}
	PG_TDE_END_XLOG_CHANGE();
}

#endif							/* !FRONTEND */

void
pg_tde_sign_principal_key_info(TDESignedPrincipalKeyInfo *signed_key_info, const TDEPrincipalKey *principal_key)
{
	signed_key_info->data = principal_key->keyInfo;

	if (!RAND_bytes(signed_key_info->sign_iv, MAP_ENTRY_IV_SIZE))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate iv for key map: %s", ERR_error_string(ERR_get_error(), NULL)));

	AesGcmEncrypt(principal_key->keyData, principal_key->keyLength,
				  signed_key_info->sign_iv, MAP_ENTRY_IV_SIZE,
				  (unsigned char *) &signed_key_info->data, sizeof(signed_key_info->data),
				  (unsigned char *) "", 0,
				  (unsigned char *) "",
				  signed_key_info->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}

static void
pg_tde_initialize_key_entry(TDESmgrKeyEntry *key_entry, const TDEPrincipalKey *principal_key, const RelFileLocator *rlocator, const InternalKey *rel_key_data)
{
	TDESmgrKeyAAD aad;

	key_entry->file_version = PG_TDE_SMGR_FILE_MAGIC;
	memcpy(key_entry->key_base_iv, rel_key_data->base_iv, INTERNAL_KEY_IV_LEN);

	Assert(rel_key_data->key_len == 16 || rel_key_data->key_len == 32);
	key_entry->cipher = rel_key_data->key_len == 32 ? CIPHER_AES_256 : CIPHER_AES_128;	/* We support only those
																						 * for now */

	pg_tde_set_key_aad(&aad, key_entry->cipher, rlocator);

	if (!RAND_bytes(key_entry->entry_iv, MAP_ENTRY_IV_SIZE))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate iv for key map: %s", ERR_error_string(ERR_get_error(), NULL)));

	AesGcmEncrypt(principal_key->keyData, principal_key->keyLength,
				  key_entry->entry_iv, MAP_ENTRY_IV_SIZE,
				  (unsigned char *) &aad, sizeof(TDESmgrKeyAAD),
				  rel_key_data->key, rel_key_data->key_len,
				  key_entry->encrypted_key_data,
				  key_entry->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}

/*
 * Reads a relation key file. Fails if the file can't be read or is corrupted.
 */
static void
pg_tde_read_key_file(const char *file_path, TDESmgrKeyEntry *key_entry)
{
	int			fd;
	off_t		bytes_read;

	fd = OpenTransientFile(file_path, O_RDONLY | PG_BINARY);

	if (fd < 0)
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not open tde file \"%s\": %m", file_path));
	}

	bytes_read = pg_pread(fd, key_entry, sizeof(TDESmgrKeyEntry), 0);
	if (bytes_read < 0)
	{
		int			save_errno = errno;

		/* not to leak on frontend */
		CloseTransientFile(fd);
		errno = save_errno;
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not read tde file \"%s\": %m", file_path));
	}
	CloseTransientFile(fd);

	if (bytes_read != sizeof(TDESmgrKeyEntry))
	{
		ereport(ERROR,
				errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("could not read tde file \"%s\": read %zd of %zu",
					   file_path, (ssize_t) bytes_read, sizeof(TDESmgrKeyEntry)));
	}

	if (FILEMAGIC_TYPE(key_entry->file_version) != FILEMAGIC_TYPE(PG_TDE_SMGR_FILE_MAGIC))
	{
		ereport(ERROR,
				errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("key file \"%s\" is corrupted or has wrong version", file_path),
				errdetail("Getting relation key from the file."));
	}
}

/*
 * Reads the key file of the relation into key_entry. Returns false if the
 * relation has no key file.
 */
static bool
pg_tde_read_key_entry(const RelFileLocator *rlocator, TDESmgrKeyEntry *key_entry)
{
	char		file_path[MAXPGPATH];

	Assert(rlocator != NULL);
	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_SHARED) || LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	if (!pg_tde_set_key_file_path(*rlocator, file_path))
		return false;

	if (access(file_path, F_OK) == -1)
	{
		if (errno == ENOENT)
			return false;

		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not access tde file \"%s\": %m", file_path));
	}

	pg_tde_read_key_file(file_path, key_entry);

	return true;
}

#ifndef FRONTEND

/*
 * Parses the name of a relation key file. Returns false if it isn't one.
 */
static bool
pg_tde_parse_key_file_name(const char *name, Oid *spcOid, RelFileNumber *relNumber)
{
	int			n = 0;

	return sscanf(name, PG_TDE_KEY_FILENAME "%n", spcOid, relNumber, &n) == 2 &&
		n != 0 && name[n] == '\0';
}

/*
 * Lists names of the relation key files in the given key generation of the
 * database. If spcOid is InvalidOid, files of all the tablespaces are listed,
 * otherwise only the ones of the given tablespace. The caller is responsible
 * for freeing the list with list_free_deep().
 */
static List *
pg_tde_list_key_files(Oid dbOid, uint32 gen, Oid spcOid)
{
	char		gen_dir[MAXPGPATH];
	DIR		   *dir;
	struct dirent *de;
	List	   *files = NIL;

	pg_tde_set_gen_dir_path(dbOid, gen, "", gen_dir);

	dir = AllocateDir(gen_dir);

	if (dir == NULL)
	{
		if (errno != ENOENT)
			ereport(ERROR,
					errcode_for_file_access(),
					errmsg("could not open directory \"%s\": %m", gen_dir));

		return NIL;
	}

	while ((de = ReadDir(dir, gen_dir)) != NULL)
	{
		Oid			file_spcOid;
		RelFileNumber file_relNumber;

		if (!pg_tde_parse_key_file_name(de->d_name, &file_spcOid, &file_relNumber))
			continue;

		if (spcOid != InvalidOid && file_spcOid != spcOid)
			continue;

		files = lappend(files, pstrdup(de->d_name));
	}

	FreeDir(dir);

	return files;
}

/*
 * Counts number of encryption keys of the database.
 *
 * Does not check if files are valid.
 *
 * Works even if the database has no keys.
 */
int
pg_tde_count_encryption_keys(Oid dbOid, Oid spcOid)
{
	List	   *files;
	int			count;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_SHARED) || LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	/* A database with no key generation has no directory to list */
	files = pg_tde_list_key_files(dbOid, pg_tde_get_key_gen(dbOid, ERROR), spcOid);
	count = list_length(files);

	list_free_deep(files);

	return count;
}

#endif							/* !FRONTEND */

bool
pg_tde_verify_principal_key_info(TDESignedPrincipalKeyInfo *signed_key_info, const KeyData *principal_key_data)
{
	return AesGcmDecrypt(principal_key_data->data, principal_key_data->len,
						 signed_key_info->sign_iv, MAP_ENTRY_IV_SIZE,
						 (unsigned char *) &signed_key_info->data, sizeof(signed_key_info->data),
						 (unsigned char *) "", 0,
						 (unsigned char *) "",
						 signed_key_info->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}

static void
pg_tde_set_key_aad(TDESmgrKeyAAD *aad, uint32 cipher, const RelFileLocator *rlocator)
{
	memset(aad, 0, sizeof(TDESmgrKeyAAD));
	aad->cipher = cipher;
	aad->spcOid = rlocator->spcOid;
	aad->relNumber = rlocator->relNumber;
}

static InternalKey *
tde_decrypt_rel_key(const TDEPrincipalKey *principal_key, TDESmgrKeyEntry *key_entry,
					const RelFileLocator *rlocator)
{
	InternalKey *key = palloc_object(InternalKey);
	uint32		key_len = pg_tde_cipher_key_length(key_entry->cipher);
	TDESmgrKeyAAD aad;

	Assert(principal_key);

	pg_tde_set_key_aad(&aad, key_entry->cipher, rlocator);

	if (!AesGcmDecrypt(principal_key->keyData, principal_key->keyLength,
					   key_entry->entry_iv, MAP_ENTRY_IV_SIZE,
					   (unsigned char *) &aad, sizeof(TDESmgrKeyAAD),
					   key_entry->encrypted_key_data, key_len,
					   key->key,
					   key_entry->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE))
		ereport(ERROR,
				errmsg("Failed to decrypt key, incorrect principal key or corrupted key file"));

	memcpy(key->base_iv, key_entry->key_base_iv, INTERNAL_KEY_IV_LEN);
	key->key_len = key_len;

	return key;
}

/*
 * Get the principal key from the key file. The caller must hold
 * a LW_SHARED or higher lock on files before calling this function.
 */
TDESignedPrincipalKeyInfo *
pg_tde_get_principal_key_info(Oid dbOid)
{
	char		pkey_path[MAXPGPATH];

	if (!pg_tde_set_pkey_file_path(dbOid, pkey_path))
		return NULL;

	return pg_tde_read_principal_key_file(pkey_path);
}

/*
 * Reads the principal key file. Returns NULL if there is no such file.
 */
static TDESignedPrincipalKeyInfo *
pg_tde_read_principal_key_file(const char *pkey_path)
{
	int			fd;
	TDESignedPrincipalKeyInfo *signed_key_info;
	off_t		bytes_read;
	TDEFileHeader fheader;

	fd = OpenTransientFile(pkey_path, O_RDONLY | PG_BINARY);

	/* The file does not exist. */
	if (fd < 0)
	{
		if (errno == ENOENT)
			return NULL;

		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not open tde file \"%s\": %m", pkey_path));
	}

	bytes_read = pg_pread(fd, &fheader, sizeof(TDEFileHeader), 0);
	if (bytes_read < 0)
	{
		int			save_errno = errno;

		/* not to leak on frontend */
		CloseTransientFile(fd);
		errno = save_errno;
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not read tde file \"%s\": %m", pkey_path));
	}
	CloseTransientFile(fd);

	if (bytes_read == 0)
		return NULL;

	if (bytes_read != sizeof(TDEFileHeader))
	{
		ereport(ERROR,
				errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("could not read tde file \"%s\": read %zd of %zu",
					   pkey_path, (ssize_t) bytes_read, sizeof(TDEFileHeader)));
	}

	if (FILEMAGIC_TYPE(fheader.file_version) != FILEMAGIC_TYPE(PG_TDE_SMGR_FILE_MAGIC))
	{
		ereport(ERROR,
				errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("key file \"%s\" is corrupted or has wrong version", pkey_path),
				errdetail("Getting principal key from the file."));
	}

	signed_key_info = palloc_object(TDESignedPrincipalKeyInfo);
	*signed_key_info = fheader.signed_key_info;

	return signed_key_info;
}

/*
 * Figures out whether a relation is encrypted or not, but without trying to
 * decrypt the key if it is.
 */
bool
pg_tde_has_smgr_key(RelFileLocator rel)
{
	bool		result;
	char		file_path[MAXPGPATH];

	Assert(rel.relNumber != InvalidRelFileNumber);

	LWLockAcquire(tde_lwlock_enc_keys(), LW_SHARED);

	if (!pg_tde_set_key_file_path(rel, file_path))
		result = false;
	else if (access(file_path, F_OK) == 0)
		result = true;
	else if (errno == ENOENT)
		result = false;
	else
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not access tde file \"%s\": %m", file_path));

	LWLockRelease(tde_lwlock_enc_keys());
	return result;
}

/*
 * Reads the key file of the relation and decrypts the key.
 */
InternalKey *
pg_tde_get_smgr_key(RelFileLocator rel)
{
	char		file_path[MAXPGPATH];
	TDESmgrKeyEntry key_entry;
	TDEPrincipalKey *principal_key;
	LWLock	   *lock_pk = tde_lwlock_enc_keys();
	InternalKey *rel_key;

	Assert(rel.relNumber != InvalidRelFileNumber);

	LWLockAcquire(lock_pk, LW_SHARED);

	/*
	 * Don't bother with the principal key if the relation has no key. Only
	 * the existence is checked here, the key itself must be read after
	 * GetPrincipalKey(), see below.
	 */
	if (!pg_tde_set_key_file_path(rel, file_path))
	{
		LWLockRelease(lock_pk);
		return NULL;
	}

	if (access(file_path, F_OK) != 0)
	{
		if (errno != ENOENT)
			ereport(ERROR,
					errcode_for_file_access(),
					errmsg("could not access tde file \"%s\": %m", file_path));

		LWLockRelease(lock_pk);
		return NULL;
	}

	/*
	 * The principal key must be obtained before reading the internal key.
	 * GetPrincipalKey() releases and re-acquires the lock if the key is not
	 * in the cache, so anything read before it might be stale: another
	 * process could have rotated the principal key and re-encrypted the
	 * internal key into the next key generation, or dropped the relation, in
	 * between. So the path set above must not be used anymore either.
	 *
	 * After GetPrincipalKey() returns, the lock is held until the internal
	 * key is decrypted, hence the internal key we read is encrypted with the
	 * principal key we've got.
	 */
	principal_key = GetPrincipalKey(rel.dbOid, LW_SHARED);

	if (!pg_tde_read_key_entry(&rel, &key_entry))
	{
		/* The relation was dropped while we didn't hold the lock */
		LWLockRelease(lock_pk);
#ifdef FRONTEND
		if (principal_key != NULL)
			pfree(principal_key);
#endif
		return NULL;
	}

	if (principal_key == NULL)
		ereport(ERROR,
				errmsg("principal key not configured"),
				errhint("Use pg_tde_set_key_using_database_key_provider() or pg_tde_set_key_using_global_key_provider() to configure one."));
	rel_key = tde_decrypt_rel_key(principal_key, &key_entry, &rel);

	/* principal_key may point to the cache, which needs the lock held */
	if (principal_key->keyLength != rel_key->key_len)
	{
		ereport(LOG,
				errmsg("length \"%u\" of principal key \"%s\" does not match the length \"%d\" of the internal key", principal_key->keyLength, principal_key->keyInfo.name, rel_key->key_len),
				errhint("Create a new principal key and set it instead of the current one."));
	}

	LWLockRelease(lock_pk);

#ifdef FRONTEND
	/* There is no principal key cache in the frontend. */
	pfree(principal_key);
#endif

	return rel_key;
}
