#include "postgres.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

#include "access/xlog_internal.h"
#include "access/xlog.h"
#include "access/xloginsert.h"
#include "storage/fd.h"
#include "utils/memutils.h"

#include "access/pg_tde_xlog_keys.h"
#include "access/pg_tde_xlog.h"
#include "catalog/tde_global_space.h"
#include "catalog/tde_principal_key.h"
#include "common/pg_tde_utils.h"
#include "encryption/enc_aes.h"
#include "encryption/enc_tde.h"
#include "pg_tde.h"
#include "utils/palloc.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#endif

typedef struct WalKeyFileHeader
{
	int32		file_version;
	TDESignedPrincipalKeyInfo signed_key_info;

	/*
	 * WAL position the server key was set at. All the WAL records that
	 * changed the server key earlier start before it, and the record of
	 * setting this key doesn't. The file is not brought back to the state it
	 * had at the redo start, so that is how redo tells the records the file is
	 * already newer than. InvalidXLogRecPtr if the key was set without a WAL
	 * record.
	 */
	XLogRecPtr	lsn;
} WalKeyFileHeader;

typedef struct WalKeyFileEntry
{
	uint32		cipher;			/* Cipher type. We support only AES_128 and
								 * AES_256 for now. */
	uint32		range_type;		/* WalEncryptionRangeType */
	WalLocation range_start;

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
} WalKeyFileEntry;

static WALKeyCacheRec *tde_wal_key_cache = NULL;
static WALKeyCacheRec *tde_wal_prealloc_record = NULL;
static WALKeyCacheRec *tde_wal_key_last_rec = NULL;
static WalEncryptionRange *tde_wal_prealloc_range = NULL;

static WALKeyCacheRec *pg_tde_add_wal_range_to_cache(WalEncryptionRange *cached_range);
static WalEncryptionRange *pg_tde_wal_range_from_entry(const TDEPrincipalKey *principal_key, WalKeyFileEntry *entry);
static void pg_tde_initialize_wal_key_file_entry(WalKeyFileEntry *entry, const TDEPrincipalKey *principal_key, const WalEncryptionRange *range);
static int	pg_tde_open_wal_key_file_basic(const char *filename, int flags, bool ignore_missing);
static int	pg_tde_open_wal_key_file_read(const char *filename, bool ignore_missing, off_t *curr_pos);
static int	pg_tde_open_wal_key_file_write(const char *filename, const TDESignedPrincipalKeyInfo *signed_key_info, XLogRecPtr lsn, bool truncate, off_t *curr_pos);
static bool pg_tde_read_one_wal_key_file_entry(int fd, WalKeyFileEntry *entry, off_t *offset);
static void pg_tde_read_one_wal_key_file_entry2(int fd, int32 key_index, WalKeyFileEntry *entry);
static void pg_tde_wal_key_file_header_read(const char *filename, int fd, WalKeyFileHeader *fheader, off_t *bytes_read);
static bool pg_tde_read_wal_key_file_header(WalKeyFileHeader *fheader);
static int	pg_tde_wal_key_file_header_write(const char *filename, int fd, const TDESignedPrincipalKeyInfo *signed_key_info, XLogRecPtr lsn, off_t *bytes_written);
static void pg_tde_write_one_wal_key_file_entry(int fd, const WalKeyFileEntry *entry, off_t *offset, const char *db_map_path);
static void pg_tde_write_wal_key_file_entry(const WalEncryptionRange *range, const TDEPrincipalKey *principal_key);

void
pg_tde_free_wal_key_cache(void)
{
	WALKeyCacheRec *rec = tde_wal_key_cache;

	while (rec != NULL)
	{
		WALKeyCacheRec *next = rec->next;

		EVP_CIPHER_CTX_free(rec->crypt_ctx);
		pfree(rec);
		rec = next;
	}

	tde_wal_key_cache = NULL;
	tde_wal_key_last_rec = NULL;
}

/*
 * Called by the WAL write callback, possibly with WALWriteLock held. So it
 * must not take tde_lwlock_enc_keys, see the comments to
 * tde_lwlock_wal_keys().
 */
void
pg_tde_wal_last_range_set_location(WalLocation loc)
{
	LWLock	   *lock_pk = tde_lwlock_wal_keys();
	int			fd;
	off_t		read_pos,
				write_pos,
				last_key_idx;

	LWLockAcquire(lock_pk, LW_EXCLUSIVE);

	fd = pg_tde_open_wal_key_file_write(get_wal_key_file_path(), NULL, InvalidXLogRecPtr, false, &read_pos);

	last_key_idx = ((lseek(fd, 0, SEEK_END) - sizeof(WalKeyFileHeader)) / sizeof(WalKeyFileEntry)) - 1;
	write_pos = sizeof(WalKeyFileHeader) +
		(last_key_idx * sizeof(WalKeyFileEntry)) +
		offsetof(WalKeyFileEntry, range_start);

	if (pg_pwrite(fd, &loc, sizeof(WalLocation), write_pos) != sizeof(WalLocation))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not write WAL key data file: %m"));
	}

	/*
	 * If the last key overlaps with the previous, then invalidate the
	 * previous one. This may (and will) happen on replicas because it
	 * re-reads primary's data from the beginning of the segment on restart.
	 */
	if (last_key_idx > 0)
	{
		off_t		prev_key_pos = sizeof(WalKeyFileHeader) + ((last_key_idx - 1) * sizeof(WalKeyFileEntry));
		WalKeyFileEntry prev_entry;

		if (pg_pread(fd, &prev_entry, sizeof(WalKeyFileEntry), prev_key_pos) != sizeof(WalKeyFileEntry))
		{
			ereport(ERROR,
					errcode_for_file_access(),
					errmsg("could not read previous WAL key: %m"));
		}

		if (wal_location_cmp(prev_entry.range_start, loc) >= 0)
		{
			prev_entry.range_type = WAL_ENCRYPTION_RANGE_INVALID;

			if (pg_pwrite(fd, &prev_entry, sizeof(WalKeyFileEntry), prev_key_pos) != sizeof(WalKeyFileEntry))
			{
				ereport(ERROR,
						errcode_for_file_access(),
						errmsg("could not write invalidated key: %m"));
			}
		}
	}

	if (pg_fsync(fd) != 0)
	{
		ereport(data_sync_elevel(ERROR),
				errcode_for_file_access(),
				errmsg("could not fsync file: %m"));
	}

	LWLockRelease(lock_pk);
	CloseTransientFile(fd);
}

/*
 * Generates a new internal key for WAL and adds it to the key file.
 *
 * We have a special function for WAL as it is being called during recovery
 * start so there should be no XLog records and aquired locks. The key is
 * always created with start_lsn = InvalidXLogRecPtr. Which will be updated
 * with the actual lsn by the first WAL write.
 */
void
pg_tde_create_wal_range(WalEncryptionRange *range, WalEncryptionRangeType type, int key_len)
{
	TDEPrincipalKey *principal_key;

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	principal_key = GetPrincipalKey(GLOBAL_DATA_TDE_OID, LW_EXCLUSIVE);
	if (principal_key == NULL)
	{
		ereport(ERROR,
				errmsg("principal key not configured"),
				errhint("Use pg_tde_set_server_key_using_global_key_provider() to configure one."));
	}

	/* TODO: no need in generating key if WAL_ENCRYPTION_RANGE_UNENCRYPTED */
	range->type = type;
	range->start.lsn = InvalidXLogRecPtr;
	range->start.tli = 0;
	range->end.lsn = MaxXLogRecPtr;
	range->end.tli = MaxTimeLineID;

	pg_tde_generate_internal_key(&range->key, key_len);

	LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
	pg_tde_write_wal_key_file_entry(range, principal_key);
	LWLockRelease(tde_lwlock_wal_keys());

#ifdef FRONTEND
	free(principal_key);
#endif
	LWLockRelease(tde_lwlock_enc_keys());
}

/*
 * Returns last (the most recent) key for a given relation
 */
WALKeyCacheRec *
pg_tde_get_last_wal_key(void)
{
	return tde_wal_key_last_rec;
}

WALKeyCacheRec *
pg_tde_get_wal_cache_keys(void)
{
	return tde_wal_key_cache;
}

WalEncryptionRange *
pg_tde_read_last_wal_range(void)
{
	off_t		read_pos = 0;
	LWLock	   *lock_pk = tde_lwlock_enc_keys();
	TDEPrincipalKey *principal_key;
	int			fd;
	int			file_idx;
	WalKeyFileEntry entry;
	WalEncryptionRange *range;
	off_t		fsize;

	LWLockAcquire(lock_pk, LW_EXCLUSIVE);
	principal_key = GetPrincipalKey(GLOBAL_DATA_TDE_OID, LW_EXCLUSIVE);
	if (principal_key == NULL)
	{
		LWLockRelease(lock_pk);
		elog(DEBUG1, "init WAL encryption: no principal key");
		return NULL;
	}

	LWLockAcquire(tde_lwlock_wal_keys(), LW_SHARED);

	fd = pg_tde_open_wal_key_file_read(get_wal_key_file_path(), false, &read_pos);
	fsize = lseek(fd, 0, SEEK_END);
	/* No keys */
	if (fsize == sizeof(WalKeyFileHeader))
	{
#ifdef FRONTEND
		pfree(principal_key);
#endif
		LWLockRelease(tde_lwlock_wal_keys());
		LWLockRelease(lock_pk);
		CloseTransientFile(fd);
		return NULL;
	}

	file_idx = ((fsize - sizeof(WalKeyFileHeader)) / sizeof(WalKeyFileEntry)) - 1;
	pg_tde_read_one_wal_key_file_entry2(fd, file_idx, &entry);

	LWLockRelease(tde_lwlock_wal_keys());

	range = pg_tde_wal_range_from_entry(principal_key, &entry);
#ifdef FRONTEND
	pfree(principal_key);
#endif
	LWLockRelease(lock_pk);
	CloseTransientFile(fd);

	return range;
}

/*
 * Fetches WAL keys from disk and adds them to the WAL cache.
 *
 * Called by the WAL read and write callbacks, the latter possibly with
 * WALWriteLock held. So it must not take tde_lwlock_enc_keys, see the comments
 * to tde_lwlock_wal_keys().
 */
WALKeyCacheRec *
pg_tde_fetch_wal_keys(WalLocation start)
{
	off_t		read_pos = 0;
	LWLock	   *lock_pk = tde_lwlock_wal_keys();
	TDEPrincipalKey *principal_key;
#ifndef FRONTEND
	TDEPrincipalKey server_key;
#endif
	int			fd;
	int			keys_count;
	WALKeyCacheRec *return_wal_rec = NULL;

	LWLockAcquire(lock_pk, LW_SHARED);
#ifndef FRONTEND
	principal_key = pg_tde_get_server_key_copy(&server_key) ? &server_key : NULL;
#else
	principal_key = GetPrincipalKey(GLOBAL_DATA_TDE_OID, LW_SHARED);
#endif
	if (principal_key == NULL)
	{
		LWLockRelease(lock_pk);
		elog(DEBUG1, "fetch WAL keys: no principal key");
		return NULL;
	}

	fd = pg_tde_open_wal_key_file_read(get_wal_key_file_path(), false, &read_pos);

	keys_count = (lseek(fd, 0, SEEK_END) - sizeof(WalKeyFileHeader)) / sizeof(WalKeyFileEntry);

	/*
	 * If there is no keys, return a fake one (with the range 0-infinity) so
	 * the reader won't try to check the disk all the time. This for the
	 * walsender in case if WAL is unencrypted and never was.
	 */
	if (keys_count == 0)
	{
		WALKeyCacheRec *wal_rec;
		WalEncryptionRange stub_range = {
			.start = {.tli = 0, .lsn = InvalidXLogRecPtr},
			.end = {.tli = MaxTimeLineID, .lsn = MaxXLogRecPtr},
		};

		wal_rec = pg_tde_add_wal_range_to_cache(&stub_range);

#ifdef FRONTEND
		pfree(principal_key);
#else
		explicit_bzero(&server_key, sizeof(server_key));
#endif
		LWLockRelease(lock_pk);
		CloseTransientFile(fd);
		return wal_rec;
	}

	for (int file_idx = 0; file_idx < keys_count; file_idx++)
	{
		WalKeyFileEntry entry;

		pg_tde_read_one_wal_key_file_entry2(fd, file_idx, &entry);

		/*
		 * Skip new (just created but not updated by write) and invalid keys
		 */
		if (entry.range_type != WAL_ENCRYPTION_RANGE_INVALID &&
			wal_location_valid(entry.range_start) &&
			wal_location_cmp(entry.range_start, start) >= 0)
		{
			WalEncryptionRange *range = pg_tde_wal_range_from_entry(principal_key, &entry);
			WALKeyCacheRec *wal_rec;

			wal_rec = pg_tde_add_wal_range_to_cache(range);

			pfree(range);

			if (!return_wal_rec)
				return_wal_rec = wal_rec;
		}
	}
#ifdef FRONTEND
	pfree(principal_key);
#else
	explicit_bzero(&server_key, sizeof(server_key));
#endif
	LWLockRelease(lock_pk);
	CloseTransientFile(fd);

	return return_wal_rec;
}

/*
 * In special cases, we have to add one more record to the WAL key cache during write (in the critical section, when we can't allocate).
 * This method is a helper to deal with that: when adding a single key, we potentially allocate 2 records.
 * These variables help preallocate them, so in the critical section we can just use the already allocated objects, and update the cache with them.
 *
 * While this is somewhat a hack, it is also simple, safe, reliable, and way easier to implement than to refactor the cache or the decryption/encryption loop.
 */
void
pg_tde_wal_cache_extra_palloc(void)
{
#ifndef FRONTEND
	MemoryContext oldCtx;

	oldCtx = MemoryContextSwitchTo(TopMemoryContext);
#endif
	if (tde_wal_prealloc_record == NULL)
	{
		tde_wal_prealloc_record = palloc0_object(WALKeyCacheRec);
	}
	if (tde_wal_prealloc_range == NULL)
	{
		tde_wal_prealloc_range = palloc0_object(WalEncryptionRange);
	}
#ifndef FRONTEND
	MemoryContextSwitchTo(oldCtx);
#endif
}

static WALKeyCacheRec *
pg_tde_add_wal_range_to_cache(WalEncryptionRange *range)
{
	WALKeyCacheRec *wal_rec;
#ifndef FRONTEND
	MemoryContext oldCtx;

	oldCtx = MemoryContextSwitchTo(TopMemoryContext);
#endif
	wal_rec = tde_wal_prealloc_record == NULL ? palloc0_object(WALKeyCacheRec) : tde_wal_prealloc_record;
	tde_wal_prealloc_record = NULL;
#ifndef FRONTEND
	MemoryContextSwitchTo(oldCtx);
#endif

	wal_rec->range = *range;
	wal_rec->crypt_ctx = NULL;
	if (!tde_wal_key_last_rec)
	{
		tde_wal_key_last_rec = wal_rec;
		tde_wal_key_cache = tde_wal_key_last_rec;
	}
	else
	{
		tde_wal_key_last_rec->next = wal_rec;
		tde_wal_key_last_rec->range.end = wal_rec->range.start;
		tde_wal_key_last_rec = wal_rec;
	}

	return wal_rec;
}

static int
pg_tde_open_wal_key_file_basic(const char *filename,
							   int flags,
							   bool ignore_missing)
{
	int			fd;

	fd = OpenTransientFile(filename, flags);
	if (fd < 0 && !(errno == ENOENT && ignore_missing == true))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not open WAL key file \"%s\": %m", filename));
	}

	return fd;
}

static int
pg_tde_open_wal_key_file_read(const char *filename,
							  bool ignore_missing,
							  off_t *curr_pos)
{
	int			fd;
	WalKeyFileHeader fheader;
	off_t		bytes_read = 0;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_SHARED) ||
		   LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE) ||
		   LWLockHeldByMeInMode(tde_lwlock_wal_keys(), LW_SHARED) ||
		   LWLockHeldByMeInMode(tde_lwlock_wal_keys(), LW_EXCLUSIVE));

	fd = pg_tde_open_wal_key_file_basic(filename, O_RDONLY | PG_BINARY, ignore_missing);
	if (ignore_missing && fd < 0)
		return fd;

	pg_tde_wal_key_file_header_read(filename, fd, &fheader, &bytes_read);
	if (bytes_read > 0 && fheader.file_version != PG_TDE_WAL_KEY_FILE_MAGIC)
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("WAL key file \"%s\" is corrupted or has wrong version: %m", filename));

	*curr_pos = bytes_read;

	return fd;
}

static int
pg_tde_open_wal_key_file_write(const char *filename,
							   const TDESignedPrincipalKeyInfo *signed_key_info,
							   XLogRecPtr lsn,
							   bool truncate,
							   off_t *curr_pos)
{
	int			fd;
	WalKeyFileHeader fheader;
	off_t		bytes_read = 0;
	off_t		bytes_written = 0;
	int			file_flags = O_RDWR | O_CREAT | PG_BINARY | (truncate ? O_TRUNC : 0);

	Assert(LWLockHeldByMeInMode(tde_lwlock_wal_keys(), LW_EXCLUSIVE));

	fd = pg_tde_open_wal_key_file_basic(filename, file_flags, false);

	pg_tde_wal_key_file_header_read(filename, fd, &fheader, &bytes_read);
	if (bytes_read > 0 && fheader.file_version != PG_TDE_WAL_KEY_FILE_MAGIC)
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("WAL key file \"%s\" has wrong version: %m", filename));

	/* In case it's a new file, let's add the header now. */
	if (bytes_read == 0 && signed_key_info)
		pg_tde_wal_key_file_header_write(filename, fd, signed_key_info, lsn, &bytes_written);

	*curr_pos = bytes_read + bytes_written;
	return fd;
}

static void
pg_tde_wal_key_file_header_read(const char *filename,
								int fd,
								WalKeyFileHeader *fheader,
								off_t *bytes_read)
{
	Assert(fheader);

	*bytes_read = pg_pread(fd, fheader, sizeof(WalKeyFileHeader), 0);

	/* File is empty */
	if (*bytes_read == 0)
		return;

	if (*bytes_read != sizeof(WalKeyFileHeader))
	{
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("WAL key file \"%s\" is corrupted: %m", filename));
	}
}

/*
 * Reads the header of the WAL keys file. Returns false if there is no file,
 * or it is empty.
 */
static bool
pg_tde_read_wal_key_file_header(WalKeyFileHeader *fheader)
{
	int			fd;
	off_t		bytes_read = 0;

	fd = pg_tde_open_wal_key_file_basic(get_wal_key_file_path(), O_RDONLY | PG_BINARY, true);

	/* The file does not exist. */
	if (fd < 0)
		return false;

	pg_tde_wal_key_file_header_read(get_wal_key_file_path(), fd, fheader, &bytes_read);
	if (bytes_read > 0 &&
		FILEMAGIC_TYPE(fheader->file_version) != FILEMAGIC_TYPE(PG_TDE_WAL_KEY_FILE_MAGIC))
	{
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("WAL key file \"%s\" is corrupted or has wrong version: %m", get_wal_key_file_path()),
				errdetail("Getting principal key from the file."));
	}

	CloseTransientFile(fd);

	return bytes_read > 0;
}

static int
pg_tde_wal_key_file_header_write(const char *filename,
								 int fd,
								 const TDESignedPrincipalKeyInfo *signed_key_info,
								 XLogRecPtr lsn,
								 off_t *bytes_written)
{
	WalKeyFileHeader fheader = {0};

	Assert(signed_key_info);

	fheader.file_version = PG_TDE_WAL_KEY_FILE_MAGIC;
	fheader.signed_key_info = *signed_key_info;
	fheader.lsn = lsn;
	*bytes_written = pg_pwrite(fd, &fheader, sizeof(WalKeyFileHeader), 0);

	if (*bytes_written != sizeof(WalKeyFileHeader))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not write WAL key file \"%s\": %m", filename));
	}

	if (pg_fsync(fd) != 0)
	{
		ereport(data_sync_elevel(ERROR),
				errcode_for_file_access(),
				errmsg("could not fsync file \"%s\": %m", filename));
	}

	ereport(DEBUG2, errmsg("Wrote the header to %s", filename));

	return fd;
}

/*
 * Returns true if an entry is found or false if we have reached the end of the
 * file.
 */
static bool
pg_tde_read_one_wal_key_file_entry(int fd,
								   WalKeyFileEntry *entry,
								   off_t *offset)
{
	off_t		bytes_read = 0;

	Assert(entry);
	Assert(offset);

	bytes_read = pg_pread(fd, entry, sizeof(WalKeyFileEntry), *offset);

	/* We've reached the end of the file. */
	if (bytes_read != sizeof(WalKeyFileEntry))
		return false;

	*offset += bytes_read;

	return true;
}

static void
pg_tde_read_one_wal_key_file_entry2(int fd,
									int32 key_index,
									WalKeyFileEntry *entry)
{
	off_t		read_pos;

	read_pos = sizeof(WalKeyFileHeader) + key_index * sizeof(WalKeyFileEntry);
	if (pg_pread(fd, entry, sizeof(WalKeyFileEntry), read_pos) != sizeof(WalKeyFileEntry))
	{
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("could not find the required key at index %d in WAL key file \"%s\": %m",
					   key_index, get_wal_key_file_path()));
	}
}

static void
pg_tde_write_wal_key_file_entry(const WalEncryptionRange *range,
								const TDEPrincipalKey *principal_key)
{
	int			fd;
	off_t		curr_pos = 0;
	WalKeyFileEntry write_entry;
	TDESignedPrincipalKeyInfo signed_key_Info;

	pg_tde_sign_principal_key_info(&signed_key_Info, principal_key);

	/* Open and validate file for basic correctness. */
	fd = pg_tde_open_wal_key_file_write(get_wal_key_file_path(), &signed_key_Info, InvalidXLogRecPtr, false, &curr_pos);

	/* WAL keys are always added at the end of the file */
	curr_pos = lseek(fd, 0, SEEK_END);

	/* Initialize WAL key file entry and encrypt key */
	pg_tde_initialize_wal_key_file_entry(&write_entry, principal_key, range);

	/* Write the given entry at curr_pos; i.e. the free entry. */
	pg_tde_write_one_wal_key_file_entry(fd, &write_entry, &curr_pos, get_wal_key_file_path());

	CloseTransientFile(fd);
}

static WalEncryptionRange *
pg_tde_wal_range_from_entry(const TDEPrincipalKey *principal_key, WalKeyFileEntry *entry)
{
	WalEncryptionRange *range = tde_wal_prealloc_range == NULL ? palloc0_object(WalEncryptionRange) : tde_wal_prealloc_range;

	tde_wal_prealloc_range = NULL;

	Assert(principal_key);

	range->type = entry->range_type;
	range->start = entry->range_start;
	range->end.tli = MaxTimeLineID;
	range->end.lsn = MaxXLogRecPtr;
	range->key.key_len = pg_tde_cipher_key_length(entry->cipher);

	memcpy(range->key.base_iv, entry->key_base_iv, INTERNAL_KEY_IV_LEN);
	if (!AesGcmDecrypt(principal_key->keyData, principal_key->keyLength,
					   entry->entry_iv, MAP_ENTRY_IV_SIZE,
					   (unsigned char *) entry, offsetof(WalKeyFileEntry, range_start),
					   entry->encrypted_key_data, range->key.key_len,
					   range->key.key,
					   entry->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE))
		ereport(ERROR,
				errmsg("Failed to decrypt key, incorrect principal key or corrupted key file"));

	return range;
}

static void
pg_tde_write_one_wal_key_file_entry(int fd,
									const WalKeyFileEntry *entry,
									off_t *offset,
									const char *db_map_path)
{
	int			bytes_written = 0;

	bytes_written = pg_pwrite(fd, entry, sizeof(WalKeyFileEntry), *offset);

	if (bytes_written != sizeof(WalKeyFileEntry))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not write WAL key file \"%s\": %m", db_map_path));
	}
	if (pg_fsync(fd) != 0)
	{
		ereport(data_sync_elevel(ERROR),
				errcode_for_file_access(),
				errmsg("could not fsync file \"%s\": %m", db_map_path));
	}

	*offset += bytes_written;
}

static void
pg_tde_initialize_wal_key_file_entry(WalKeyFileEntry *entry,
									 const TDEPrincipalKey *principal_key,
									 const WalEncryptionRange *range)
{
	Assert(range->type == WAL_ENCRYPTION_RANGE_ENCRYPTED || range->type == WAL_ENCRYPTION_RANGE_UNENCRYPTED);

	memset(entry, 0, sizeof(WalKeyFileEntry));

	Assert(range->key.key_len == 16 || range->key.key_len == 32);
	entry->cipher = range->key.key_len == 32 ? CIPHER_AES_256 : CIPHER_AES_128; /* We support only those
																				 * for now */

	entry->range_type = range->type;
	entry->range_start = range->start;
	memcpy(entry->key_base_iv, range->key.base_iv, INTERNAL_KEY_IV_LEN);

	if (!RAND_bytes(entry->entry_iv, MAP_ENTRY_IV_SIZE))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate iv for wal key file entry: %s", ERR_error_string(ERR_get_error(), NULL)));

	/*
	 * TODO: we may want to include `range_start` in AAD. But now it is zero
	 * on the key (range) creation and later gets updated by the first WAL
	 * write. The current AAD has a little sense now, so we might want not to
	 * calculate it at all.
	 */
	AesGcmEncrypt(principal_key->keyData, principal_key->keyLength,
				  entry->entry_iv, MAP_ENTRY_IV_SIZE,
				  (unsigned char *) entry, offsetof(WalKeyFileEntry, range_start),
				  range->key.key, range->key.key_len,
				  entry->encrypted_key_data,
				  entry->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}

#ifndef FRONTEND
/*
 * Brings the copy of the WAL keys file up to date with the changes that
 * pg_tde_wal_last_range_set_location() might have made in the file since it
 * was copied. That function is the only one that changes the file without
 * tde_lwlock_enc_keys, and it touches nothing but the start location of the
 * last range and the type of the one before it.
 *
 * Both files must have the same entries, and the caller must hold an exclusive
 * tde_lwlock_wal_keys.
 */
static void
pg_tde_sync_last_wal_ranges(int src_fd, int dst_fd, const char *dst_path)
{
	int			last_idx;

	Assert(LWLockHeldByMeInMode(tde_lwlock_wal_keys(), LW_EXCLUSIVE));

	last_idx = ((lseek(src_fd, 0, SEEK_END) - sizeof(WalKeyFileHeader)) / sizeof(WalKeyFileEntry)) - 1;

	for (int idx = last_idx; idx >= 0 && idx >= last_idx - 1; idx--)
	{
		off_t		pos = sizeof(WalKeyFileHeader) + idx * sizeof(WalKeyFileEntry);
		WalKeyFileEntry src_entry;
		WalKeyFileEntry dst_entry;

		if (pg_pread(src_fd, &src_entry, sizeof(WalKeyFileEntry), pos) != sizeof(WalKeyFileEntry) ||
			pg_pread(dst_fd, &dst_entry, sizeof(WalKeyFileEntry), pos) != sizeof(WalKeyFileEntry))
			ereport(ERROR,
					errcode_for_file_access(),
					errmsg("could not read WAL key at index %d: %m", idx));

		if (src_entry.range_type == dst_entry.range_type &&
			wal_location_cmp(src_entry.range_start, dst_entry.range_start) == 0)
			continue;

		dst_entry.range_type = src_entry.range_type;
		dst_entry.range_start = src_entry.range_start;

		/* Syncs the file as well */
		pg_tde_write_one_wal_key_file_entry(dst_fd, &dst_entry, &pos, dst_path);
	}
}

/*
 * Rotate keys and generates the WAL record for it.
 *
 * The WAL keys are re-encrypted into a new file which then replaces the
 * current one. If write_xlog is true, the record is flushed before that, see
 * PG_TDE_START_XLOG_CHANGE().
 *
 * redo_lsn: start of the record being replayed if write_xlog is false.
 */
void
pg_tde_perform_rotate_server_key(const TDEPrincipalKey *principal_key,
								 const TDEPrincipalKey *new_principal_key,
								 bool write_xlog,
								 XLogRecPtr redo_lsn)
{
	TDESignedPrincipalKeyInfo new_signed_key_info;
	off_t		old_curr_pos,
				new_curr_pos;
	int			old_fd,
				new_fd;
	char		tmp_path[MAXPGPATH];
	XLogRecPtr	lsn;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));
	Assert(principal_key);
	Assert(principal_key->keyInfo.databaseId == GLOBAL_DATA_TDE_OID);

	pg_tde_sign_principal_key_info(&new_signed_key_info, new_principal_key);
	lsn = write_xlog ? pg_tde_key_change_lsn() : redo_lsn;

	snprintf(tmp_path, MAXPGPATH, "%s.r", get_wal_key_file_path());

	/* Keeps the WAL callbacks away from the file while we are copying it */
	LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);

	old_fd = pg_tde_open_wal_key_file_read(get_wal_key_file_path(), false, &old_curr_pos);
	new_fd = pg_tde_open_wal_key_file_write(tmp_path, &new_signed_key_info, lsn, true, &new_curr_pos);

	/* Read all entries until EOF */
	while (1)
	{
		WalEncryptionRange *range;
		WalKeyFileEntry read_map_entry;
		WalKeyFileEntry write_map_entry;

		if (!pg_tde_read_one_wal_key_file_entry(old_fd, &read_map_entry, &old_curr_pos))
			break;

		/* Decrypt and re-encrypt key */
		range = pg_tde_wal_range_from_entry(principal_key, &read_map_entry);
		pg_tde_initialize_wal_key_file_entry(&write_map_entry, new_principal_key, range);
		pg_tde_write_one_wal_key_file_entry(new_fd, &write_map_entry, &new_curr_pos, tmp_path);
		pfree(range);
	}

	/*
	 * Do the final step - replace the current WAL key file with the file with
	 * new data.
	 */
	if (write_xlog)
	{
		XLogPrincipalKeyRotate xlrec;

		xlrec.databaseId = new_principal_key->keyInfo.databaseId;
		xlrec.keyringId = new_principal_key->keyInfo.keyringId;
		memcpy(xlrec.keyName, new_principal_key->keyInfo.name, sizeof(new_principal_key->keyInfo.name));

		/*
		 * The lock must not be held while writing WAL. But once it is
		 * released, the WAL write callback may set the start location of the
		 * last range in the file we have just copied. And it does so if the
		 * record below happens to be the first WAL written since the server
		 * start. So the lock is taken back only for the replacement itself,
		 * and the copy is brought up to date before that.
		 */
		LWLockRelease(tde_lwlock_wal_keys());

		PG_TDE_START_XLOG_CHANGE(XLOG_TDE_ROTATE_PRINCIPAL_KEY,
								 &xlrec, sizeof(XLogPrincipalKeyRotate));
		{
			LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
			pg_tde_sync_last_wal_ranges(old_fd, new_fd, tmp_path);
			durable_rename(tmp_path, get_wal_key_file_path(), ERROR);
		}
		PG_TDE_END_XLOG_CHANGE();
	}
	else
	{
		durable_rename(tmp_path, get_wal_key_file_path(), ERROR);
	}

	/*
	 * The cache must be switched to the new key along with the file, hence
	 * under the same lock. But out of the critical section, as the cache may
	 * allocate memory. principal_key may point to the cache entry, so it must
	 * not be used after this.
	 */
	pg_tde_set_server_key_cache(new_principal_key);

	LWLockRelease(tde_lwlock_wal_keys());

	CloseTransientFile(old_fd);
	CloseTransientFile(new_fd);
}
#endif

#ifndef FRONTEND
/*
 * Redo of setting the server key.
 *
 * The primary writes this record only when it has no server key, so normally
 * there is none here either and the key is just saved.
 *
 * If there is one, it is either the very same key, when the record is
 * replayed once again, or the key that this server kept on its own. E.g. it
 * was deleted on the primary, but kept here by pg_tde_delete_server_key_redo()
 * because of the WAL keys encrypted with it. The record sets its successor
 * then, and the WAL keys are re-encrypted with it. Like redo of a rotation,
 * this needs both keys to be available in their key providers.
 *
 * The caller must hold an exclusive tde_lwlock_enc_keys and make sure the
 * file is not newer than the record, see xl_tde_perform_key_change().
 *
 * lsn: start of the record being replayed.
 */
void
pg_tde_save_server_key_redo(const TDESignedPrincipalKeyInfo *signed_key_info, XLogRecPtr lsn)
{
	TDESignedPrincipalKeyInfo *curr_key_info;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	curr_key_info = pg_tde_get_server_key_info();

	if (curr_key_info == NULL)
	{
		int			fd;
		off_t		curr_pos;

		LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
		fd = pg_tde_open_wal_key_file_write(get_wal_key_file_path(), signed_key_info, lsn, false, &curr_pos);
		CloseTransientFile(fd);
		LWLockRelease(tde_lwlock_wal_keys());
	}
	else if (curr_key_info->data.keyringId != signed_key_info->data.keyringId ||
			 strncmp(curr_key_info->data.name, signed_key_info->data.name, PRINCIPAL_KEY_NAME_LEN) != 0)
	{
		TDEPrincipalKey *curr_key;
		TDEPrincipalKey *new_key;

		curr_key = GetPrincipalKey(GLOBAL_DATA_TDE_OID, LW_EXCLUSIVE);
		new_key = pg_tde_load_principal_key(signed_key_info);

		/* Updates the cache as well */
		pg_tde_perform_rotate_server_key(curr_key, new_key, false, lsn);

		explicit_bzero(new_key, sizeof(TDEPrincipalKey));
		pfree(new_key);
	}

	if (curr_key_info != NULL)
		pfree(curr_key_info);
}
#endif

/*
 * Creates the key file and saves the principal key information.
 *
 * If the file pre-exist, it truncates the file before adding principal key
 * information.
 *
 * The caller must have an EXCLUSIVE LOCK on the files before calling this function.
 *
 * write_xlog: if true, the function will write an XLOG record about the
 * principal key addition. We may want to skip this during server recovery/startup
 * or in some other cases when WAL writes are not allowed. The record is
 * flushed before the file is put in place, see PG_TDE_START_XLOG_CHANGE().
 */
void
pg_tde_save_server_key(const TDEPrincipalKey *principal_key, bool write_xlog)
{
	int			fd;
	off_t		curr_pos = 0;
	TDESignedPrincipalKeyInfo signed_key_Info;

	pg_tde_sign_principal_key_info(&signed_key_Info, principal_key);

#ifndef FRONTEND
	if (write_xlog)
	{
		char		tmp_path[MAXPGPATH];

		/*
		 * Write the file aside first. So everything that may fail is done
		 * before the record is written, and only the rename is left for the
		 * critical section.
		 */
		snprintf(tmp_path, MAXPGPATH, "%s.r", get_wal_key_file_path());

		LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
		fd = pg_tde_open_wal_key_file_write(tmp_path, &signed_key_Info, pg_tde_key_change_lsn(), true, &curr_pos);
		CloseTransientFile(fd);
		LWLockRelease(tde_lwlock_wal_keys());

		PG_TDE_START_XLOG_CHANGE(XLOG_TDE_ADD_PRINCIPAL_KEY,
								 &signed_key_Info, sizeof(TDESignedPrincipalKeyInfo));
		{
			/* The lock is taken only here, as it must not be held while writing WAL */
			LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
			durable_rename(tmp_path, get_wal_key_file_path(), ERROR);
			LWLockRelease(tde_lwlock_wal_keys());
		}
		PG_TDE_END_XLOG_CHANGE();

		return;
	}
#endif

	LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
	fd = pg_tde_open_wal_key_file_write(get_wal_key_file_path(), &signed_key_Info, InvalidXLogRecPtr, true, &curr_pos);
	CloseTransientFile(fd);
	LWLockRelease(tde_lwlock_wal_keys());
}

/*
 * Get the principal key from the key file. The caller must hold
 * a LW_SHARED or higher lock on files before calling this function.
 */
TDESignedPrincipalKeyInfo *
pg_tde_get_server_key_info(void)
{
	WalKeyFileHeader fheader;
	TDESignedPrincipalKeyInfo *signed_key_info;

	if (!pg_tde_read_wal_key_file_header(&fheader))
		return NULL;

	signed_key_info = palloc_object(TDESignedPrincipalKeyInfo);
	*signed_key_info = fheader.signed_key_info;

	return signed_key_info;
}

/*
 * Checks if the server key was set later than the WAL record starting at the
 * given position was written. If so, redo must leave the key alone, see
 * pg_tde_principal_key_is_newer().
 */
bool
pg_tde_server_key_is_newer(XLogRecPtr lsn)
{
	WalKeyFileHeader fheader;

	return pg_tde_read_wal_key_file_header(&fheader) && fheader.lsn > lsn;
}

int
pg_tde_count_wal_ranges_in_file(void)
{
	File		fd;
	off_t		curr_pos = 0;
	WalKeyFileEntry entry;
	int			count = 0;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_SHARED) ||
		   LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	fd = pg_tde_open_wal_key_file_read(get_wal_key_file_path(), true, &curr_pos);
	if (fd < 0)
		return count;

	while (pg_tde_read_one_wal_key_file_entry(fd, &entry, &curr_pos))
		count++;

	CloseTransientFile(fd);

	return count;
}

#ifndef FRONTEND
void
pg_tde_delete_server_key(void)
{
	Oid			dbOid = GLOBAL_DATA_TDE_OID;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));
	Assert(pg_tde_count_wal_ranges_in_file() == 0);

	PG_TDE_START_XLOG_CHANGE(XLOG_TDE_DELETE_PRINCIPAL_KEY, &dbOid, sizeof(Oid));
	{
		/*
		 * Remove whole key map file. The lock is taken only here, as it must
		 * not be held while writing WAL.
		 */
		LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
		durable_unlink(get_wal_key_file_path(), ERROR);
	}
	PG_TDE_END_XLOG_CHANGE();

	/*
	 * The key leaves the cache along with the file, hence under the same
	 * lock. But out of the critical section, as the cache may allocate memory.
	 */
	pg_tde_set_server_key_cache(NULL);
	LWLockRelease(tde_lwlock_wal_keys());
}

/*
 * Redo of the server key deletion.
 *
 * WAL keys are not replicated, every server has its own. So unlike the
 * primary at the time of the deletion, we may have some: a standby can have
 * WAL encryption enabled on its own. Removing the file would make WAL
 * encrypted with these keys unreadable, hence the server key is kept then.
 * It is replaced when the primary sets the next server key, see
 * pg_tde_save_server_key_redo().
 *
 * The caller must hold an exclusive tde_lwlock_enc_keys and make sure the
 * file is not newer than the record, see xl_tde_perform_key_change().
 */
void
pg_tde_delete_server_key_redo(void)
{
	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	if (pg_tde_count_wal_ranges_in_file() != 0)
	{
		ereport(WARNING,
				errmsg("cannot delete server principal key"),
				errdetail("There are WAL encryption keys."));
		return;
	}

	/*
	 * Remove whole key map file, and the key from the cache along with it.
	 * The file may be gone already, if the record is replayed once again.
	 */
	LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);
	if (access(get_wal_key_file_path(), F_OK) == 0 || errno != ENOENT)
		durable_unlink(get_wal_key_file_path(), WARNING);
	pg_tde_set_server_key_cache(NULL);
	LWLockRelease(tde_lwlock_wal_keys());
}


/*****************************************
 * Functions for migrating old wal_keys into a new format file.
 *****************************************/

/*
 * A version-specific migration routine. It reads an entry of the specific
 * version from the given fd and offset, and transforms it into
 * WalKeyFileEntry (current version)
 */
typedef bool (*WalEntryFromDiskEntry) (int fd, off_t *entry_offset, const TDEPrincipalKey *principal_key, WalKeyFileEntry *out);

/* File header of the versions 1 and 2 */
typedef struct WalKeyFileHeaderV1
{
	int32		file_version;
	TDESignedPrincipalKeyInfo signed_key_info;
} WalKeyFileHeaderV1;

typedef struct WalKeyFileEntryV1
{
	uint32		_unused1;		/* Part of AAD, is 1 or 2 in existing entries */
	uint32		_unused2;		/* Part of AAD */

	uint8		encrypted_key_data[16];
	uint8		key_base_iv[16];

	uint32		range_type;		/* WalEncryptionRangeType */
	uint32		_unused3;
	WalLocation range_start;

	/* IV and tag used when encrypting the key itself */
	unsigned char entry_iv[16];
	unsigned char aead_tag[16];
} WalKeyFileEntryV1;

static bool
pg_tde_read_one_wal_key_file_entry_v1(int fd,
									  WalKeyFileEntryV1 *entry,
									  off_t *offset)
{
	off_t		bytes_read = 0;

	Assert(entry);
	Assert(offset);

	bytes_read = pg_pread(fd, entry, sizeof(WalKeyFileEntryV1), *offset);

	/* We've reached the end of the file. */
	if (bytes_read != sizeof(WalKeyFileEntryV1))
		return false;

	*offset += bytes_read;

	return true;
}

static void
wal_range_from_entry_v1(WalKeyFileEntryV1 *entry, const TDEPrincipalKey *principal_key, WalEncryptionRange *range)
{
	Assert(principal_key);

	range->type = entry->range_type;
	range->start = entry->range_start;
	range->end.tli = MaxTimeLineID;
	range->end.lsn = MaxXLogRecPtr;
	range->key.key_len = sizeof(entry->encrypted_key_data);

	memcpy(range->key.base_iv, entry->key_base_iv, sizeof(entry->key_base_iv));
	if (!AesGcmDecrypt(principal_key->keyData, principal_key->keyLength,
					   entry->entry_iv, sizeof(entry->entry_iv),
					   (unsigned char *) entry, offsetof(WalKeyFileEntryV1, encrypted_key_data),
					   entry->encrypted_key_data, range->key.key_len,
					   range->key.key,
					   entry->aead_tag, sizeof(entry->aead_tag)))
		ereport(ERROR,
				errmsg("failed to decrypt key, incorrect principal key or corrupted key file %u", principal_key->keyLength));
}

static bool
range_from_disk_entry_v1(int fd, off_t *entry_offset, const TDEPrincipalKey *principal_key, WalKeyFileEntry *out)
{
	WalKeyFileEntryV1 disk_entry;
	WalEncryptionRange range;

	if (!pg_tde_read_one_wal_key_file_entry_v1(fd, &disk_entry, entry_offset))
		return false;

	wal_range_from_entry_v1(&disk_entry, principal_key, &range);
	pg_tde_initialize_wal_key_file_entry(out, principal_key, &range);

	return true;
}

/* The entries have not changed since the version 2 */
static bool
range_from_disk_entry_v2(int fd, off_t *entry_offset, const TDEPrincipalKey *principal_key, WalKeyFileEntry *out)
{
	return pg_tde_read_one_wal_key_file_entry(fd, out, entry_offset);
}

void
pg_tde_update_wal_keys_file(void)
{
	LWLock	   *lock_pk = tde_lwlock_enc_keys();
	TDEPrincipalKey *principal_key = NULL;
	char		tmp_wal_key_file_path[MAXPGPATH] = {0};
	off_t		read_pos,
				write_pos;
	int			old_fd,
				new_fd;
	WalKeyFileHeaderV1 fheader;
	WalEntryFromDiskEntry read_range;
	WalKeyFileEntry new_entry;

	old_fd = pg_tde_open_wal_key_file_basic(get_wal_key_file_path(), O_RDONLY | PG_BINARY, true);
	/* Nothing to do, no wal_keys file exists */
	if (old_fd < 0)
		return;

	snprintf(tmp_wal_key_file_path, MAXPGPATH, "%s.r", get_wal_key_file_path());

	/*
	 * The header of the current version is longer, but an up-to-date file is
	 * told by the version, which comes first in all of them.
	 */
	read_pos = pg_pread(old_fd, &fheader, sizeof(WalKeyFileHeaderV1), 0);

	/* check if we have anything to do: an empty file is the same as none */
	if (read_pos == 0 ||
		(read_pos >= sizeof(int32) && fheader.file_version == PG_TDE_WAL_KEY_FILE_MAGIC))
	{
		CloseTransientFile(old_fd);
		return;
	}

	if (read_pos != sizeof(WalKeyFileHeaderV1) ||
		FILEMAGIC_TYPE(fheader.file_version) != FILEMAGIC_TYPE(PG_TDE_WAL_KEY_FILE_MAGIC))
		ereport(FATAL,
				errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("WAL key file \"%s\" is corrupted", get_wal_key_file_path()));

	if (FILEMAGIC_VERSION(fheader.file_version) == 1)
		read_range = range_from_disk_entry_v1;
	else if (FILEMAGIC_VERSION(fheader.file_version) == 2)
		read_range = range_from_disk_entry_v2;
	else
		elog(ERROR, "wal_keys migration: unsupported or corrupted old file version %d", FILEMAGIC_VERSION(fheader.file_version));

	/*
	 * No real need in locks here as the func should be called only on the
	 * server start, but the functions below expect them.
	 */
	LWLockAcquire(lock_pk, LW_EXCLUSIVE);

	/*
	 * The principal key is needed only to re-encrypt the entries of the
	 * version 1. It is loaded by the old header, as nothing can read the file
	 * of an old version but this function.
	 */
	if (FILEMAGIC_VERSION(fheader.file_version) == 1)
		principal_key = pg_tde_load_principal_key(&fheader.signed_key_info);

	LWLockAcquire(tde_lwlock_wal_keys(), LW_EXCLUSIVE);

	/*
	 * The old versions don't have the WAL position the server key was set
	 * at, so the file is taken as older than any WAL record.
	 */
	new_fd = pg_tde_open_wal_key_file_write(tmp_wal_key_file_path, &fheader.signed_key_info, InvalidXLogRecPtr, true, &write_pos);

	while (read_range(old_fd, &read_pos, principal_key, &new_entry))
	{
		pg_tde_write_one_wal_key_file_entry(new_fd, &new_entry, &write_pos, tmp_wal_key_file_path);
	}

	CloseTransientFile(old_fd);
	CloseTransientFile(new_fd);
	durable_rename(tmp_wal_key_file_path, get_wal_key_file_path(), ERROR);

	LWLockRelease(tde_lwlock_wal_keys());
	LWLockRelease(lock_pk);

	if (principal_key != NULL)
	{
		explicit_bzero(principal_key, sizeof(TDEPrincipalKey));
		pfree(principal_key);
	}
}

#endif
