/*
 * TDE XLog resource manager
 */

#ifndef PG_TDE_XLOG_H
#define PG_TDE_XLOG_H

#ifndef FRONTEND

#include "access/xact.h"
#include "access/xlog.h"
#include "access/xloginsert.h"
#include "miscadmin.h"
#include "storage/proc.h"

/* TDE XLOG record types */
#define XLOG_TDE_CREATE_RELATION_KEY	0x00
#define XLOG_TDE_ADD_PRINCIPAL_KEY		0x10
#define XLOG_TDE_ROTATE_PRINCIPAL_KEY	0x20
#define XLOG_TDE_WRITE_KEY_PROVIDER 	0x30
#define XLOG_TDE_INSTALL_EXTENSION		0x40
#define XLOG_TDE_DELETE_RELATION_KEY	0x50
#define XLOG_TDE_DELETE_PRINCIPAL_KEY	0x60

/* ID 140 is registered for Percona TDE extension: https://wiki.postgresql.org/wiki/CustomWALResourceManagers */
#define RM_TDERMGR_ID	140

typedef struct XLogRelKey
{
	RelFileLocator rlocator;
} XLogRelKey;

extern void RegisterTdeRmgr(void);

/*
 * See comments to PG_TDE_START_XLOG_CHANGE().
 *
 * Do not call those directly; use PG_TDE_{START,END}_XLOG_CHANGE()!
 */
static inline void
pg_tde_start_xlog_change(uint8 info, const void *data, int len)
{
	XLogRecPtr	lsn;

	/*
	 * Make sure the transaction has an xid. Otherwise, it doesn't write a
	 * commit record and doesn't wait for synchronous standbys on commit, as
	 * the record is not transactional. Assigning an xid may fail, hence should
	 * be out of the critical section.
	 */
	GetTopTransactionId();

	START_CRIT_SECTION();

	Assert((MyProc->delayChkptFlags & DELAY_CHKPT_START) == 0);
	MyProc->delayChkptFlags |= DELAY_CHKPT_START;

	XLogBeginInsert();
	XLogRegisterData((char *) data, len);
	lsn = XLogInsert(RM_TDERMGR_ID, info);
	XLogFlush(lsn);
}

static inline void
pg_tde_end_xlog_change(void)
{
	MyProc->delayChkptFlags &= ~DELAY_CHKPT_START;

	END_CRIT_SECTION();
}

/*
 * Wraps a change that should be XLogged and must be done. The XLog record is
 * guaranteed to persist in WAL, be sent to replicas, and be replayed during
 * recovery should a crash happen inside the section:
 *
 *	PG_TDE_START_XLOG_CHANGE(info, &data, sizeof(data));
 *	{
 *		... the change ...
 *	}
 *	PG_TDE_END_XLOG_CHANGE();
 *
 * Writes and flushes the XLog record and enters a critical section, hence any
 * failure until PG_TDE_END_XLOG_CHANGE() is a PANIC. Also delays checkpoints,
 * so the recovery is guaranteed to replay the record should a crash happen.
 *
 * Everything that may fail with an ERROR must be done before. The change must
 * not return, break or goto out of the block, as it would skip
 * PG_TDE_END_XLOG_CHANGE().
 */
#define PG_TDE_START_XLOG_CHANGE(xrec_type, data, len) \
	do { \
		pg_tde_start_xlog_change((xrec_type), (data), (len))

#define PG_TDE_END_XLOG_CHANGE() \
		pg_tde_end_xlog_change(); \
	} while (0)

/* Must be called via PG_TDE_{START,END}_XLOG_CHANGE() */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC poison pg_tde_start_xlog_change pg_tde_end_xlog_change
#endif

#endif							/* !FRONTEND */
#endif							/* PG_TDE_XLOG_H */
