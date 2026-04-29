//this file is part of eMule
//Copyright (C)2002-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#include "StdAfx.h"
#include <memory>
#include <timeapi.h>
#include "updownclient.h"
#include "uploaddiskiothread.h"
#include "emule.h"
#include "UploadQueue.h"
#include "sharedfilelist.h"
#include "partfile.h"
#include "knownfile.h"
#include "log.h"
#include "preferences.h"
#include "safefile.h"
#include "listensocket.h"
#include "packets.h"
#include "Statistics.h"
#include "UploadBandwidthThrottler.h"
#include "zlib/zlib.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define SLOT_COMPRESSION_DATARATE		(1000 * 1024)	// Data rate for a single client from which we start to check if we need to disable compression
#define BIGBUFFER_MINDATARATE			(75 * 1024)

#define RUN_STOP	0
#define RUN_IDLE	1
#define RUN_WORK	2

// Number of disk-reader worker threads.  2 is enough to hide per-file seek
// latency on HDDs while keeping contention on the upload-list lock and the
// socket send path low.  Raising it gives diminishing returns and more lock
// contention; lowering it to 1 degenerates to the original unpatched 0.70c
// "one read at a time" behaviour which is exactly what produced the "speed
// drops to zero" symptom.
#define UPLOAD_DISK_WORKER_COUNT	2

IMPLEMENT_DYNCREATE(CUploadDiskIOThread, CWinThread)

CUploadDiskIOThread::CUploadDiskIOThread()
	: m_eventThreadEnded(FALSE, TRUE)
	, m_Run(RUN_STOP)
	, m_bNewData()
	, m_bStop(false)
	, m_bSignalThrottler(false)
	, m_nInFlight(0)
	, m_bWorkersStop(false)
{
	ASSERT(theApp.uploadqueue != NULL);
	AfxBeginThread(RunProc, (LPVOID)this);
}

CUploadDiskIOThread::~CUploadDiskIOThread()
{
	ASSERT(!m_Run);
	ASSERT(m_workers.empty());
}

UINT AFX_CDECL CUploadDiskIOThread::RunProc(LPVOID pParam)
{
	DbgSetThreadName("UploadDiskIOThread");
	InitThreadLocale();
	return pParam ? static_cast<CUploadDiskIOThread*>(pParam)->RunInternal() : 1;
}

void CUploadDiskIOThread::EndThread()
{
	// Use a dedicated stop flag instead of overloading m_Run: the worker writes
	// m_Run = RUN_WORK / RUN_IDLE outside the cv lock while processing, so a
	// RUN_STOP written here could be clobbered on the next iteration.  m_bStop
	// is touched only here and in the cv predicate, so it cannot race.
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_bStop = true;
	}
	m_cv.notify_one();
	m_eventThreadEnded.Lock();
}

void CUploadDiskIOThread::StopWorkers()
{
	{
		std::lock_guard<std::mutex> lock(m_queueMutex);
		m_bWorkersStop = true;
	}
	m_cvQueue.notify_all();
	for (std::thread &t : m_workers) {
		if (t.joinable())
			t.join();
	}
	m_workers.clear();
	// No jobs should remain — workers drain everything before honouring
	// m_bWorkersStop.  Assert, and as a defensive safety net also free any
	// leftovers so we don't leak on an unexpected shutdown path.
	{
		std::lock_guard<std::mutex> lock(m_queueMutex);
		ASSERT(m_workQueue.IsEmpty() && m_nInFlight == 0);
		while (!m_workQueue.IsEmpty()) {
			OverlappedRead_Struct *p = m_workQueue.RemoveHead();
			if (p) {
				if (p->pFile) --p->pFile->nInUse;
				delete[] p->pBuffer;
				delete p;
			}
		}
		m_nInFlight = 0;
	}
}

UINT CUploadDiskIOThread::RunInternal()
{
	m_Run = RUN_IDLE;

	// Spawn the worker pool now that the coordinator is live.  std::thread is
	// backed by pthread on Wine, which is the most battle-tested path.
	m_workers.reserve(UPLOAD_DISK_WORKER_COUNT);
	for (int i = 0; i < UPLOAD_DISK_WORKER_COUNT; ++i)
		m_workers.emplace_back([this] { WorkerProc(); });

	for (;;) {
		// Wait until there is work to do or we are asked to stop.
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			m_cv.wait(lock, [this] { return m_bNewData || m_bStop; });
			if (m_bStop)
				break;
			m_bNewData = false;
		}

		m_Run = RUN_WORK;

		// ---- Phase 1: collect read requests (under upload-list lock) ----
		//
		// Round-robin across clients: each pass adds at most ONE block per
		// client; loop until a pass adds nothing.  This matters because
		// workers pop from the queue in order — if all of client A's blocks
		// were queued first, then all of B's, workers would all converge on
		// A and finish it before starting B, causing B/C/D's socket queues
		// to drain to zero.  Interleaved = fair.
		CTypedPtrList<CPtrList, OverlappedRead_Struct*> pendingReads;
		{
			CCriticalSection *pcsUploadListRead = NULL;
			const CUploadingPtrList &rUploadList = theApp.uploadqueue->GetUploadListTS(&pcsUploadListRead);
			pcsUploadListRead->Lock();
			for (;;) {
				const INT_PTR cBefore = pendingReads.GetCount();
				for (POSITION pos = rUploadList.GetHeadPosition(); pos != NULL;)
					StartCreateNextBlockPackage(rUploadList.GetNext(pos), pendingReads, true);
				if (pendingReads.GetCount() == cBefore)
					break;
			}
			pcsUploadListRead->Unlock();
		}

		// ---- Phase 2: hand the batch to the worker pool ----
		//
		// Enqueue all jobs, then wait for the pool to drain.  Workers perform
		// each ReadFile synchronously on their own stack — no async, no IOCP.
		// They also call ReadCompletionRoutine, which builds the packets,
		// pushes them on the socket, and signals the throttler.  The
		// coordinator therefore has nothing to do while workers run except
		// wait; in particular it does NOT hold any upload-list lock during
		// this wait, so client-add, block-request, and completion paths all
		// keep working.
		if (!pendingReads.IsEmpty()) {
			{
				std::lock_guard<std::mutex> lock(m_queueMutex);
				while (!pendingReads.IsEmpty())
					m_workQueue.AddTail(pendingReads.RemoveHead());
			}
			// Wake all workers (cheap; they re-check the predicate).
			m_cvQueue.notify_all();

			// Wait for drain.
			{
				std::unique_lock<std::mutex> lock(m_queueMutex);
				m_cvBatchDone.wait(lock, [this] { return m_workQueue.IsEmpty() && m_nInFlight == 0; });
			}
		}

		m_Run = RUN_IDLE;

		// Defensive end-of-batch throttler signal.  Workers already signal
		// per-read, so this is normally a no-op; it just closes the race
		// window where the very last read completed just before the
		// coordinator re-acquired m_queueMutex.
		if (m_bSignalThrottler.exchange(false) && theApp.uploadBandwidthThrottler != NULL)
			theApp.uploadBandwidthThrottler->NewUploadDataAvailable();

		// If WakeUpCall() arrived while we were processing, m_bNewData is
		// already true; cv.wait predicate on the next iteration picks it up.
	}

	// Shutdown: stop workers first so no thread still holds OverlappedRead_Struct
	// pointers, then tear down the thread cleanly.
	StopWorkers();

	m_Run = RUN_STOP;
	m_eventThreadEnded.SetEvent();
	return 0;
}

void CUploadDiskIOThread::WorkerProc()
{
	DbgSetThreadName("UploadDiskIOWorker");
	InitThreadLocale();

	for (;;) {
		OverlappedRead_Struct *pRead = NULL;

		// Wait for a job or shutdown signal.
		{
			std::unique_lock<std::mutex> lock(m_queueMutex);
			m_cvQueue.wait(lock, [this] { return !m_workQueue.IsEmpty() || m_bWorkersStop; });
			if (m_workQueue.IsEmpty() && m_bWorkersStop)
				return; // drain-first policy: stop only after the queue is empty
			pRead = m_workQueue.RemoveHead();
			++m_nInFlight;
		}

		// Synchronous read with per-call offset — equivalent to pread() on
		// POSIX, which is exactly how Wine implements it.  The handle is
		// opened WITHOUT FILE_FLAG_OVERLAPPED; passing an OVERLAPPED struct
		// just tells ReadFile where to start reading, without using the
		// handle's shared file pointer.  Therefore multiple workers can
		// safely call ReadFile on the same handle at the same time.
		DWORD dwRead = 0;
		if (pRead->pFile->m_hRead != INVALID_HANDLE_VALUE) {
			OVERLAPPED ov = {};
			// Offset / OffsetHigh together form a 64-bit offset.
			*(uint64*)&ov.Offset = pRead->uStartOffset;
			const DWORD toRead = (DWORD)(pRead->uEndOffset - pRead->uStartOffset);
			if (!::ReadFile(pRead->pFile->m_hRead, pRead->pBuffer, toRead, &dwRead, &ov)) {
				// ERROR_HANDLE_EOF is possible if the block straddles EOF
				// on a freshly truncated part-file.  All other errors (incl.
				// ERROR_INVALID_HANDLE if the file was closed mid-read) are
				// treated as zero-byte reads and ReadCompletionRoutine will
				// mark the client's m_bIOError.
				dwRead = 0;
			}
		}

		// Build packets, send them, and signal the throttler.  This runs
		// fully outside the queue mutex.  ReadCompletionRoutine internally
		// takes the upload-list lock for the duration of packet creation
		// (which is brief) — contention between workers on that lock is
		// minor because packet creation is CPU-bound and short.
		ReadCompletionRoutine(dwRead, pRead);

		// Signal the throttler per-read, not per-batch: with multiple
		// workers a slow read in worker #0 must not hold back the packets
		// that worker #1 has already prepared for a different slot.  The
		// coordinator also does a defensive final signal at batch end.
		if (m_bSignalThrottler.exchange(false) && theApp.uploadBandwidthThrottler != NULL)
			theApp.uploadBandwidthThrottler->NewUploadDataAvailable();

		// Mark completion and wake the coordinator if this was the last one.
		{
			std::lock_guard<std::mutex> lock(m_queueMutex);
			--m_nInFlight;
			if (m_workQueue.IsEmpty() && m_nInFlight == 0)
				m_cvBatchDone.notify_one();
		}
	}
}

bool CUploadDiskIOThread::AssociateFile(CKnownFile *pFile)
{
	ASSERT(m_Run);
	if (pFile && pFile->m_hRead == INVALID_HANDLE_VALUE && !pFile->bNoNewReads) {
		CString fullname = (pFile->IsPartFile())
			? RemoveFileExtension(static_cast<const CPartFile*>(pFile)->GetFullName())
			: pFile->GetFilePath();
		// IMPORTANT: do NOT pass FILE_FLAG_OVERLAPPED.  The handle is used by
		// multiple worker threads concurrently, each passing its own offset
		// in an OVERLAPPED struct — MSDN explicitly supports this as a
		// synchronous atomic seek+read (Raymond Chen, 2015-01-21).  Using
		// FILE_FLAG_OVERLAPPED would hit Wine's overlapped-disk-I/O path,
		// which is the sub-system the 0.70c rewrite was specifically trying
		// to avoid.
		// FILE_FLAG_SEQUENTIAL_SCAN is kept as a prefetcher hint.
		pFile->m_hRead = ::CreateFile(fullname, GENERIC_READ,
			FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (pFile->m_hRead == INVALID_HANDLE_VALUE) {
			theApp.QueueDebugLogLineEx(LOG_ERROR, _T("Failed to open \"%s\" for reading: %s")
				, (LPCTSTR)fullname, (LPCTSTR)GetErrorMessage(::GetLastError(), 1));
			return false;
		}
		pFile->bCompress = ShouldCompressBasedOnFilename(fullname);
	}
	return true;
}

void CUploadDiskIOThread::DissociateFile(CKnownFile *pFile)
{
	ASSERT(pFile);
	if (pFile->m_hRead != INVALID_HANDLE_VALUE) {
		VERIFY(::CloseHandle(pFile->m_hRead));
		pFile->m_hRead = INVALID_HANDLE_VALUE;
	}
}

void CUploadDiskIOThread::StartCreateNextBlockPackage(UploadingToClient_Struct *pUploadClientStruct,
	CTypedPtrList<CPtrList, OverlappedRead_Struct*> &outPendingReads,
	bool bSinglePass)
{
	if (pUploadClientStruct->m_bIOError || pUploadClientStruct->m_BlockRequests_queue.IsEmpty())
		return;
	// when calling this function we already have a lock on the uploadlist
	// (so pUploadClientStruct and its members are safe in terms of not getting deleted/changed)
	CUpDownClient *pClient = pUploadClientStruct->m_pClient;
	CClientReqSocket *pSock = pClient->socket;
	if (pSock == NULL || !pSock->IsConnected())
		return;

	// now also get a lock on the Block lists
	CSingleLock lockBlockLists(&pUploadClientStruct->m_csBlockListsLock, TRUE);
	// See if we can do an early return.
	// There may be no new blocks to load from disk and add to buffer, or buffer may be large enough already.

	uint64 nCurQueueSessionPayloadUp = pClient->GetQueueSessionPayloadUp();
	// GetQueueSessionPayloadUp is probably outdated so also add the value reported by the sockets as sent
	nCurQueueSessionPayloadUp += pSock->GetSentPayloadSinceLastCall(false);
	uint64 addedPayloadQueueSession = pClient->GetQueueSessionUploadAdded();
	// buffer at least 1 block (180KB) for normal uploads, and 5 blocks (~900KB) for fast uploads
	const uint32 nBufferLimit = (pClient->GetUploadDatarate() > BIGBUFFER_MINDATARATE) ? (5 * EMBLOCKSIZE + 1) : (EMBLOCKSIZE + 1);

	if (addedPayloadQueueSession > nCurQueueSessionPayloadUp && addedPayloadQueueSession - nCurQueueSessionPayloadUp >= nBufferLimit)
		return; // the buffered data is large enough already

	try {
		// Get more data if currently buffered was less than nBufferLimit Bytes.
		// When bSinglePass is true we break after one block so the caller can
		// round-robin across the other clients.
		while (!pUploadClientStruct->m_BlockRequests_queue.IsEmpty()
			&& (addedPayloadQueueSession <= nCurQueueSessionPayloadUp || addedPayloadQueueSession - nCurQueueSessionPayloadUp < nBufferLimit))
		{
			Requested_Block_Struct *currentblock = pUploadClientStruct->m_BlockRequests_queue.GetHead();
			if (!md4equ(currentblock->FileID, pClient->GetUploadFileID())) {
				// the UploadFileID differs. That's normally not a problem, we just switch it, but
				// we don't want to do so in this thread for synchronization issues. So return and wait
				// until the main thread which checks the block request periodically does so.
				// This should happen very rarely anyway so no problem performance wise
				theApp.QueueDebugLogLine(false, _T("CUploadDiskIOThread::StartCreateNextBlockPackage: Switched fileid, waiting for the main thread"));
				return;
			}

			CKnownFile *pFile = theApp.sharedfiles->GetFileByID(currentblock->FileID);
			if (pFile == NULL)
				throwCStr(_T("CUploadDiskIOThread::StartCreateNextBlockPackage: shared file not found"));
			if (pFile->bNoNewReads) //should be moving to incoming
				return;

			// we already have done all important sanity checks for the block request in the main thread when adding it; just redo some quick important ones
			if (currentblock->StartOffset >= currentblock->EndOffset || currentblock->EndOffset > pFile->GetFileSize())
				throwCStr(_T("Invalid Block Offsets"));
			uint64 uTogo = currentblock->EndOffset - currentblock->StartOffset;
			if (uTogo > EMBLOCKSIZE * 3)
				throw GetResString(IDS_ERR_LARGEREQBLOCK);

			if (!AssociateFile(pFile))
				throwCStr(_T("StartCreateNextBlockPackage: cannot open CKnownFile"));

			// Buffer first then struct, wrapped in unique_ptr so unwinding
			// disposes of both on any throw.
			std::unique_ptr<byte[]> buf(new byte[(size_t)uTogo]);
			std::unique_ptr<OverlappedRead_Struct> pOverlappedRead(new OverlappedRead_Struct());
			pOverlappedRead->pFile = pFile;
			pOverlappedRead->pUploadClientStruct = pUploadClientStruct;
			pOverlappedRead->uStartOffset = currentblock->StartOffset;
			pOverlappedRead->uEndOffset = currentblock->EndOffset;
			pOverlappedRead->pBuffer = buf.release();

			++pFile->nInUse;
			outPendingReads.AddTail(pOverlappedRead.release());

			addedPayloadQueueSession += uTogo;
			pClient->SetQueueSessionUploadAdded(addedPayloadQueueSession);
			pUploadClientStruct->m_DoneBlocks_list.AddHead(pUploadClientStruct->m_BlockRequests_queue.RemoveHead());

			if (bSinglePass)
				break;
		}
		return; //no errors
	} catch (const CString &ex) {
		theApp.QueueDebugLogLineEx(LOG_ERROR, GetResString(IDS_ERR_CLIENTERRORED), pClient->GetUserName(), (LPCTSTR)ex);
	} catch (CFileException *ex) {
		theApp.QueueDebugLogLineEx(LOG_ERROR, _T("Failed to create upload package for %s%s"), pClient->GetUserName(), (LPCTSTR)CExceptionStrDash(*ex));
		ex->Delete();
	}
	pUploadClientStruct->m_bIOError = true; // will let remove this client from the list in the main thread
}

void CUploadDiskIOThread::ReadCompletionRoutine(DWORD dwRead, const OverlappedRead_Struct *pOvRead)
{
	if (pOvRead == NULL) {
		ASSERT(0);
		return;
	}
	ASSERT(pOvRead->pFile);

	--pOvRead->pFile->nInUse;

	CKnownFile *pKnownFile = pOvRead->pFile;
	if (m_Run) {
		bool bReadError = !dwRead;
		if (bReadError)
			Debug(_T("  Completed read, dwRead=0\n"));
		else if (dwRead != pOvRead->uEndOffset - pOvRead->uStartOffset) {
			theApp.QueueDebugLogLineEx(LOG_ERROR, _T("ReadCompletionRoutine: Didn't read requested data count - wanted: %lu, read: %lu")
				, (DWORD)(pOvRead->uEndOffset - pOvRead->uStartOffset), dwRead);
			bReadError = true;
		}
		if (pKnownFile->m_hRead != INVALID_HANDLE_VALUE) { //discard data from closed files
			UploadingToClient_Struct *pStruct = pOvRead->pUploadClientStruct;
			// check if the client struct is still in the upload list (otherwise it is a deleted pointer)
			CCriticalSection *pcsUploadListRead = NULL;
			const CUploadingPtrList &rUploadList = theApp.uploadqueue->GetUploadListTS(&pcsUploadListRead);
			CSingleLock lockUploadListRead(pcsUploadListRead, TRUE);
			ASSERT(lockUploadListRead.IsLocked());
			bool bFound = (rUploadList.Find(pStruct) != NULL);

			// all important prechecks done, create the packets
			if (bFound && !bReadError) {
				// Keep the uploadlist locked while working with the client object.
				// Instead of sending the packets immediately, we store them
				// and send after we have released the uploadlist lock -
				// just to be sure there is no chance of a deadlock (now or in future version, also it doesn't cost us much)
				CPacketList packetsList;
				CUpDownClient *pClient = pStruct->m_pClient;
				CClientReqSocket *pSocket = pClient->socket;
				if (pSocket && pSocket->IsConnected()) {
					// Try to use compression whenever possible (see CreatePackedPackets notes)
					if (pKnownFile->bCompress)
						CreatePackedPackets(*pOvRead, packetsList);
					else
						CreateStandardPackets(*pOvRead, packetsList);

					m_bSignalThrottler.store(true);
				} else
					theApp.QueueDebugLogLineEx(LOG_ERROR, _T("ReadCompletionRoutine: Client has no connected socket, %s"), (LPCTSTR)pClient->DbgGetClientInfo(true));

				lockUploadListRead.Unlock();

				// now send out all packets we have made. By default, our socket object is not safe
				// to use now either, because we have no lock on itself (to make sure it is not deleted)
				// however the way we handle sockets, they cannot get deleted directly (takes 10s),
				// so this isn't a problem in our case
				while (!packetsList.IsEmpty() && pSocket != NULL) {
					Packet *packet = packetsList.RemoveHead();
					pSocket->SendPacket(packet, false, packet->uStatsPayLoad);
				}
			} else { // bReadError is true
				if (bFound)
					pStruct->m_bIOError = true;
				else
					theApp.QueueDebugLogLineEx(LOG_WARNING, _T("ReadCompletionRoutine: Client not found in uploadlist when reading finished; discarding block"));
				lockUploadListRead.Unlock();
			}
		}
	}

	// cleanup
	delete[] pOvRead->pBuffer;
	delete pOvRead;
}

bool CUploadDiskIOThread::ShouldCompressBasedOnFilename(const CString &strFileName)
{
	LPCTSTR pDot = ::PathFindExtension(strFileName);
	CString strExt(pDot + static_cast<int>(*pDot != _T('\0')));
	strExt.MakeLower();
	if (strExt == _T("avi"))
		return !thePrefs.GetDontCompressAvi();
	return strExt != _T("zip") && strExt != _T("rar") && strExt != _T("7z") && strExt != _T("cbz") && strExt != _T("cbr") && strExt != _T("ace") && strExt != _T("ogm");
}

void CUploadDiskIOThread::CreateStandardPackets(const OverlappedRead_Struct &OverlappedRead, CPacketList &rOutPacketList)
{
	const uchar *pucMD4FileHash = OverlappedRead.pFile->GetFileHash();
	bool bIsPartFile = OverlappedRead.pFile->IsPartFile();
	CString sDbgClientInfo;
	if (thePrefs.GetDebugClientTCPLevel() > 0)
		sDbgClientInfo = OverlappedRead.pUploadClientStruct->m_pClient->DbgGetClientInfo(true);

	uint32 togo = (uint32)(OverlappedRead.uEndOffset - OverlappedRead.uStartOffset);
	CMemFile memfile((BYTE*)OverlappedRead.pBuffer, togo);
	while (togo) {
		uint32 nPacketSize = (togo < 13000) ? togo : 10240u;
		togo -= nPacketSize;

		uint64 endpos = OverlappedRead.uEndOffset - togo;
		uint64 startpos = endpos - nPacketSize;

		LPCTSTR sOp;
		Packet *packet;
		if (endpos > _UI32_MAX) {
			packet = new Packet(OP_SENDINGPART_I64, nPacketSize + 32, OP_EMULEPROT, bIsPartFile);
			md4cpy(&packet->pBuffer[0], pucMD4FileHash);
			PokeUInt64(&packet->pBuffer[16], startpos);
			PokeUInt64(&packet->pBuffer[24], endpos);
			memfile.Read(&packet->pBuffer[32], nPacketSize);
			theStats.AddUpDataOverheadFileRequest(32);
			sOp = _T("OP_SendingPart_I64");
		} else {
			packet = new Packet(OP_SENDINGPART, nPacketSize + 24, OP_EDONKEYPROT, bIsPartFile);
			md4cpy(&packet->pBuffer[0], pucMD4FileHash);
			PokeUInt32(&packet->pBuffer[16], (uint32)startpos);
			PokeUInt32(&packet->pBuffer[20], (uint32)endpos);
			memfile.Read(&packet->pBuffer[24], nPacketSize);
			theStats.AddUpDataOverheadFileRequest(24);
			sOp = _T("OP_SendingPart");
		}
		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			Debug(_T(">>> %-20s to   %s; %s\n"), sOp, (LPCTSTR)sDbgClientInfo, (LPCTSTR)md4str(pucMD4FileHash));
			Debug(_T("  Start=%I64u  End=%I64u  Size=%u\n"), startpos, endpos, nPacketSize);
		}
		packet->uStatsPayLoad = nPacketSize;
		rOutPacketList.AddTail(packet);
	}
}

void CUploadDiskIOThread::CreatePackedPackets(const OverlappedRead_Struct &OverlappedRead, CPacketList &rOutPacketList)
{
	const uint64 uStartOffset = OverlappedRead.uStartOffset;
	const uint64 uEndOffset = OverlappedRead.uEndOffset;
	const uchar *pucMD4FileHash = OverlappedRead.pFile->GetFileHash();
	bool bIsPartFile = OverlappedRead.pFile->IsPartFile();

	uint32 togo = (uint32)(uEndOffset - uStartOffset);
	uLongf newsize = togo + 300;
	BYTE *output = new BYTE[newsize];

	// Use the lowest compression level 1 instead of the highest 9 because typically for 10240 blocks:
	// - compressed size difference is usually small enough (~4% for .exe, .avi, .pdf and 12% for .c text)
	// - time was 1.5-2.5 better
	// Of course, throughput of the deflate() routine depends on processor and data bytes,
	// but should not be the bottleneck because 50-70 MB/s rates were seen when using one CPU core.
	if (compress2(output, &newsize, OverlappedRead.pBuffer, togo, 1) != Z_OK || togo <= newsize) {
		delete[] output;
		CreateStandardPackets(OverlappedRead, rOutPacketList);
		return;
	}
	CString sDbgClientInfo;
	if (thePrefs.GetDebugClientTCPLevel() > 0)
		sDbgClientInfo = OverlappedRead.pUploadClientStruct->m_pClient->DbgGetClientInfo(true);

	CMemFile memfile(output, newsize);
	uint32 oldSize = togo;
	togo = newsize;

	uint32 totalPayloadSize = 0;

	while (togo) {
		uint32 nPacketSize = (togo < 13000) ? togo : 10240u;
		togo -= nPacketSize;
		Packet *packet;
		LPCTSTR sOp;
		if (uEndOffset > UINT32_MAX) {
			packet = new Packet(OP_COMPRESSEDPART_I64, nPacketSize + 28, OP_EMULEPROT, bIsPartFile);
			md4cpy(&packet->pBuffer[0], pucMD4FileHash);
			PokeUInt64(&packet->pBuffer[16], uStartOffset);
			PokeUInt32(&packet->pBuffer[24], newsize);
			memfile.Read(&packet->pBuffer[28], nPacketSize);
			sOp = _T("OP_CompressedPart_I64");
		} else {
			packet = new Packet(OP_COMPRESSEDPART, nPacketSize + 24, OP_EMULEPROT, bIsPartFile);
			md4cpy(&packet->pBuffer[0], pucMD4FileHash);
			PokeUInt32(&packet->pBuffer[16], (uint32)uStartOffset);
			PokeUInt32(&packet->pBuffer[20], newsize);
			memfile.Read(&packet->pBuffer[24], nPacketSize);
			sOp = _T("OP_CompressedPart");
		}

		if (thePrefs.GetDebugClientTCPLevel() > 0) {
			Debug(_T(">>> %-20s to   %s; %s\n"), sOp, (LPCTSTR)sDbgClientInfo, (LPCTSTR)md4str(pucMD4FileHash));
			Debug(_T("  Start=%I64u  BlockSize=%u  Size=%u\n"), uStartOffset, newsize, nPacketSize);
		}
		// approximate payload size
		uint32 payloadSize = togo ? nPacketSize * oldSize / newsize : oldSize - totalPayloadSize;

		totalPayloadSize += payloadSize;

		theStats.AddUpDataOverheadFileRequest(24);
		packet->uStatsPayLoad = payloadSize;
		rOutPacketList.AddTail(packet);
	}
	memfile.Close();
	delete[] output;
}

void CUploadDiskIOThread::WakeUpCall()
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_bNewData = true;
	}
	m_cv.notify_one();
}
