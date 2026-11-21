//this file is part of eMule
//Copyright (C)2020-2026 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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
#include "updownclient.h"
#include "PartFileWriteThread.h"
#include "emule.h"
#include "partfile.h"
#include "log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define RUN_STOP	0
#define RUN_IDLE	1
#define RUN_WORK	2
#define WAKEUP		((ULONG_PTR)(~0))

// 97q: a write that takes this long is logged, see WriteCompletionRoutine()
#define SLOW_WRITE_MS	SEC2MS(20)

// 97q: a periodic flush, see StartFlush()
struct FlushJob
{
	explicit FlushJob(const CPartFile *pFile)
		: pOwner(pFile), hFile(INVALID_HANDLE_VALUE), strName(pFile->GetFileName()), dwStart(::GetTickCount()), dwError(0), bDone(false), nRefs(2)
	{
	}

	const CPartFile *pOwner;	// only compared, never used: the download may be gone when the job ends
	HANDLE	hFile;		// a duplicate of CPartFile::m_hWrite, closed by the job
	CString	strName;
	DWORD	dwStart;
	DWORD	dwError;	// set before bDone
	std::atomic<bool> bDone;
	std::atomic<int> nRefs;	// the pool thread and the job list, so that the pool thread needs no lock
};

static CCriticalSection s_lockHandle; // CPartFile::m_hWrite is closed by either thread and duplicated by the main thread
static CCriticalSection s_lockFlushJobs;
static CMap<uint32, uint32, FlushJob*, FlushJob*> s_mapFlushJobs;
static uint32 s_uLastFlushJob;
static std::atomic<int> s_nFlushesRunning;
static std::atomic<bool> s_bFlushesEnding; // the application is closing: theApp may be gone by the time a flush ends

static void ReleaseFlushJob(FlushJob *pJob)
{
	if (--pJob->nRefs == 0)
		delete pJob;
}

// 97q: GetQueuedCompletionStatus() also returns FALSE when the packet it hands over is a write
// that failed. That write is handed on with its error, so that the download it was for is told
// and the thread goes on; FALSE is returned only when nothing was dequeued (the drain is over,
// or the port itself failed).
BOOL CPartFileWriteThread::GetNextCompletion(DWORD &dwWrite, DWORD &dwError, ULONG_PTR &completionKey, OverlappedWrite_Struct *&pCurIO, DWORD dwWait)
{
	pCurIO = NULL;
	dwError = 0;
	if (::GetQueuedCompletionStatus(m_hPort, &dwWrite, &completionKey, (LPOVERLAPPED*)&pCurIO, dwWait))
		return TRUE;
	dwError = ::GetLastError();
	if (pCurIO != NULL) {
		dwWrite = 0;
		return TRUE;
	}
	if (dwError != WAIT_TIMEOUT)
		theApp.QueueLogLineEx(LOG_ERROR, _T("Download disk I/O: waiting for disk writes failed, error %lu: %s - no download is written to disk until eMule restarts")
			, dwError, (LPCTSTR)GetErrorMessage(dwError, 1));
	::SetLastError(dwError);
	return FALSE;
}

IMPLEMENT_DYNCREATE(CPartFileWriteThread, CWinThread)

CPartFileWriteThread::CPartFileWriteThread()
	: m_eventThreadEnded(FALSE, TRUE)
	, m_hPort()
	, m_Run(RUN_STOP)
	, m_bNewData()
{
	AfxBeginThread(RunProc, (LPVOID)this, THREAD_PRIORITY_BELOW_NORMAL);
}

CPartFileWriteThread::~CPartFileWriteThread()
{
	ASSERT(!m_hPort && !m_Run);
}

UINT AFX_CDECL CPartFileWriteThread::RunProc(LPVOID pParam)
{
	DbgSetThreadName("PartWriteThread");
	InitThreadLocale();
	return pParam ? static_cast<CPartFileWriteThread*>(pParam)->RunInternal() : 1;
}

void CPartFileWriteThread::EndThread()
{
	m_Run = RUN_STOP;
	PostQueuedCompletionStatus(m_hPort, 0, 0, NULL);
	m_eventThreadEnded.Lock();

	// 97q: a periodic flush still running is given some time to end; one stuck on a disk that
	// does not answer is left to delete itself
	s_bFlushesEnding = true;
	for (int i = 0; s_nFlushesRunning > 0 && i < 100; ++i)
		::Sleep(50);
	CSingleLock lock(&s_lockFlushJobs, TRUE);
	for (POSITION pos = s_mapFlushJobs.GetStartPosition(); pos != NULL;) {
		uint32 uJob;
		FlushJob *pJob;
		s_mapFlushJobs.GetNextAssoc(pos, uJob, pJob);
		ReleaseFlushJob(pJob);
	}
	s_mapFlushJobs.RemoveAll();
}

UINT CPartFileWriteThread::RunInternal()
{
	m_hPort = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 1);
	if (!m_hPort)
		return ::GetLastError();

	DWORD dwWrite = 0;
	DWORD dwError = 0;
	ULONG_PTR completionKey = 0;
	OverlappedWrite_Struct *pCurIO = NULL;
	m_Run = RUN_IDLE;
	while (m_Run
		&& GetNextCompletion(dwWrite, dwError, completionKey, pCurIO, INFINITE)
		&& completionKey)
	{
		m_Run = RUN_WORK;
		//move buffer list into the local storage
		if (!m_FlushList.IsEmpty()) {
			m_lockFlushList.Lock();
			while (!m_FlushList.IsEmpty())
				m_listToWrite.AddTail(m_FlushList.RemoveHead());
			m_bNewData.exchange(0);
			m_lockFlushList.Unlock();
		}
		//start new writes
		WriteBuffers();
		//check completed I/O
		do {
			if (!completionKey)
				break;
			if (completionKey != WAKEUP) //ignore wakeups
				WriteCompletionRoutine(dwWrite, dwError, pCurIO);
		} while (GetNextCompletion(dwWrite, dwError, completionKey, pCurIO, 0));

		if (!completionKey) //thread termination
			break;
		m_Run = RUN_IDLE;
		// 97q: also with writes pending, as a slow one must not hold up the others
		if (m_bNewData.exchange(0))
			PostQueuedCompletionStatus(m_hPort, 0, WAKEUP, NULL);
	}
	m_Run = RUN_STOP;

	//Improper termination of asynchronous I/O follows...
	//close file handles to release I/O completion port
	while (!m_listPendingIO.IsEmpty())
		WriteCompletionRoutine(0, 0, m_listPendingIO.RemoveHead());

	::CloseHandle(m_hPort);
	m_hPort = 0;

	m_eventThreadEnded.SetEvent();
	return 0;
}

void CPartFileWriteThread::WriteBuffers()
{
	//process internal list
	while (!m_listToWrite.IsEmpty() && m_Run) {
		const ToWrite &item = m_listToWrite.RemoveHead();
		PartFileBufferedData *pBuffer = item.pBuffer;
		ASSERT(pBuffer->end >= pBuffer->start && (pBuffer->data || pBuffer->end == pBuffer->start)); //verifies allocation request too

		CPartFile *pFile = item.pFile;
		if (AddFile(pFile)) {
			//initiate write
			OverlappedWrite_Struct *pOvWrite = new OverlappedWrite_Struct;
			pOvWrite->oOverlap.Internal = 0;
			pOvWrite->oOverlap.InternalHigh = 0;
			//pOvWrite->oOverlap.Offset = LODWORD(currentblock->StartOffset);
			//pOvWrite->oOverlap.OffsetHigh = HIDWORD(currentblock->StartOffset);
			*(uint64*)&pOvWrite->oOverlap.Offset = pBuffer->start;
			pOvWrite->oOverlap.hEvent = 0;
			pOvWrite->pFile = pFile;
			pOvWrite->pBuffer = pBuffer;
			pOvWrite->dwStart = ::GetTickCount();

			static const BYTE zero = 0;
			if (!::WriteFile(pFile->m_hWrite, pBuffer->data ? pBuffer->data : &zero, (DWORD)(pBuffer->end - pBuffer->start + 1), NULL, (LPOVERLAPPED)pOvWrite)) {
				DWORD dwError = ::GetLastError();
				if (dwError != ERROR_IO_PENDING) {
					delete pOvWrite;
					theApp.QueueDebugLogLineEx(LOG_WARNING, _T("WriteBuffers error: %lu"), dwError);
					FailWrite(item, dwError);
					// 97q: closing the handle under the writes still going on would fail them too;
					// it is closed, to be opened again by the next write, only when none is left
					if (pFile->m_iWrites <= 0)
						RemFile(pFile);
					continue;
				}
			}
			pOvWrite->pos = m_listPendingIO.AddTail(pOvWrite);
			++pFile->m_iWrites;
		} else {
			const DWORD dwError = ::GetLastError();
			theApp.QueueDebugLogLineEx(LOG_ERROR, _T("WriteBuffers error: CPartFile cannot be written"));
			FailWrite(item, dwError);
		}
	}
}

// 97q: a buffer that could not be written goes back to its download as failed, with the error that
// says why, and the download is paused (see CPartFile::FlushBuffersExceptionHandler()); the request
// that allocates the whole file is not in the download's buffer list, so it is dropped here
void CPartFileWriteThread::FailWrite(const ToWrite &item, DWORD dwError)
{
	if (item.pBuffer->data) {
		item.pBuffer->dwError = dwError ? dwError : (DWORD)ERROR_WRITE_FAULT;
		item.pBuffer->flushed = PB_ERROR;
	} else
		delete item.pBuffer;
}

void CPartFileWriteThread::WriteCompletionRoutine(DWORD dwBytesWritten, DWORD dwError, const OverlappedWrite_Struct *pOvWrite)
{
	if (pOvWrite == NULL) {
		ASSERT(0);
		return;
	}
	CPartFile *pFile = pOvWrite->pFile;
	if (m_Run) {
		PartFileBufferedData *pBuffer = pOvWrite->pBuffer;
		const DWORD dwWrite = (DWORD)(pBuffer->end - pBuffer->start + 1);

		// 97q: a disk that is slow to answer, or about to fail, is worth knowing about
		const DWORD dwTook = ::GetTickCount() - pOvWrite->dwStart;
		if (dwTook >= SLOW_WRITE_MS && pFile)
			theApp.QueueLogLineEx(LOG_WARNING, _T("Download disk I/O: writing \"%s\" at %I64u-%I64u took %lu ms - the disk is slow to answer")
				, (LPCTSTR)pFile->GetFileName(), pBuffer->start, pBuffer->end, dwTook);

		ASSERT(pOvWrite->pos);
		m_listPendingIO.RemoveAt(pOvWrite->pos);
		// 97q: the write is over whether it succeeded or not; a count left up would keep the
		// download from ever completing (see CPartFile::FlushBuffer())
		if (pFile)
			--pFile->m_iWrites;
		if (dwBytesWritten && dwWrite == dwBytesWritten) {
			if (pFile) {
				if (pBuffer->data) { //write data
					ASSERT(pBuffer->flushed == PB_PENDING && pFile->m_iWrites >= 0);
					pBuffer->flushed = PB_WRITTEN;
				} else { //full file allocation
					ASSERT(dwBytesWritten == 1);
					if (pFile->m_hWrite != INVALID_HANDLE_VALUE) {
						::FlushFileBuffers(pFile->m_hWrite);
						pFile->m_hpartfile.SetLength(pBuffer->start); //truncate the extra byte
					}
					delete pBuffer;
				}
			}
		} else {
			theApp.QueueDebugLogLineEx(LOG_WARNING, _T("Download disk I/O: writing %lu bytes at %I64u: %lu written, error %lu")
				, dwWrite, pBuffer->start, dwBytesWritten, dwError);
			FailWrite(ToWrite{pFile, pBuffer}, dwError);
		}
	} else if (pFile)
		RemFile(pFile);

	delete pOvWrite;
}

bool CPartFileWriteThread::AddFile(CPartFile *pFile)
{
	ASSERT(m_hPort && m_Run);
	if (pFile && pFile->m_hWrite == INVALID_HANDLE_VALUE) {
		const CString sPartFile(RemoveFileExtension(pFile->GetFullName()));
		pFile->m_hWrite = ::CreateFile(sPartFile, GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		// 97q: the download is told through its failed buffer, from the error kept for the caller
		// (see WriteBuffers()), and is paused by the main thread rather than set here
		if (pFile->m_hWrite == INVALID_HANDLE_VALUE) {
			const DWORD dwError = ::GetLastError();
			theApp.QueueDebugLogLineEx(LOG_ERROR, _T("Failed to open \"%s\" for overlapped write: %s"), (LPCTSTR)sPartFile, (LPCTSTR)GetErrorMessage(dwError, 1));
			::SetLastError(dwError);
			return false;
		}
		if (m_hPort != ::CreateIoCompletionPort(pFile->m_hWrite, m_hPort, (ULONG_PTR)pFile, 0)) {
			const DWORD dwError = ::GetLastError();
			theApp.QueueDebugLogLineEx(LOG_ERROR, _T("Failed to associate \"%s\" with IOCP: %s"), (LPCTSTR)sPartFile, (LPCTSTR)GetErrorMessage(dwError, 1));
			RemFile(pFile);
			::SetLastError(dwError);
			return false;
		}
	}
	return true;
}

void CPartFileWriteThread::RemFile(CPartFile *pFile)
{
	ASSERT(pFile);
	CSingleLock lock(&s_lockHandle, TRUE); // 97q: see StartFlush()
	if (pFile->m_hWrite != INVALID_HANDLE_VALUE) {
		VERIFY(::CloseHandle(pFile->m_hWrite));
		pFile->m_hWrite = INVALID_HANDLE_VALUE;
	}
}

// 97q: FlushFileBuffers() returns only once the disk has the data, so the periodic flush made the
// main thread, and the window, wait for the disk every 31 seconds for each download. It runs on a
// pool thread instead, on a duplicate of the handle that the write thread may close meanwhile, and
// the main thread takes its result later (see CPartFile::Process()). Returns 0 if nothing was started.
uint32 CPartFileWriteThread::StartFlush(CPartFile *pFile)
{
	FlushJob *pJob = new FlushJob(pFile);
	s_lockHandle.Lock();
	const bool bDuplicated = pFile->m_hWrite != INVALID_HANDLE_VALUE
		&& ::DuplicateHandle(::GetCurrentProcess(), pFile->m_hWrite, ::GetCurrentProcess(), &pJob->hFile, 0, FALSE, DUPLICATE_SAME_ACCESS);
	s_lockHandle.Unlock();
	if (!bDuplicated) {
		delete pJob;
		return 0;
	}

	s_lockFlushJobs.Lock();
	if (!++s_uLastFlushJob)
		++s_uLastFlushJob;
	const uint32 uJob = s_uLastFlushJob;
	s_mapFlushJobs[uJob] = pJob;
	s_lockFlushJobs.Unlock();

	++s_nFlushesRunning;
	if (!::TrySubmitThreadpoolCallback(FlushProc, pJob, NULL))
		FlushProc(NULL, pJob); //no pool thread to be had: flush here, as before
	return uJob;
}

VOID CALLBACK CPartFileWriteThread::FlushProc(PTP_CALLBACK_INSTANCE pInstance, PVOID pParam) noexcept
{
	if (pInstance)
		::CallbackMayRunLong(pInstance); //a slow disk may keep this thread for long
	FlushJob *pJob = static_cast<FlushJob*>(pParam);
	DWORD dwError = 0;
	if (!::FlushFileBuffers(pJob->hFile)) {
		dwError = ::GetLastError();
		if (!dwError)
			dwError = ERROR_WRITE_FAULT;
	}
	VERIFY(::CloseHandle(pJob->hFile));

	const DWORD dwTook = ::GetTickCount() - pJob->dwStart;
	if (dwTook >= SLOW_WRITE_MS && !s_bFlushesEnding) //set before EndThread() waits, so it waits for this line
		theApp.QueueLogLineEx(LOG_WARNING, _T("Download disk I/O: flushing \"%s\" to disk took %lu ms - the disk is slow to answer")
			, (LPCTSTR)pJob->strName, dwTook);

	pJob->dwError = dwError;
	pJob->bDone = true;
	--s_nFlushesRunning;
	ReleaseFlushJob(pJob);
}

// 97q: true once the flush is over, with its error; the job is gone after that
bool CPartFileWriteThread::TakeFlushResult(uint32 uJob, DWORD &dwError)
{
	dwError = 0;
	CSingleLock lock(&s_lockFlushJobs, TRUE);
	FlushJob *pJob;
	if (!s_mapFlushJobs.Lookup(uJob, pJob))
		return true; //dropped on shutdown
	if (!pJob->bDone)
		return false;
	dwError = pJob->dwError;
	s_mapFlushJobs.RemoveKey(uJob);
	ReleaseFlushJob(pJob);
	return true;
}

// 97q: called by the thread that hashes a download whole on completion (see CPartFile::CompleteFile(),
// which leaves the flushes on the list for it). Waits until no flush of the download is running and
// returns the first error of them.
DWORD CPartFileWriteThread::WaitForFlushes(const CPartFile *pFile)
{
	DWORD dwError = 0;
	for (bool bRunning = true; bRunning && !s_bFlushesEnding;) {
		bRunning = false;
		CArray<uint32> aDone;
		CSingleLock lock(&s_lockFlushJobs, TRUE);
		for (POSITION pos = s_mapFlushJobs.GetStartPosition(); pos != NULL;) {
			uint32 uJob;
			FlushJob *pJob;
			s_mapFlushJobs.GetNextAssoc(pos, uJob, pJob);
			if (pJob->pOwner != pFile)
				continue;
			if (pJob->bDone) {
				if (!dwError)
					dwError = pJob->dwError;
				aDone.Add(uJob);
			} else
				bRunning = true;
		}
		for (INT_PTR i = aDone.GetCount(); --i >= 0;) {
			FlushJob *pJob = s_mapFlushJobs[aDone[i]];
			s_mapFlushJobs.RemoveKey(aDone[i]);
			ReleaseFlushJob(pJob);
		}
		lock.Unlock();
		if (bRunning)
			::Sleep(50);
	}
	return dwError;
}

// 97q: the download is deleted; a flush still running deletes its job when it ends
void CPartFileWriteThread::ForgetFlushes(const CPartFile *pFile)
{
	CArray<uint32> aJobs;
	CSingleLock lock(&s_lockFlushJobs, TRUE);
	for (POSITION pos = s_mapFlushJobs.GetStartPosition(); pos != NULL;) {
		uint32 uJob;
		FlushJob *pJob;
		s_mapFlushJobs.GetNextAssoc(pos, uJob, pJob);
		if (pJob->pOwner == pFile)
			aJobs.Add(uJob);
	}
	for (INT_PTR i = aJobs.GetCount(); --i >= 0;) {
		FlushJob *pJob = s_mapFlushJobs[aJobs[i]];
		s_mapFlushJobs.RemoveKey(aJobs[i]);
		ReleaseFlushJob(pJob);
	}
}

void CPartFileWriteThread::WakeUpCall()
{
	// 97q: pending I/O does not make posting unnecessary: a write that takes long
	// (a disk that does not answer) would hold up every other download until it ends
	if (m_Run == RUN_IDLE)
		PostQueuedCompletionStatus(m_hPort, 0, WAKEUP, NULL);
	else
		m_bNewData.exchange(1);
}