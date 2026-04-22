//this file is part of eMule
//Copyright (C)2020-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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
#include "DownloadQueue.h"
#include "partfile.h"
#include "log.h"
#include "preferences.h"
#include "Statistics.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// ---------------------------------------------------------------------------
// SyncWrite — positional file write (equivalent to POSIX pwrite(2))
//
// Writes 'count' bytes from 'buf' at byte offset 'offset' in 'hFile'.
// hFile must be opened WITHOUT FILE_FLAG_OVERLAPPED (synchronous handle).
// Because m_hWrite is exclusively owned by the write thread, moving the
// file pointer via SetFilePointerEx is perfectly safe.
//
// WHY NOT OVERLAPPED:
//   Passing a non-NULL OVERLAPPED to WriteFile on a *synchronous* handle
//   (no FILE_FLAG_OVERLAPPED) is documented to use Offset/OffsetHigh for
//   positioning on Windows, but Wine implements it inconsistently:
//   - Some Wine versions return ERROR_IO_PENDING on synchronous handles,
//     causing the caller to see a failure and set PS_ERROR.
//   - Other Wine versions ignore the OVERLAPPED offset entirely and write
//     at the current file pointer, placing all chunks at offset 0 and
//     corrupting the part file — the hash check then fails → PS_ERROR.
//   SetFilePointerEx + WriteFile(NULL overlapped) is fully portable and
//   avoids both problems.
// ---------------------------------------------------------------------------
static DWORD SyncWrite(HANDLE hFile, const void *buf, DWORD count, uint64_t offset)
{
	LARGE_INTEGER liPos;
	liPos.QuadPart = static_cast<LONGLONG>(offset);
	if (!::SetFilePointerEx(hFile, liPos, NULL, FILE_BEGIN))
		return 0;
	DWORD written = 0;
	if (!::WriteFile(hFile, buf, count, &written, NULL))
		return 0;
	return written;
}

// ---------------------------------------------------------------------------

CPartFileWriteThread::CPartFileWriteThread()
	: m_bNewData(false)
	, m_bStop(false)
	, m_Run(RUN_IDLE)   // initialised to IDLE *before* the thread starts so
	                    // that IsRunning() is consistent from the first instant
	                    // and EndThread() called from another thread before the
	                    // first iteration never loses the stop signal.
	// m_thread is default-constructed here; started in the body below so that
	// all other members are guaranteed initialised before the thread runs.
{
	m_thread = std::thread([this] { RunInternal(); });
}

CPartFileWriteThread::~CPartFileWriteThread()
{
	// FIX Bug #3: the ASSERT is guarded by joinable() so it does not fire when
	// EndThread() was already called (the normal path).  It fires only when the
	// destructor is reached with the thread still running, which is the
	// programmer-error we want to catch in debug builds.
	// In release builds the cleanup proceeds unconditionally so we never
	// std::terminate() with a joinable thread.
	if (m_thread.joinable()) {
		ASSERT(m_bStop); // EndThread() should have been called first
		EndThread();
	}
}

// ---------------------------------------------------------------------------
// Thread control
// ---------------------------------------------------------------------------

void CPartFileWriteThread::EndThread()
{
	// FIX: use a dedicated stop flag instead of overloading m_Run.
	// The worker thread writes m_Run = RUN_WORK / RUN_IDLE outside the cv lock
	// while running WriteBuffers(); if we wrote m_Run = RUN_STOP here, a race
	// would let the worker clobber it with RUN_IDLE on the next loop iteration,
	// and .join() would block forever because the cv predicate would never
	// see RUN_STOP again.  m_bStop is touched only here (set) and in the cv
	// predicate (read), so nothing can overwrite it.
	{
		std::lock_guard<std::mutex> lock(m_cvMutex);
		m_bStop    = true;
		m_bNewData = false;
	}
	m_cv.notify_one();
	if (m_thread.joinable())
		m_thread.join();
}

void CPartFileWriteThread::WakeUpCall()
{
	{
		std::lock_guard<std::mutex> lock(m_cvMutex);
		m_bNewData = true;
	}
	m_cv.notify_one();
}

// ---------------------------------------------------------------------------
// Thread body
// ---------------------------------------------------------------------------

void CPartFileWriteThread::RunInternal()
{
	DbgSetThreadName("PartWriteThread");
	InitThreadLocale();
	// m_Run is already RUN_IDLE (set by the constructor before thread launch).
	// Writing it again here would create a race with EndThread() if the
	// destructor is called between thread start and this line.

	for (;;) {
		// Wait until there is work to do or we are asked to stop.
		{
			std::unique_lock<std::mutex> lock(m_cvMutex);
			m_cv.wait(lock, [this] { return m_bNewData || m_bStop; });

			if (m_bStop)
				break;

			m_bNewData = false;
		}

		m_Run = RUN_WORK;

		// Drain the shared FlushList into our private list under the lock,
		// then release it so the main thread can keep adding without blocking.
		if (!m_FlushList.IsEmpty()) {
			m_lockFlushList.Lock();
			while (!m_FlushList.IsEmpty())
				m_listToWrite.AddTail(m_FlushList.RemoveHead());
			m_lockFlushList.Unlock();
		}

		WriteBuffers();

		m_Run = RUN_IDLE;
	}

	m_Run = RUN_STOP;
}

// ---------------------------------------------------------------------------
// Write logic
// ---------------------------------------------------------------------------

void CPartFileWriteThread::WriteBuffers()
{
	while (!m_listToWrite.IsEmpty()) {
		const ToWrite &item = m_listToWrite.RemoveHead();
		PartFileBufferedData *pBuffer = item.pBuffer;
		CPartFile            *pFile   = item.pFile;

		ASSERT(pBuffer->end >= pBuffer->start
			&& (pBuffer->data || pBuffer->end == pBuffer->start));

		if (!AddFile(pFile)) {
			// Could not open the file for writing.
			if (pBuffer->data) {
				pBuffer->dwError  = ::GetLastError();
				pBuffer->flushed  = PB_ERROR;
			} else
				delete pBuffer; // allocation request — discard
			continue;
		}

		const DWORD   dwSize = (DWORD)(pBuffer->end - pBuffer->start + 1);
		static const BYTE zero = 0;
		const void   *data   = pBuffer->data ? pBuffer->data : &zero;

		const DWORD written = SyncWrite(pFile->m_hWrite, data, dwSize, pBuffer->start);

		if (pBuffer->data) {
			// Normal data write.
			if (written == dwSize) {
				pBuffer->flushed = PB_WRITTEN;
			} else {
				pBuffer->dwError = ::GetLastError();
				pBuffer->flushed = PB_ERROR;
				// Log disk-full immediately so the user sees it in real time.
				// Any other I/O error is logged later by FlushBuffersExceptionHandler.
				// ERROR_DISK_FULL (112) and ERROR_HANDLE_DISK_FULL (39) are both
				// mapped from ENOSPC by Wine, so this check works on Wine/Linux too.
				if (pBuffer->dwError == ERROR_DISK_FULL || pBuffer->dwError == ERROR_HANDLE_DISK_FULL)
					theApp.QueueDebugLogLineEx(LOG_ERROR,
						_T("Write failed — disk full while writing \"%s\""),
						(LPCTSTR)pFile->GetFileName());
				else
					theApp.QueueDebugLogLineEx(LOG_WARNING,
						_T("WriteBuffers error: %lu"), pBuffer->dwError);
				RemFile(pFile);
			}
		} else {
			// File space pre-allocation: we wrote a single zero byte at
			// (end-of-desired-size) to force the OS to extend the file,
			// then truncate back to the real size.
			//
			// WHY m_hWrite instead of m_hpartfile:
			//   m_hpartfile is a CFile object owned by the main thread.
			//   Calling SetLength() on it from the write thread is a race
			//   condition. Under Wine, two open handles to the same file
			//   can have stale file-size caches, so the truncation may be
			//   lost or applied to the wrong size.
			//   We truncate via m_hWrite (exclusively ours) using
			//   SetFilePointerEx + SetEndOfFile, which is always correct.
			if (written == 1) {
				::FlushFileBuffers(pFile->m_hWrite);
				LARGE_INTEGER liTrunc;
				liTrunc.QuadPart = static_cast<LONGLONG>(pBuffer->start);
				if (::SetFilePointerEx(pFile->m_hWrite, liTrunc, NULL, FILE_BEGIN))
					::SetEndOfFile(pFile->m_hWrite);
			}
			delete pBuffer;
		}
	}
}

// ---------------------------------------------------------------------------
// File handle management
// ---------------------------------------------------------------------------

bool CPartFileWriteThread::AddFile(CPartFile *pFile)
{
	ASSERT(m_Run > RUN_STOP);
	if (pFile && pFile->m_hWrite == INVALID_HANDLE_VALUE) {
		const CString sPartFile(RemoveFileExtension(pFile->GetFullName()));

		// Open without FILE_FLAG_OVERLAPPED: SyncWrite() performs positional
		// writes synchronously, so no completion port is needed.
		pFile->m_hWrite = ::CreateFile(sPartFile,
			GENERIC_WRITE,
			FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_SEQUENTIAL_SCAN,
			NULL);

		if (pFile->m_hWrite == INVALID_HANDLE_VALUE) {
			theApp.QueueDebugLogLineEx(LOG_ERROR,
				_T("Failed to open \"%s\" for write: %s"),
				(LPCTSTR)sPartFile,
				(LPCTSTR)GetErrorMessage(::GetLastError(), 1));
			// FIX: SetStatus() updates the UI; calling it from the write thread
			// is a cross-thread GUI access.  _SetStatus() only stores the status;
			// the main thread will pick up PS_ERROR on the next update tick.
			pFile->_SetStatus(PS_ERROR);
			return false;
		}
	}
	return pFile != nullptr;
}

/*static*/ void CPartFileWriteThread::RemFile(CPartFile *pFile)
{
	ASSERT(pFile);
	if (pFile->m_hWrite != INVALID_HANDLE_VALUE) {
		VERIFY(::CloseHandle(pFile->m_hWrite));
		pFile->m_hWrite = INVALID_HANDLE_VALUE;
	}
}
