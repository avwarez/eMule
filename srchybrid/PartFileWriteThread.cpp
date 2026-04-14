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
// SyncWrite — cross-platform positional file write
//
// Writes 'count' bytes from 'buf' at byte offset 'offset' in 'hFile'.
// Does NOT change the file pointer (equivalent to POSIX pwrite(2)).
//
// Windows implementation: WriteFile with an OVERLAPPED struct whose Offset
// fields carry the target position.  Because hFile is opened WITHOUT
// FILE_FLAG_OVERLAPPED, the call is fully synchronous — it blocks until
// the kernel has completed the write and returns the byte count directly.
// No I/O Completion Port is involved.
//
// Linux / future native port: replace this function body with
//     return (DWORD)::pwrite(pFile->m_fdWrite, buf, count, (off_t)offset);
// and change AddFile / RemFile to open/close a POSIX file descriptor instead
// of a HANDLE.  No other code in this file needs to change.
// ---------------------------------------------------------------------------
static DWORD SyncWrite(HANDLE hFile, const void *buf, DWORD count, uint64_t offset)
{
	OVERLAPPED ov = {};
	ov.Offset     = static_cast<DWORD>(offset);
	ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
	DWORD written = 0;
	if (!::WriteFile(hFile, buf, count, &written, &ov))
		return 0;
	return written;
}

// ---------------------------------------------------------------------------

CPartFileWriteThread::CPartFileWriteThread()
	: m_bNewData(false)
	, m_Run(RUN_STOP)
	// m_thread is default-constructed here; started in the body below so that
	// all other members are guaranteed initialised before the thread runs.
{
	m_thread = std::thread([this] { RunInternal(); });
}

CPartFileWriteThread::~CPartFileWriteThread()
{
	ASSERT(m_Run == RUN_STOP);
	// Safety net: EndThread() should have been called before deletion.
	if (m_thread.joinable())
		EndThread();
}

// ---------------------------------------------------------------------------
// Thread control
// ---------------------------------------------------------------------------

void CPartFileWriteThread::EndThread()
{
	{
		std::lock_guard<std::mutex> lock(m_cvMutex);
		m_Run    = RUN_STOP;
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

	m_Run = RUN_IDLE;

	for (;;) {
		// Wait until there is work to do or we are asked to stop.
		{
			std::unique_lock<std::mutex> lock(m_cvMutex);
			m_cv.wait(lock, [this] { return m_bNewData || m_Run == RUN_STOP; });

			if (m_Run == RUN_STOP)
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
				theApp.QueueDebugLogLineEx(LOG_WARNING,
					_T("WriteBuffers error: %lu"), pBuffer->dwError);
				RemFile(pFile);
			}
		} else {
			// File space pre-allocation: we wrote a single zero byte at
			// (end-of-desired-size) to force the OS to extend the file,
			// then truncate back to the real size.
			if (written == 1) {
				::FlushFileBuffers(pFile->m_hWrite);
				pFile->m_hpartfile.SetLength(pBuffer->start);
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
			pFile->SetStatus(PS_ERROR);
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
