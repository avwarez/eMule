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
#pragma once
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

class Packet;
class CUpDownClient;
typedef CTypedPtrList<CPtrList, Packet*> CPacketList;

struct UploadingToClient_Struct;

// Reads remain synchronous: the handle is opened WITHOUT FILE_FLAG_OVERLAPPED,
// but each ReadFile is invoked with an OVERLAPPED struct carrying the offset.
// Per MSDN (ReadFile documentation; Raymond Chen "The Old New Thing",
// 2015-01-21) this form is a fully synchronous atomic seek+read: the kernel
// starts the read at OVERLAPPED.Offset and does not return until the read
// completes.  No event handle is used, no async completion, no IOCP.
//
// Why this matters for Wine compatibility: Wine maps ReadFile on a synchronous
// handle to a single pread() syscall — POSIX-native and free of the long-
// standing bugs in Wine's overlapped-disk-I/O path (dlls/ntdll async machinery,
// APC delivery, hEvent signaling on EOF, GetOverlappedResult regressions).
// Multiple worker threads can call ReadFile on the same handle concurrently
// because the offset is overridden per-call by OVERLAPPED.Offset (no shared
// file-pointer race).
struct OverlappedRead_Struct
{
	CKnownFile				*pFile;
	UploadingToClient_Struct *pUploadClientStruct;
	uint64					uStartOffset;
	uint64					uEndOffset;
	BYTE					*pBuffer;
};

class CUploadDiskIOThread : public CWinThread
{
	DECLARE_DYNCREATE(CUploadDiskIOThread)
public:
	CUploadDiskIOThread();
	~CUploadDiskIOThread();
	CUploadDiskIOThread(const CUploadDiskIOThread&) = delete;
	CUploadDiskIOThread& operator=(const CUploadDiskIOThread&) = delete;

	void		EndThread();
	void		WakeUpCall();
	static void	DissociateFile(CKnownFile *pFile);

private:
	static UINT AFX_CDECL RunProc(LPVOID pParam);
	UINT		RunInternal();

	bool		AssociateFile(CKnownFile *pFile);
	static bool ShouldCompressBasedOnFilename(const CString &strFileName);
	// bSinglePass: if true, add at most ONE block to outPendingReads for this
	// client.  RunInternal loops with bSinglePass=true so the pending-read
	// list ends up round-robin across clients instead of grouped per client,
	// which preserves per-slot fairness when workers pick jobs in order.
	void		StartCreateNextBlockPackage(UploadingToClient_Struct *pUploadClientStruct,
					CTypedPtrList<CPtrList, OverlappedRead_Struct*> &outPendingReads,
					bool bSinglePass);
	void		ReadCompletionRoutine(DWORD dwRead, const OverlappedRead_Struct *pOvRead);

	static void CreatePackedPackets(const OverlappedRead_Struct &OverlappedRead, CPacketList &rOutPacketList);
	static void CreateStandardPackets(const OverlappedRead_Struct &OverlappedRead, CPacketList &rOutPacketList);

	// Worker pool: the coordinator (CWinThread::RunInternal) fills a shared
	// work queue during Phase 1; N worker threads drain it in Phase 2, each
	// calling ReadFile synchronously.  Concurrency therefore lives in
	// userspace, not in kernel async machinery, so every primitive used is
	// one Wine implements on top of pthread/pread without any async path.
	void		WorkerProc();
	void		StopWorkers();

	CEvent						m_eventThreadEnded;

	// Coordinator sync (with EndThread / WakeUpCall)
	std::mutex					m_mutex;
	std::condition_variable		m_cv;
	std::atomic<int>	m_Run; //0 - not running; 1 - idle; 2 - processing
	bool				m_bNewData;			// protected by m_mutex
	bool				m_bStop;			// protected by m_mutex
	std::atomic<bool>	m_bSignalThrottler;	// set by workers, read/cleared by coordinator

	// Worker pool
	std::vector<std::thread>	m_workers;
	std::mutex						m_queueMutex;
	std::condition_variable			m_cvQueue;		// workers wait for jobs
	std::condition_variable			m_cvBatchDone;	// coordinator waits for batch completion
	CTypedPtrList<CPtrList, OverlappedRead_Struct*> m_workQueue;
	int								m_nInFlight;	// jobs dequeued-but-not-completed (under m_queueMutex)
	bool							m_bWorkersStop;	// under m_queueMutex
};
