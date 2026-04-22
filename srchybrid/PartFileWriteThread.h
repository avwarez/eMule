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
#pragma once
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

struct PartFileBufferedData;
class CPartFile;

struct ToWrite
{
	CPartFile			*pFile;
	PartFileBufferedData *pBuffer;
};

// Cross-platform note: CPartFileWriteThread uses std::thread and std::condition_variable
// instead of CWinThread/IOCP.  The actual file writes use SyncWrite() (defined in the .cpp),
// which wraps WriteFile+OVERLAPPED on Windows and can be replaced by pwrite(2) on Linux
// without touching any other code.
class CPartFileWriteThread
{
public:
	CPartFileWriteThread();
	~CPartFileWriteThread();
	CPartFileWriteThread(const CPartFileWriteThread&) = delete;
	CPartFileWriteThread& operator=(const CPartFileWriteThread&) = delete;

	// Accessed directly by PartFile.cpp — keep layout compatible
	CCriticalSection	m_lockFlushList;
	CList<ToWrite>		m_FlushList;

	void	EndThread();
	void	WakeUpCall();
	bool	IsRunning() const		{ return m_Run > RUN_STOP; }
	bool	AddFile(CPartFile *pFile);
	static void RemFile(CPartFile *pFile);

private:
	void	RunInternal();
	void	WriteBuffers();

	CList<ToWrite>			m_listToWrite;

	// Declare synchronisation primitives before m_thread so they are fully
	// constructed before the thread lambda can access them.
	std::mutex				m_cvMutex;
	std::condition_variable	m_cv;
	bool					m_bNewData;
	bool					m_bStop;	// dedicated stop flag, protected by m_cvMutex
	std::atomic<int>		m_Run;	// RUN_STOP=0, RUN_IDLE=1, RUN_WORK=2

	std::thread				m_thread;	// must be last: started in constructor body

	static constexpr int RUN_STOP = 0;
	static constexpr int RUN_IDLE = 1;
	static constexpr int RUN_WORK = 2;
};
