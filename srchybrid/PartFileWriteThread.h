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
#pragma once
#include <atomic>

struct PartFileBufferedData;

struct ToWrite
{
	CPartFile *pFile;
	PartFileBufferedData *pBuffer;
};

struct OverlappedWrite_Struct
{
	OVERLAPPED				oOverlap; // must be the first member
	CPartFile				*pFile;
	PartFileBufferedData	*pBuffer;
	POSITION				pos; // in m_listPendingIO
	DWORD					dwStart; // 97q: when the write was started, see WriteCompletionRoutine()
};

class CPartFileWriteThread : public CWinThread
{
	DECLARE_DYNCREATE(CPartFileWriteThread)
public:
	CPartFileWriteThread();
	~CPartFileWriteThread();
	CPartFileWriteThread(const CPartFileWriteThread&) = delete;
	CPartFileWriteThread& operator=(const CPartFileWriteThread&) = delete;
	CCriticalSection m_lockWriteList;

	void	EndThread();	//completionkey == 0
	void	WakeUpCall();	//completionkey == -1
	bool	IsRunning() const							{ return m_Run > 0; }
	bool	AddFile(CPartFile *pFile);
	static void	RemFile(CPartFile *pFile);
	// 97q: the periodic flush of a download to disk, run on a pool thread, see StartFlush()
	static uint32	StartFlush(CPartFile *pFile);
	static bool	TakeFlushResult(uint32 uJob, DWORD &dwError);
	static DWORD	WaitForFlushes(const CPartFile *pFile);
	static void	ForgetFlushes(const CPartFile *pFile);

	CCriticalSection m_lockFlushList;
	CList<ToWrite> m_FlushList;

private:
	static UINT AFX_CDECL RunProc(LPVOID pParam);
	UINT	RunInternal();

	BOOL	GetNextCompletion(DWORD &dwWrite, DWORD &dwError, ULONG_PTR &completionKey, OverlappedWrite_Struct *&pCurIO, DWORD dwWait);
	void	WriteBuffers();
	static void	FailWrite(const ToWrite &item, DWORD dwError);
	void	WriteCompletionRoutine(DWORD dwBytesWritten, DWORD dwError, const OverlappedWrite_Struct *pOvWrite);
	static VOID CALLBACK FlushProc(PTP_CALLBACK_INSTANCE pInstance, PVOID pParam) noexcept;

	CList<ToWrite>	m_listToWrite;
	CTypedPtrList<CPtrList, OverlappedWrite_Struct*>	m_listPendingIO;

	CEvent	m_eventThreadEnded;
	HANDLE	m_hPort;
	std::atomic<char> m_Run; //0 - not running; 1 - idle; 2 - processing
	std::atomic<char> m_bNewData;
};