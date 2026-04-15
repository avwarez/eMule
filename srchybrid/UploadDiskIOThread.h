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

class Packet;
class CUpDownClient;
typedef CTypedPtrList<CPtrList, Packet*> CPacketList;

struct UploadingToClient_Struct;

// No OVERLAPPED member: reads are now synchronous (no IOCP).
// uStartOffset is used directly with SetFilePointerEx before ReadFile.
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
	void		StartCreateNextBlockPackage(UploadingToClient_Struct *pUploadClientStruct,
					CTypedPtrList<CPtrList, OverlappedRead_Struct*> &outPendingReads);
	void		ReadCompletionRoutine(DWORD dwRead, const OverlappedRead_Struct *pOvRead);

	static void CreatePackedPackets(const OverlappedRead_Struct &OverlappedRead, CPacketList &rOutPacketList);
	static void CreateStandardPackets(const OverlappedRead_Struct &OverlappedRead, CPacketList &rOutPacketList);

	CEvent						m_eventThreadEnded;
	std::mutex					m_mutex;
	std::condition_variable		m_cv;

	std::atomic<int>	m_Run; //0 - not running; 1 - idle; 2 - processing
	bool				m_bNewData;		// protected by m_mutex
	bool				m_bSignalThrottler;
};
