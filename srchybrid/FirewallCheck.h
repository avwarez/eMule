//this file is part of eMule
//Copyright (C)2002-2026 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#pragma once

// Reads the Windows Firewall policy on a thread of its own and logs, for the TCP and the UDP port
// and for each network profile in use, whether inbound connections reach this program - and if
// not, what stops them: the firewall blocking everything, a block rule (the one Windows makes when
// its "allow access" prompt is cancelled), an allow rule limited to some remote addresses, or no
// rule at all. The check runs again every minute and logs the result again only when it changes;
// the main window is told when the ports get blocked or open again. Changes the rules only when
// the user asks for it, through OpenPorts().
class CFirewallCheck
{
public:
	CFirewallCheck();
	~CFirewallCheck();

	void Start();
	bool IsBlocked(CString &sFixCmdLine);	// sFixCmdLine is empty when OpenPorts() can do nothing
	void OpenPorts(HWND hWndParent);

private:
	static UINT AFX_CDECL RunProc(LPVOID pParam);
	void Run();
	bool Check(bool bFirst, bool bAfterFix);

	CWinThread	*m_pThread;
	CEvent		m_evStop;
	CEvent		m_evRecheck;
	CString		m_sLastResult;

	CCriticalSection m_csState;	// guards the members below
	HANDLE		m_hFixProcess;
	CString		m_sFixCmdLine;
	bool		m_bBlocked;
};
