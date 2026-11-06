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
#include "StdAfx.h"
#include <atlbase.h>
#include <netfw.h>
#include "FirewallCheck.h"
#include "emule.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "Opcodes.h"
#include "emuledlg.h"
#include "UserMsgs.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace
{
	// An enabled inbound rule that can apply to this program on TCP or UDP.
	struct SFwRule
	{
		CString	sName;
		CString	sApplication;	// as the rule stores it; empty when the rule is for every program
		CString	sLocalPorts;
		CString	sRemoteAddresses;
		long	lProfiles;
		long	lProtocol;
		bool	bAllow;
	};

	enum EFwVerdict
	{
		FWV_OFF,			// the firewall does not run on this profile
		FWV_BLOCK_ALL,		// "Block all incoming connections", no rule counts
		FWV_BLOCK_RULE,		// a block rule matches; it wins over any allow rule
		FWV_ALLOW_RULE,		// an allow rule matches, from any remote address
		FWV_ALLOW_LIMITED,	// only allow rules limited to some remote addresses match
		FWV_DEFAULT_ALLOW,	// no rule matches, and the profile lets the rest in
		FWV_NO_RULE			// no rule matches, and the profile blocks the rest
	};

	CString BstrToString(BSTR bstr)
	{
		return bstr ? CString(bstr) : CString();
	}

	bool SamePath(const CString &sRulePath, const CString &sOwnPath)
	{
		TCHAR szExpanded[MAX_PATH];
		DWORD dwLen = ::ExpandEnvironmentStrings(sRulePath, szExpanded, _countof(szExpanded));
		LPCTSTR pszPath = (dwLen > 0 && dwLen <= _countof(szExpanded)) ? szExpanded : (LPCTSTR)sRulePath;
		return ::CompareStringOrdinal(pszPath, -1, sOwnPath, -1, TRUE) == CSTR_EQUAL;
	}

	// LocalPorts is "*" or a comma separated list of ports, port ranges and keywords (RPC, Teredo,
	// IPHTTPS, ...); a keyword never covers an eMule port.
	bool PortListHas(const CString &sPorts, uint16 nPort)
	{
		if (sPorts.IsEmpty() || sPorts == _T("*"))
			return true;
		for (int iPos = 0;;) {
			CString sToken(sPorts.Tokenize(_T(","), iPos));
			if (iPos < 0)
				return false;
			sToken.Trim();
			LPCTSTR pszFirst = sToken;
			LPTSTR pszEnd;
			unsigned long uFirst = _tcstoul(pszFirst, &pszEnd, 10);
			if (pszEnd == pszFirst)
				continue;
			unsigned long uLast = uFirst;
			if (*pszEnd == _T('-')) {
				LPCTSTR pszLast = pszEnd + 1;
				uLast = _tcstoul(pszLast, &pszEnd, 10);
				if (pszEnd == pszLast)
					continue;
			}
			if (*pszEnd == _T('\0') && uFirst <= nPort && nPort <= uLast)
				return true;
		}
	}

	bool RuleCovers(const SFwRule &rule, long lProfile, long lProtocol, uint16 nPort)
	{
		if ((rule.lProfiles & lProfile) == 0)
			return false;
		if (rule.lProtocol == NET_FW_IP_PROTOCOL_ANY)
			return true;
		return rule.lProtocol == lProtocol && PortListHas(rule.sLocalPorts, nPort);
	}

	LPCTSTR ProfileName(long lProfile)
	{
		switch (lProfile) {
		case NET_FW_PROFILE2_DOMAIN:
			return _T("domain");
		case NET_FW_PROFILE2_PRIVATE:
			return _T("private");
		default:
			return _T("public");
		}
	}

	bool ReadRules(INetFwPolicy2 *pPolicy, const CString &sOwnPath, CArray<SFwRule> &aRules)
	{
		CComPtr<INetFwRules> pRules;
		CComPtr<IUnknown> pUnknown;
		if (FAILED(pPolicy->get_Rules(&pRules)) || FAILED(pRules->get__NewEnum(&pUnknown)))
			return false;
		CComQIPtr<IEnumVARIANT> pEnum(pUnknown);
		if (!pEnum)
			return false;

		for (CComVariant var; pEnum->Next(1, &var, NULL) == S_OK; var.Clear()) {
			if (var.vt != VT_DISPATCH || var.pdispVal == NULL)
				continue;
			CComQIPtr<INetFwRule> pRule(var.pdispVal);
			if (!pRule)
				continue;

			VARIANT_BOOL bEnabled = VARIANT_FALSE;
			NET_FW_RULE_DIRECTION eDirection = NET_FW_RULE_DIR_OUT;
			NET_FW_ACTION eAction = NET_FW_ACTION_BLOCK;
			SFwRule rule{};
			if (FAILED(pRule->get_Enabled(&bEnabled)) || bEnabled == VARIANT_FALSE
				|| FAILED(pRule->get_Direction(&eDirection)) || eDirection != NET_FW_RULE_DIR_IN
				|| FAILED(pRule->get_Action(&eAction))
				|| FAILED(pRule->get_Protocol(&rule.lProtocol))
				|| FAILED(pRule->get_Profiles(&rule.lProfiles)))
			{
				continue;
			}
			if (rule.lProtocol != NET_FW_IP_PROTOCOL_TCP && rule.lProtocol != NET_FW_IP_PROTOCOL_UDP && rule.lProtocol != NET_FW_IP_PROTOCOL_ANY)
				continue;

			// A rule bound to a service applies to that service only; one bound to another
			// program applies to that program only.
			CComBSTR bstr;
			if (SUCCEEDED(pRule->get_ServiceName(&bstr)) && bstr.Length() > 0)
				continue;
			bstr.Empty();
			if (FAILED(pRule->get_ApplicationName(&bstr)))
				continue;
			if (bstr.Length() > 0 && !SamePath(BstrToString(bstr), sOwnPath))
				continue;
			rule.sApplication = BstrToString(bstr);

			bstr.Empty();
			if (rule.lProtocol != NET_FW_IP_PROTOCOL_ANY && SUCCEEDED(pRule->get_LocalPorts(&bstr)))
				rule.sLocalPorts = BstrToString(bstr);
			bstr.Empty();
			if (SUCCEEDED(pRule->get_RemoteAddresses(&bstr)))
				rule.sRemoteAddresses = BstrToString(bstr);
			bstr.Empty();
			if (SUCCEEDED(pRule->get_Name(&bstr)))
				rule.sName = BstrToString(bstr);
			rule.bAllow = (eAction == NET_FW_ACTION_ALLOW);
			aRules.Add(rule);
		}
		return true;
	}

	EFwVerdict Evaluate(INetFwPolicy2 *pPolicy, const CArray<SFwRule> &aRules, long lProfile, long lProtocol, uint16 nPort, const SFwRule *&pDecidingRule)
	{
		pDecidingRule = NULL;
		const NET_FW_PROFILE_TYPE2 eProfile = static_cast<NET_FW_PROFILE_TYPE2>(lProfile);
		VARIANT_BOOL bValue = VARIANT_TRUE;
		if (SUCCEEDED(pPolicy->get_FirewallEnabled(eProfile, &bValue)) && bValue == VARIANT_FALSE)
			return FWV_OFF;
		bValue = VARIANT_FALSE;
		if (SUCCEEDED(pPolicy->get_BlockAllInboundTraffic(eProfile, &bValue)) && bValue != VARIANT_FALSE)
			return FWV_BLOCK_ALL;

		// A block rule wins over every allow rule, but only one for every remote address is
		// sure to stop the peers.
		const SFwRule *pLimitedAllow = NULL;
		for (INT_PTR i = 0; i < aRules.GetCount(); ++i) {
			const SFwRule &rule = aRules[i];
			if (!RuleCovers(rule, lProfile, lProtocol, nPort))
				continue;
			const bool bAnyRemote = rule.sRemoteAddresses.IsEmpty() || rule.sRemoteAddresses == _T("*");
			if (!rule.bAllow) {
				if (bAnyRemote) {
					pDecidingRule = &rule;
					return FWV_BLOCK_RULE;
				}
			} else if (bAnyRemote) {
				if (pDecidingRule == NULL)
					pDecidingRule = &rule;
			} else if (pLimitedAllow == NULL)
				pLimitedAllow = &rule;
		}
		if (pDecidingRule != NULL)
			return FWV_ALLOW_RULE;
		if (pLimitedAllow != NULL) {
			pDecidingRule = pLimitedAllow;
			return FWV_ALLOW_LIMITED;
		}

		NET_FW_ACTION eDefault = NET_FW_ACTION_BLOCK;
		if (SUCCEEDED(pPolicy->get_DefaultInboundAction(eProfile, &eDefault)) && eDefault == NET_FW_ACTION_ALLOW)
			return FWV_DEFAULT_ALLOW;
		return FWV_NO_RULE;
	}

	bool IsBlockedVerdict(EFwVerdict eVerdict)
	{
		return eVerdict == FWV_BLOCK_ALL || eVerdict == FWV_BLOCK_RULE || eVerdict == FWV_NO_RULE;
	}

	// The values go between double quotes on a cmd.exe command line, where neither a quote
	// nor a percent sign can be passed through safely.
	bool QuotableForCmd(const CString &s)
	{
		return s.FindOneOf(_T("\"%")) < 0;
	}

	// What opening a blocked port takes, as netsh commands: block rules made for this program
	// (what Windows makes when its "allow access" prompt is cancelled) are turned into allow
	// rules, and a port no rule covers gets an allow rule of its own. Nothing is done for a
	// profile that blocks everything, or for a block rule that applies to every program.
	class CFixCommand
	{
	public:
		CFixCommand(const CString &sOwnPath, bool bFixable)
			: m_sOwnPath(sOwnPath)
			, m_bFixable(bFixable && QuotableForCmd(sOwnPath))
		{
		}

		void Add(EFwVerdict eVerdict, const SFwRule *pRule, const CArray<SFwRule> &aRules, long lProfile, long lProtocol, LPCTSTR pszProtocol, uint16 nPort)
		{
			switch (eVerdict) {
			case FWV_BLOCK_ALL:
				m_bFixable = false;
				break;
			case FWV_BLOCK_RULE:
				if (pRule->sApplication.IsEmpty()) {
					m_bFixable = false;
					break;
				}
				for (INT_PTR i = 0; i < aRules.GetCount(); ++i) {
					const SFwRule &rule = aRules[i];
					if (rule.bAllow || rule.sApplication.IsEmpty() || !RuleCovers(rule, lProfile, lProtocol, nPort))
						continue;
					if (QuotableForCmd(rule.sName) && QuotableForCmd(rule.sApplication))
						AddCommand(_T("set rule name=\"") + rule.sName + _T("\" dir=in program=\"") + rule.sApplication + _T("\" new action=allow"));
					else
						m_bFixable = false;
				}
				break;
			case FWV_NO_RULE:
				{
					CString sCommand;
					sCommand.Format(_T("add rule name=\"eMule %s %u\" dir=in action=allow program=\"%s\" protocol=%s localport=%u profile=any"), pszProtocol, nPort, (LPCTSTR)m_sOwnPath, pszProtocol, nPort);
					AddCommand(sCommand);
				}
				break;
			default:
				break;
			}
		}

		// The command line for cmd.exe, empty when the ports cannot be opened this way.
		CString GetCmdLine() const
		{
			if (!m_bFixable || m_asCommands.IsEmpty())
				return CString();
			CString sCmdLine(_T("/s /c \""));
			for (INT_PTR i = 0; i < m_asCommands.GetCount(); ++i) {
				if (i > 0)
					sCmdLine += _T(" & ");
				sCmdLine += _T("netsh advfirewall firewall ") + m_asCommands[i];
			}
			return sCmdLine + _T('"');
		}

	private:
		void AddCommand(const CString &sCommand)
		{
			for (INT_PTR i = 0; i < m_asCommands.GetCount(); ++i)
				if (m_asCommands[i] == sCommand)
					return;
			m_asCommands.Add(sCommand);
		}

		const CString	m_sOwnPath;
		CStringArray	m_asCommands;
		bool			m_bFixable;
	};

	// Returns the log line for a verdict, and whether it is a warning.
	bool FormatVerdict(EFwVerdict eVerdict, const SFwRule *pRule, long lProfile, LPCTSTR pszProtocol, uint16 nPort, CString &sLine)
	{
		LPCTSTR pszProfile = ProfileName(lProfile);
		switch (eVerdict) {
		case FWV_OFF:
			sLine.Format(_T("Windows Firewall is off on the %s network profile: it does not filter inbound %s port %u"), pszProfile, pszProtocol, nPort);
			return false;
		case FWV_BLOCK_ALL:
			sLine.Format(_T("Windows Firewall blocks inbound %s port %u: the %s network profile blocks all incoming connections, whatever its rules say"), pszProtocol, nPort, pszProfile);
			return true;
		case FWV_BLOCK_RULE:
			sLine.Format(_T("Windows Firewall blocks inbound %s port %u on the %s network profile, by rule \"%s\""), pszProtocol, nPort, pszProfile, (LPCTSTR)pRule->sName);
			return true;
		case FWV_ALLOW_RULE:
			sLine.Format(_T("Windows Firewall allows inbound %s port %u on the %s network profile, by rule \"%s\""), pszProtocol, nPort, pszProfile, (LPCTSTR)pRule->sName);
			return false;
		case FWV_ALLOW_LIMITED:
			sLine.Format(_T("Windows Firewall allows inbound %s port %u on the %s network profile only from %s, by rule \"%s\""), pszProtocol, nPort, pszProfile, (LPCTSTR)pRule->sRemoteAddresses, (LPCTSTR)pRule->sName);
			return true;
		case FWV_DEFAULT_ALLOW:
			sLine.Format(_T("Windows Firewall allows inbound %s port %u on the %s network profile: no rule matches it, and the profile lets in what no rule blocks"), pszProtocol, nPort, pszProfile);
			return false;
		default:
			sLine.Format(_T("Windows Firewall blocks inbound %s port %u on the %s network profile: no rule allows it, and the profile blocks what no rule allows"), pszProtocol, nPort, pszProfile);
			return true;
		}
	}
}

CFirewallCheck::CFirewallCheck()
	: m_pThread()
	, m_evStop(FALSE, TRUE)
	, m_evRecheck(FALSE, FALSE)
	, m_hFixProcess()
	, m_bBlocked()
{
}

CFirewallCheck::~CFirewallCheck()
{
	if (m_pThread != NULL) {
		m_evStop.SetEvent();
		::WaitForSingleObject(m_pThread->m_hThread, INFINITE);
		delete m_pThread;
	}
	if (m_hFixProcess != NULL)
		::CloseHandle(m_hFixProcess);
}

void CFirewallCheck::Start()
{
	if (m_pThread != NULL)
		return;
	m_pThread = AfxBeginThread(RunProc, this, THREAD_PRIORITY_BELOW_NORMAL, 0, CREATE_SUSPENDED);
	if (m_pThread != NULL) {
		m_pThread->m_bAutoDelete = FALSE;
		m_pThread->ResumeThread();
	}
}

UINT AFX_CDECL CFirewallCheck::RunProc(LPVOID pParam)
{
	DbgSetThreadName("FirewallCheck");
	if (SUCCEEDED(::CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		static_cast<CFirewallCheck*>(pParam)->Run();
		::CoUninitialize();
	}
	return 0;
}

// Windows may change the rules after the first check - a cancelled "allow access" prompt, for
// one - so the check runs again every minute, and the log gets the result only when it changes.
void CFirewallCheck::Run()
{
	// A policy that cannot be read at all (Wine, for one) will not be readable a minute later.
	if (!Check(true, false))
		return;
	const HANDLE ahEvents[] = {m_evStop, m_evRecheck};
	for (;;) {
		const DWORD dwWait = ::WaitForMultipleObjects(_countof(ahEvents), ahEvents, FALSE, MIN2MS(1));
		if (dwWait == WAIT_OBJECT_0)
			break;
		bool bAfterFix = false;
		if (dwWait == WAIT_OBJECT_0 + 1) {
			// Check again as soon as the netsh commands are done.
			m_csState.Lock();
			const HANDLE hProcess = m_hFixProcess;
			m_hFixProcess = NULL;
			m_csState.Unlock();
			if (hProcess != NULL) {
				const HANDLE ahProcess[] = {m_evStop, hProcess};
				const DWORD dwDone = ::WaitForMultipleObjects(_countof(ahProcess), ahProcess, FALSE, SEC2MS(30));
				::CloseHandle(hProcess);
				if (dwDone == WAIT_OBJECT_0)
					break;
				bAfterFix = true;
			}
		}
		Check(false, bAfterFix);
	}
}

bool CFirewallCheck::IsBlocked(CString &sFixCmdLine)
{
	CSingleLock lock(&m_csState, TRUE);
	sFixCmdLine = m_sFixCmdLine;
	return m_bBlocked;
}

// Runs the netsh commands that open the ports through cmd.exe as administrator: the UAC prompt
// is for them only, and eMule itself goes on without elevation.
void CFirewallCheck::OpenPorts(HWND hWndParent)
{
	CString sFixCmdLine;
	if (!IsBlocked(sFixCmdLine) || sFixCmdLine.IsEmpty())
		return;
	TCHAR szCmd[MAX_PATH];
	const UINT uLen = ::GetSystemDirectory(szCmd, _countof(szCmd));
	if (uLen == 0 || uLen + 8 >= _countof(szCmd))
		return;
	_tcscat_s(szCmd, _T("\\cmd.exe"));

	SHELLEXECUTEINFO sei = {};
	sei.cbSize = (DWORD)sizeof sei;
	sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
	sei.hwnd = hWndParent;
	sei.lpVerb = _T("runas");
	sei.lpFile = szCmd;
	sei.lpParameters = sFixCmdLine;
	sei.nShow = SW_HIDE;
	if (!::ShellExecuteEx(&sei)) {
		const DWORD dwError = ::GetLastError();
		if (dwError == ERROR_CANCELLED)
			theApp.QueueLogLine(false, _T("Windows Firewall: the rules were not changed, administrator rights were not given"));
		else
			theApp.QueueLogLineEx(LOG_WARNING, _T("Windows Firewall: the rules cannot be changed (error %lu)"), dwError);
		return;
	}
	theApp.QueueDebugLogLine(false, _T("Windows Firewall: run as administrator: cmd.exe %s"), (LPCTSTR)sFixCmdLine);
	if (sei.hProcess != NULL) {
		m_csState.Lock();
		if (m_hFixProcess != NULL)
			::CloseHandle(m_hFixProcess);
		m_hFixProcess = sei.hProcess;
		m_csState.Unlock();
	}
	m_evRecheck.SetEvent();
}

bool CFirewallCheck::Check(bool bFirst, bool bAfterFix)
{
	CComPtr<INetFwPolicy2> pPolicy;
	HRESULT hr = pPolicy.CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER);
	long lProfiles = 0;
	if (SUCCEEDED(hr))
		hr = pPolicy->get_CurrentProfileTypes(&lProfiles);
	if (FAILED(hr)) {
		if (bFirst)
			theApp.QueueDebugLogLine(false, _T("Windows Firewall: its policy cannot be read (0x%08lx), inbound ports not checked"), hr);
		return false;
	}

	TCHAR szOwnPath[MAX_PATH];
	DWORD dwLen = ::GetModuleFileName(NULL, szOwnPath, _countof(szOwnPath));
	if (dwLen == 0 || dwLen >= _countof(szOwnPath)) {
		if (bFirst)
			theApp.QueueDebugLogLine(false, _T("Windows Firewall: the program path cannot be read, inbound ports not checked"));
		return false;
	}
	CArray<SFwRule> aRules;
	if (!ReadRules(pPolicy, szOwnPath, aRules)) {
		if (bFirst)
			theApp.QueueDebugLogLine(false, _T("Windows Firewall: its rules cannot be read, inbound ports not checked"));
		return false;
	}

	// The ports are read on every check: they can be changed in the options while eMule runs.
	const uint16 nTCPPort = thePrefs.GetPort();
	const uint16 nUDPPort = thePrefs.GetUDPPort();

	// Every line of the result is built first, so that it can be compared with the last one.
	CStringArray asLines;
	CArray<bool> abWarnings;
	CString sLine;
	bool bBlocked = false;

	// Rules from group policy, or the policy forbidding local rules, are not in what the
	// rule collection returns.
	NET_FW_MODIFY_STATE eModifyState = NET_FW_MODIFY_STATE_OK;
	if (SUCCEEDED(pPolicy->get_LocalPolicyModifyState(&eModifyState)) && eModifyState != NET_FW_MODIFY_STATE_OK) {
		sLine.Format(_T("Windows Firewall is managed by group policy (state %d): the check below sees only the local rules"), static_cast<int>(eModifyState));
		asLines.Add(sLine);
		abWarnings.Add(true);
	}
	CFixCommand fix(szOwnPath, eModifyState == NET_FW_MODIFY_STATE_OK);

	static const long s_alProfiles[] = {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
	for (unsigned i = 0; i < _countof(s_alProfiles); ++i) {
		const long lProfile = s_alProfiles[i];
		if ((lProfiles & lProfile) == 0)
			continue;
		const SFwRule *pRule;
		EFwVerdict eVerdict = Evaluate(pPolicy, aRules, lProfile, NET_FW_IP_PROTOCOL_TCP, nTCPPort, pRule);
		abWarnings.Add(FormatVerdict(eVerdict, pRule, lProfile, _T("TCP"), nTCPPort, sLine));
		asLines.Add(sLine);
		bBlocked |= IsBlockedVerdict(eVerdict);
		fix.Add(eVerdict, pRule, aRules, lProfile, NET_FW_IP_PROTOCOL_TCP, _T("TCP"), nTCPPort);
		if (nUDPPort != 0) {
			eVerdict = Evaluate(pPolicy, aRules, lProfile, NET_FW_IP_PROTOCOL_UDP, nUDPPort, pRule);
			abWarnings.Add(FormatVerdict(eVerdict, pRule, lProfile, _T("UDP"), nUDPPort, sLine));
			asLines.Add(sLine);
			bBlocked |= IsBlockedVerdict(eVerdict);
			fix.Add(eVerdict, pRule, aRules, lProfile, NET_FW_IP_PROTOCOL_UDP, _T("UDP"), nUDPPort);
		}
	}

	CString sResult;
	for (INT_PTR i = 0; i < asLines.GetCount(); ++i)
		sResult += asLines[i] + _T('\n');
	if (sResult == m_sLastResult) {
		if (bAfterFix && bBlocked)
			theApp.QueueLogLineEx(LOG_WARNING, _T("Windows Firewall still blocks inbound connections after the change of its rules"));
		return true;
	}
	m_sLastResult = sResult;

	// The main window shows a bar while a port is blocked; it asks for the state on its own once
	// it is created.
	m_csState.Lock();
	m_bBlocked = bBlocked;
	m_sFixCmdLine = bBlocked ? fix.GetCmdLine() : CString();
	m_csState.Unlock();
	if (theApp.emuledlg != NULL && theApp.emuledlg->m_hWnd != NULL)
		::PostMessage(theApp.emuledlg->m_hWnd, UM_FIREWALL_STATE, 0, 0);

	if (!bFirst)
		theApp.QueueLogLine(false, _T("Windows Firewall: the inbound check gives a different result from the last one"));
	for (INT_PTR i = 0; i < asLines.GetCount(); ++i) {
		if (abWarnings[i])
			theApp.QueueLogLineEx(LOG_WARNING, _T("%s"), (LPCTSTR)asLines[i]);
		else
			theApp.QueueLogLine(false, _T("%s"), (LPCTSTR)asLines[i]);
	}
	return true;
}
