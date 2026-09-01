//this file is part of eMule
//Copyright (C)2026 eMule contributors
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
#include "TimeTrace.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace {
	// Timestamps are relative to the first use so that the multiplication by
	// 1000000 below cannot overflow, whatever the machine uptime is.
	struct CTTClock
	{
		CTTClock()
		{
			LARGE_INTEGER li;
			li.QuadPart = 0;
			::QueryPerformanceFrequency(&li);
			llFreq = li.QuadPart ? li.QuadPart : 1;
			li.QuadPart = 0;
			::QueryPerformanceCounter(&li);
			llStart = li.QuadPart;
		}
		LONGLONG llFreq;
		LONGLONG llStart;
	};

	const CTTClock g_ttClock;

	// theVerboseLog is a plain FILE* wrapper with no lock of its own, and it is
	// written here from the main thread and from the part file write thread, so
	// every TT line is serialized through this.
	CCriticalSection g_ttLock;
}

uint64 TTNow()
{
	LARGE_INTEGER liNow;
	liNow.QuadPart = 0;
	::QueryPerformanceCounter(&liNow);
	const LONGLONG llTicks = liNow.QuadPart - g_ttClock.llStart;
	return (uint64)(llTicks / g_ttClock.llFreq) * 1000000ull
		+ (uint64)(llTicks % g_ttClock.llFreq * 1000000 / g_ttClock.llFreq);
}

void TTLog(LPCTSTR pszFmt, ...)
{
	TCHAR szMsg[512];
	va_list argp;
	va_start(argp, pszFmt);
	_vsntprintf(szMsg, _countof(szMsg), pszFmt, argp);
	va_end(argp);
	szMsg[_countof(szMsg) - 1] = _T('\0');

	g_ttLock.Lock();
	theVerboseLog.Logf(_T("%s"), szMsg);
	g_ttLock.Unlock();
}

void TTSuppressed(int iEvent)
{
#ifndef EMULE_TIMETRACE
	(void)iEvent;
#else
	static LPCTSTR const s_apszEvent[TTS_COUNT] = { _T("PUMP"), _T("RECV"), _T("WRITE"), _T("WBUF"), _T("WTDONE") };
	static volatile LONG s_alCount[TTS_COUNT];
	static uint64 s_auLastReport[TTS_COUNT];

	if (iEvent < 0 || iEvent >= TTS_COUNT)
		return;
	const LONG lCount = ::InterlockedIncrement(&s_alCount[iEvent]);
	const uint64 uNow = TTNow();
	if (uNow >= s_auLastReport[iEvent] + TT_SUPPRESS_US) {
		s_auLastReport[iEvent] = uNow;
		::InterlockedExchange(&s_alCount[iEvent], 0);
		TT("SUPPR|ev=%s|n=%ld", s_apszEvent[iEvent], lCount);
	}
#endif
}

CTTScope::CTTScope(LPCTSTR pszEvent)
	: m_pszEvent(pszEvent)
	, m_uStart(TTNow())
{
}

CTTScope::~CTTScope()
{
	const uint64 uNow = TTNow();
	TTLog(_T("TT|%I64u|%lu|%s|us=%I64u"), uNow, ::GetCurrentThreadId(), m_pszEvent, uNow - m_uStart);
}