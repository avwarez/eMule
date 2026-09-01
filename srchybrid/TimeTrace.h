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
#pragma once

// Purely observational time tracing for the main thread and the part file
// write thread. Every measurement point goes to the existing verbose log file
// (eMule_Verbose.log) through theVerboseLog, NOT through DebugLog()/
// AddDebugLogLine()/QueueDebugLogLine(): those end up in CemuleDlg::AddLogText,
// which synchronously feeds a rich edit control on the main thread - the very
// latency being measured.
//
// Two preferences are needed to get the file at all: Verbose=1 and
// SaveDebugToDisk=1 in preferences.ini ("Verbose" and "Debug to disk" in the
// options). The file rotates at MaxLogFileSize, 1 MB by default, and a trace
// fills that in half a minute, so raise it before capturing or the beginning
// of the trace is lost.
//
// Line format, one per measurement point, parsable by tools/tt_report.py:
//   TT|<microseconds>|<thread id>|<EVENT>|<key>=<value>|...
// preceded by the date stamp CLogFile::Logf() puts on every line.

// Comment out the following line to remove every measurement point.
#define EMULE_TIMETRACE

// Emission thresholds. High frequency events are emitted only above these;
// what is dropped is counted and reported once per TT_SUPPRESS_US as a SUPPR
// line, so no measurement point is silently lost.
#define TT_PUMP_MIN_US		200		// PUMP: one message dispatch
#define TT_RECV_MIN_US		200		// RECV: one socket read
#define TT_WRITE_MIN_US		200		// WRITE: issuing one overlapped write
#define TT_WBUF_EVERY		64		// WBUF: one line every N buffered items
#define TT_WTDONE_EVERY		64		// WTDONE: one line every N completions
#define TT_SUPPRESS_US		1000000	// how often a suppressed counter is reported

enum ETTSuppressed : int	// one counter per throttled event
{
	TTS_PUMP,
	TTS_RECV,
	TTS_WRITE,
	TTS_WBUF,
	TTS_WTDONE,
	TTS_COUNT
};

uint64	TTNow();				// microseconds since the first call, QueryPerformanceCounter based
void	TTLog(LPCTSTR pszFmt, ...);	// serialized write to theVerboseLog
void	TTSuppressed(int iEvent);	// count one dropped line, report the total once per second

// Logs "<event>|us=<elapsed>" on destruction, so every exit path of a scope is
// covered, including the ones taken by an exception.
class CTTScope
{
public:
	explicit CTTScope(LPCTSTR pszEvent);
	~CTTScope();
	CTTScope(const CTTScope&) = delete;
	CTTScope& operator=(const CTTScope&) = delete;
private:
	LPCTSTR const m_pszEvent;
	const uint64 m_uStart;
};

// __LINE__ in the scope object name: nested TT_SCOPE() blocks must not shadow
// each other (C4456 under /Wall).
#define TT_CAT2(a, b)				a##b
#define TT_CAT(a, b)				TT_CAT2(a, b)

#ifdef EMULE_TIMETRACE
#define TT(fmt, ...)				TTLog(_T("TT|%I64u|%lu|") _T(fmt), TTNow(), ::GetCurrentThreadId(), __VA_ARGS__)
#define TT_TIME(v)					const uint64 v = TTNow()
#define TT_ELAPSED(v, t)			const uint64 v = TTNow() - (t)
#define TT_SCOPE(ev)				CTTScope TT_CAT(_tt_scope_, __LINE__)(_T(ev))
#define TT_IF(cond, ev, fmt, ...)	do { if (cond) TT(fmt, __VA_ARGS__); else TTSuppressed(ev); } while (false)
#else
#define TT(fmt, ...)				((void)0)
#define TT_TIME(v)					((void)0)
#define TT_ELAPSED(v, t)			((void)0)
#define TT_SCOPE(ev)				((void)0)
#define TT_IF(cond, ev, fmt, ...)	((void)0)
#endif