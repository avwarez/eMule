#pragma once

enum EDebugLogPriority : int
{
	DLP_VERYLOW = 0,
	DLP_LOW,
	DLP_DEFAULT,
	DLP_HIGH,
	DLP_VERYHIGH
};

// Log message type enumeration
#define	LOG_INFO		0
#define	LOG_WARNING		1
#define	LOG_ERROR		2
#define	LOG_SUCCESS		3
#define	LOGMSGTYPEMASK	0x03

// Log message targets flags
#define	LOG_DEFAULT		0x00
#define	LOG_DEBUG		0x10
#define	LOG_STATUSBAR	0x20
#define	LOG_DONTNOTIFY	0x40


void Log(LPCTSTR pszFmt, ...);
void LogError(LPCTSTR pszFmt, ...);
void LogWarning(LPCTSTR pszFmt, ...);

void Log(UINT uFlags, LPCTSTR pszFmt, ...);
void LogError(UINT uFlags, LPCTSTR pszFmt, ...);
void LogWarning(UINT uFlags, LPCTSTR pszFmt, ...);

void DebugLog(LPCTSTR pszFmt, ...);
void DebugLogError(LPCTSTR pszFmt, ...);
void DebugLogWarning(LPCTSTR pszFmt, ...);

void DebugLog(UINT uFlags, LPCTSTR pszFmt, ...);
void DebugLogError(UINT uFlags, LPCTSTR pszFmt, ...);
void DebugLogWarning(UINT uFlags, LPCTSTR pszFmt, ...);

void LogV(UINT uFlags, LPCTSTR pszFmt, va_list argp);

void AddLogLine(bool bAddToStatusBar, LPCTSTR pszLine, ...);
void AddDebugLogLine(bool bAddToStatusBar, LPCTSTR pszLine, ...);
void AddDebugLogLine(EDebugLogPriority Priority, bool bAddToStatusBar, LPCTSTR pszLine, ...);

void AddLogTextV(UINT uFlags, EDebugLogPriority dlpPriority, LPCTSTR pszLine, va_list argptr);

// One line in the verbose log for an exception that a catch block handles without
// reporting it anywhere else, so that no failure passes without a trace. pszWhere
// is the catching function (__FUNCTION__). An exception object, when there is one,
// is described but not deleted - the catch block still owns it. These never throw:
// a failure while logging must not escape a catch block that used to absorb it.
void DebugLogCaughtException(LPCSTR pszWhere) noexcept;
void DebugLogCaughtException(LPCSTR pszWhere, CException *ex) noexcept;
void DebugLogCaughtException(LPCSTR pszWhere, const CString &strError) noexcept;


///////////////////////////////////////////////////////////////////////////////
// CLogFile

enum ELogFileFormat : uint8
{
	Unicode = 0,
	Utf8
};

class CLogFile
{
public:
	CLogFile();
	~CLogFile();

	bool IsOpen() const								{ return m_fp != NULL; }
	const CString& GetFilePath() const				{ return m_strFilePath; }
	bool SetFilePath(LPCTSTR pszFilePath);
	void SetMaxFileSize(UINT uMaxFileSize);
	bool SetFileFormat(const ELogFileFormat eFileFormat);

	bool Create(LPCTSTR pszFilePath, UINT uMaxFileSize = 1024 * 1024, const ELogFileFormat eFileFormat = Unicode);
	bool Open();
	bool Close();
	bool Log(LPCTSTR pszMsg, int iLen = -1);
	bool Logf(LPCTSTR pszFmt, ...);
	void StartNewLogFile();

protected:
	FILE	*m_fp;
	CString	m_strFilePath;
	time_t	m_tStarted;
	size_t	m_uBytesWritten;
	size_t	m_uMaxFileSize;
	ELogFileFormat m_eFileFormat;
	bool	m_bInOpenCall;
};

extern CLogFile theLog;
extern CLogFile theVerboseLog;