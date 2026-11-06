#include "stdafx.h"
#include "Ini2.h"
#include "StringConversion.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define MAX_INI_BUFFER 256

//In most cases, malformed m_lines would be bypassed, errors in ini format ignored
//Input lines would be canonicalised: lines trimmed, spaces inside brackets and around equal sign removed
bool CIni::Load()
{
	FILE *f = _tfopen(m_ininame, _T("r"));
	if (!f)
		return false;

	char *buf = new char[UINT16_MAX];
	while (!feof(f) && fgets(buf, UINT16_MAX, f)) {
		INT_PTR i = m_lines.Add(buf);
		CStringA &r(m_lines[i]);
		r.Trim("\n\r");
		int len0 = r.GetLength();
		r.Trim();
		int l = r.GetLength();
		if (l > 2 && r[0] == '[') {
			if (r[l - 1] == ']') {
				if (r[1] <= ' ' || r[l - 2] <= ' ') {
					CStringA s(r.Mid(1, l - 2).Trim());
					r.Format("[%s]", (LPCSTR)s);
				}
			}
		} else if (l >= 2 && isalnum(r[0])) {
			int j = r.Find('=') - 1;
			if (j >= 0) {
				int k = j + 2;
				while (r[k] && r[k] <= ' ')
					++k;
				while (j && r[j] <= ' ')
					--j;
				k -= ++j;
				if (k > 2) {
					r.Delete(j, k);
					r.Insert(j, '=');
				}
			}
		}
		if (r.GetLength() < len0)
			SetWrite();
	}
	fclose(f);
	delete[] buf;
	return true;
}

bool CIni::Store()
{
	if (!m_bWrite)
		return true;

	FILE *f = _tfopen(m_ininame + _T('t'), _T("w"));
	if (f) {
		for (INT_PTR i = 0; i < m_lines.GetCount(); ++i) {
			fputs(m_lines[i], f);
			fputc('\n', f);
		}
		fclose(f);
		m_bWrite = false;
		::CopyFile(m_ininame, m_ininame + _T(".bak"), FALSE);
		::MoveFileEx(m_ininame + _T('t'), m_ininame, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
		return true;
	}
	return false;
}

// Return section's line number
// 'line count' if not found
// -1 for global section
INT_PTR CIni::FindSection(LPCTSTR section)
{
	CStringA s(section ? section : _T(""));
	s.Trim();
	if (s.IsEmpty())
		return -1; //global section
	s.Insert(0, '[');
	s += ']';

	INT_PTR i;
	for (i = 0; i < m_lines.GetCount() && m_lines[i].CompareNoCase(s) != 0; ++i);
	return i;
}

//all argument strings are trimmed
//empty or null section is 'global'
//null 'key' returns empty string
CStringA CIni::GetEmuleProfileA(LPCTSTR section, LPCTSTR key, LPCTSTR def)
{
	if (!key)
		return CStringA();
	INT_PTR i = FindSection(section);
	if (i < m_lines.GetCount()) {
		CStringA k(key);
		int l = k.Trim().GetLength();
		for (; ++i < m_lines.GetCount();) {
			const CStringA &r(m_lines[i]);
			if (r[0] == '[')
				break;
			int j = r.Find('=');
			if (j > 0 && j == l && _strnicmp(k, r, j) == 0)
				return CStringA(r.Mid(j + 1));
		}
	}
	return CStringA(def ? def : _T("")).Trim();
}

CString CIni::GetEmuleProfile(LPCTSTR section, LPCTSTR key, LPCTSTR def)
{
	return CString(GetEmuleProfileA(section, key, def));
}

//null 'key' is ignored
//null 'value' deletes the line with the key
bool CIni::PutEmuleProfile(LPCTSTR section, LPCTSTR key, LPCSTR value)
{
	if (!key)
		return false;
	INT_PTR i = FindSection(section);
	CStringA k(key);
	k.Trim();
	CStringA v(value ? value : "");
	v.Trim();
	if (i >= m_lines.GetCount()) {
		if (!value)
			return true;
		CStringA s(section);
		s.Trim();
		s.Insert(0, '[');
		s += ']';
		//create new section
		m_lines.Add(s);
		k.AppendFormat("=%s", (LPCSTR)v);
		m_lines.Add(k);
		SetWrite();
		return true;
	}

	int l = k.GetLength();
	for (; ++i;) {
		if (i >= m_lines.GetCount() || m_lines[i][0] == '[') { //end of section reached
			if (value) {
				k.AppendFormat("=%s", (LPCSTR)v);
				m_lines.InsertAt(i, k);
				SetWrite();
			}
			return true;
		}
		CStringA &r(m_lines[i]);
		int j = r.Find('=');
		if (j > 0 && j == l && _strnicmp(k, r, j) == 0) {
			if (value) {
				k.AppendFormat("=%s", (LPCSTR)v);
				if (r != k) {
					r = k;
					SetWrite();
				}
			} else {
				m_lines.RemoveAt(i);
				SetWrite();
			}
			return true;
		}
	}
	return false;
}

void CIni::AddModulePath(CString &rstrFileName, bool bModulPath)
{
	TCHAR drive[_MAX_DRIVE];
	TCHAR dir[_MAX_DIR];
	TCHAR fname[_MAX_FNAME];
	TCHAR ext[_MAX_EXT];

	_tsplitpath(rstrFileName, drive, dir, fname, ext);
	if (!drive[0]) {
		//PathCanonicalize(...) doesn't work on all Platforms!
		CString strModule;
		if (bModulPath) {
			DWORD dwModPathLen = ::GetModuleFileName(NULL, strModule.GetBuffer(MAX_PATH), MAX_PATH);
			strModule.ReleaseBuffer((dwModPathLen == 0 || dwModPathLen == MAX_PATH) ? 0 : -1);
		} else {
			DWORD dwCurDirLen = ::GetCurrentDirectory(MAX_PATH, strModule.GetBuffer(MAX_PATH));
			strModule.ReleaseBuffer((dwCurDirLen == 0 || dwCurDirLen >= MAX_PATH) ? 0 : -1);
			// fix by "cpp@world-online.no"
			strModule.TrimRight(_T("\\/"));
			strModule += _T("\\");
		}
		_tsplitpath(strModule, drive, dir, fname, ext);
		strModule.Format(_T("%s%s%s"), drive, dir, (LPCTSTR)rstrFileName);
		rstrFileName = strModule;
	}
}

CString CIni::GetDefaultIniFile(bool bModulPath)
{
	TCHAR drive[_MAX_DRIVE];
	TCHAR dir[_MAX_DIR];
	TCHAR fname[_MAX_FNAME];
	TCHAR ext[_MAX_EXT];
	CString strTemp;
	DWORD dwModPathLen = ::GetModuleFileName(NULL, strTemp.GetBuffer(MAX_PATH), MAX_PATH);
	strTemp.ReleaseBuffer((dwModPathLen == 0 || dwModPathLen == MAX_PATH) ? 0 : -1);
	_tsplitpath(strTemp, drive, dir, fname, ext);
	strTemp.Format(_T("%s.ini"), fname);

	CString strApplName;
	if (bModulPath)
		strApplName.Format(_T("%s%s%s"), drive, dir, (LPCTSTR)strTemp);
	else {
		DWORD dwCurDirLen = ::GetCurrentDirectory(MAX_PATH, strApplName.GetBuffer(MAX_PATH));
		strApplName.ReleaseBuffer((dwCurDirLen == 0 || dwCurDirLen >= MAX_PATH) ? 0 : -1);
		strApplName.TrimRight(_T('\\'));
		strApplName.TrimRight(_T('/'));
		strApplName.AppendFormat(_T("\\%s"), (LPCTSTR)strTemp);
	}
	return strApplName;
}

CIni::CIni()
	: m_bWrite()
	, m_bModulePath(true)
	, m_strFileName(GetDefaultIniFile(m_bModulePath))
	, m_strSection(GetDefaultSection())
{
	SetIniName(m_strFileName);
	Load();
}

CIni::CIni(LPCTSTR const pstrFileName)
	: m_bWrite()
	, m_bModulePath(true)
	, m_strFileName(pstrFileName)
{
	if (m_strFileName.IsEmpty())
		m_strFileName = GetDefaultIniFile(m_bModulePath);
	AddModulePath(m_strFileName, m_bModulePath);
	m_strSection = GetDefaultSection();
	SetIniName(m_strFileName);
	Load();
}

CIni::CIni(LPCTSTR const pstrFileName, LPCTSTR const pstrSection)
	: m_bWrite()
	, m_bModulePath(true)
	, m_strFileName(pstrFileName)
	, m_strSection(pstrSection)
{
	if (m_strFileName.IsEmpty())
		m_strFileName = GetDefaultIniFile(m_bModulePath);
	AddModulePath(m_strFileName, m_bModulePath);
	if (m_strSection.IsEmpty())
		m_strSection = GetDefaultSection();
	SetIniName(m_strFileName);
	Load();
}

CString CIni::GetString(LPCTSTR lpszEntry, LPCTSTR lpszDefault, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	return GetEmuleProfile(m_strSection, lpszEntry, lpszDefault);
}

CStringW CIni::GetStringUTF8(LPCTSTR lpszEntry, LPCTSTR lpszDefault, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	return OptUtf8ToStr(GetEmuleProfileA(m_strSection, lpszEntry, lpszDefault));
}

double CIni::GetDouble(LPCTSTR lpszEntry, double fDefault, LPCTSTR lpszSection)
{
	TCHAR szDefault[MAX_PATH];
	_sntprintf(szDefault, _countof(szDefault), _T("%g"), fDefault);
	szDefault[_countof(szDefault) - 1] = _T('\0');
	return _tstof(GetString(lpszEntry, szDefault, lpszSection));
}

float CIni::GetFloat(LPCTSTR lpszEntry, float fDefault, LPCTSTR lpszSection)
{
	TCHAR szDefault[MAX_PATH];
	_sntprintf(szDefault, _countof(szDefault), _T("%g"), fDefault);
	szDefault[_countof(szDefault) - 1] = _T('\0');
	return (float)_tstof(GetString(lpszEntry, szDefault, lpszSection));
}

int CIni::GetInt(LPCTSTR lpszEntry, int nDefault, LPCTSTR lpszSection)
{
	TCHAR szDefault[MAX_PATH];
	_sntprintf(szDefault, _countof(szDefault), _T("%d"), nDefault);
	szDefault[_countof(szDefault) - 1] = _T('\0');
	return _tstoi(GetString(lpszEntry, szDefault, lpszSection));
}

ULONGLONG CIni::GetUInt64(LPCTSTR lpszEntry, ULONGLONG nDefault, LPCTSTR lpszSection)
{
	TCHAR szDefault[MAX_PATH];
	_sntprintf(szDefault, _countof(szDefault), _T("%I64u"), nDefault);
	szDefault[_countof(szDefault) - 1] = _T('\0');
	ULONGLONG nResult;
	if (_stscanf(GetString(lpszEntry, szDefault, lpszSection), _T("%I64u"), &nResult) != 1)
		return nDefault;
	return nResult;
}

WORD CIni::GetWORD(LPCTSTR lpszEntry, WORD nDefault, LPCTSTR lpszSection)
{
	TCHAR szDefault[MAX_PATH];
	_sntprintf(szDefault, _countof(szDefault), _T("%u"), nDefault);
	szDefault[_countof(szDefault) - 1] = _T('\0');
	return (WORD)_tstoi(GetString(lpszEntry, szDefault, lpszSection));
}

bool CIni::GetBool(LPCTSTR lpszEntry, bool bDefault, LPCTSTR lpszSection)
{
	TCHAR szDefault[MAX_PATH];
	_sntprintf(szDefault, _countof(szDefault), _T("%d"), bDefault);
	szDefault[_countof(szDefault) - 1] = _T('\0');
	return _tstoi(GetString(lpszEntry, szDefault, lpszSection)) != 0;
}

CPoint CIni::GetPoint(LPCTSTR lpszEntry, const CPoint &ptDefault, LPCTSTR lpszSection)
{
	CPoint ptReturn(ptDefault);

	CString strDefault;
	strDefault.Format(_T("(%ld,%ld)"), ptDefault.x, ptDefault.y);

	const CString &strPoint(GetString(lpszEntry, strDefault, lpszSection));
	if (_stscanf(strPoint, _T("(%ld,%ld)"), &ptReturn.x, &ptReturn.y) != 2)
		return ptDefault;

	return ptReturn;
}

CRect CIni::GetRect(LPCTSTR lpszEntry, const CRect &rcDefault, LPCTSTR lpszSection)
{
	CRect rcReturn(rcDefault);
	//prepare default string
	CString strDefault;
	strDefault.Format(_T("%ld,%ld,%ld,%ld"), rcDefault.left, rcDefault.top, rcDefault.right, rcDefault.bottom);
	//read settings
	const CString &strRect(GetString(lpszEntry, strDefault, lpszSection));
	//try as the new Version first, then check the old version
	if (_stscanf(strRect, _T("%ld,%ld,%ld,%ld"), &rcReturn.top, &rcReturn.left, &rcReturn.bottom, &rcReturn.right) != 4
		&& _stscanf(strRect, _T("(%ld,%ld,%ld,%ld)"), &rcReturn.top, &rcReturn.left, &rcReturn.bottom, &rcReturn.right) != 4)
	{
		return rcDefault; //both versions failed, fall back to defaults
	}
	return rcReturn;
}

COLORREF CIni::GetColRef(LPCTSTR lpszEntry, COLORREF crDefault, LPCTSTR lpszSection)
{
	int r = GetRValue(crDefault);
	int g = GetGValue(crDefault);
	int b = GetBValue(crDefault);

	CString strDefault;
	strDefault.Format(_T("RGB(%d,%d,%d)"), r, g, b);

	const CString &strColRef(GetString(lpszEntry, strDefault, lpszSection));
	return (_stscanf(strColRef, _T("RGB(%d,%d,%d)"), &r, &g, &b) == 3) ? RGB(r, g, b) : crDefault;
}

void CIni::WriteString(LPCTSTR lpszEntry, LPCTSTR lpsz, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	Write(m_strSection, lpszEntry, lpsz);
}

void CIni::WriteStringUTF8(LPCTSTR lpszEntry, LPCTSTR lpsz, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	WriteUTF8(m_strSection, lpszEntry, lpsz);
}

void CIni::WriteDouble(LPCTSTR lpszEntry, double f, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	TCHAR szBuffer[MAX_PATH];
	_sntprintf(szBuffer, _countof(szBuffer), _T("%g"), f);
	szBuffer[_countof(szBuffer) - 1] = _T('\0');
	Write(m_strSection, lpszEntry, szBuffer);
}

void CIni::WriteFloat(LPCTSTR lpszEntry, float f, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	TCHAR szBuffer[MAX_PATH];
	_sntprintf(szBuffer, _countof(szBuffer), _T("%g"), f);
	szBuffer[_countof(szBuffer) - 1] = _T('\0');
	Write(m_strSection, lpszEntry, szBuffer);
}

void CIni::WriteInt(LPCTSTR lpszEntry, int n, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	TCHAR szBuffer[MAX_PATH];
	_itot(n, szBuffer, 10);
	Write(m_strSection, lpszEntry, szBuffer);
}

void CIni::WriteUInt64(LPCTSTR lpszEntry, ULONGLONG n, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	TCHAR szBuffer[MAX_PATH];
	_ui64tot(n, szBuffer, 10);
	Write(m_strSection, lpszEntry, szBuffer);
}

void CIni::WriteWORD(LPCTSTR lpszEntry, WORD n, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	TCHAR szBuffer[MAX_PATH];
	_ultot(n, szBuffer, 10);
	Write(m_strSection, lpszEntry, szBuffer);
}

void CIni::WriteBool(LPCTSTR lpszEntry, bool b, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	TCHAR szBuffer[MAX_PATH];
	_sntprintf(szBuffer, _countof(szBuffer), _T("%d"), (int)b);
	szBuffer[_countof(szBuffer) - 1] = _T('\0');
	Write(m_strSection, lpszEntry, szBuffer);
}

void CIni::WritePoint(LPCTSTR lpszEntry, const CPoint &pt, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	CString strBuffer;
	strBuffer.Format(_T("(%d,%d)"), pt.x, pt.y);
	Write(m_strSection, lpszEntry, strBuffer);
}

void CIni::WriteRect(LPCTSTR lpszEntry, const CRect &rect, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	CString strBuffer;
	strBuffer.Format(_T("(%d,%d,%d,%d)"), rect.top, rect.left, rect.bottom, rect.right);
	Write(m_strSection, lpszEntry, strBuffer);
}

void CIni::WriteColRef(LPCTSTR lpszEntry, COLORREF cr, LPCTSTR lpszSection)
{
	if (lpszSection != NULL)
		m_strSection = lpszSection;
	CString strBuffer;
	strBuffer.Format(_T("RGB(%d,%d,%d)"), GetRValue(cr), GetGValue(cr), GetBValue(cr));
	Write(m_strSection, lpszEntry, strBuffer);
}

void CIni::SerGetString(bool bGet, CString &rstr, LPCTSTR lpszEntry, LPCTSTR lpszSection, LPCTSTR lpszDefault)
{
	if (bGet)
		rstr = GetString(lpszEntry, lpszDefault, lpszSection);
	else
		WriteString(lpszEntry, rstr, lpszSection);
}

void CIni::SerGetDouble(bool bGet, double &f, LPCTSTR lpszEntry, LPCTSTR lpszSection, double fDefault)
{
	if (bGet)
		f = GetDouble(lpszEntry, fDefault, lpszSection);
	else
		WriteDouble(lpszEntry, f, lpszSection);
}

void CIni::SerGetFloat(bool bGet, float &f, LPCTSTR lpszEntry, LPCTSTR lpszSection, float fDefault)
{
	if (bGet)
		f = GetFloat(lpszEntry, fDefault, lpszSection);
	else
		WriteFloat(lpszEntry, f, lpszSection);
}

void CIni::SerGetInt(bool bGet, int &n, LPCTSTR lpszEntry, LPCTSTR lpszSection, int nDefault)
{
	if (bGet)
		n = GetInt(lpszEntry, nDefault, lpszSection);
	else
		WriteInt(lpszEntry, n, lpszSection);
}

void CIni::SerGetDWORD(bool bGet, DWORD &n, LPCTSTR lpszEntry, LPCTSTR lpszSection, DWORD nDefault)
{
	if (bGet)
		n = (DWORD)GetInt(lpszEntry, nDefault, lpszSection);
	else
		WriteInt(lpszEntry, n, lpszSection);
}

void CIni::SerGetBool(bool bGet, bool &b, LPCTSTR lpszEntry, LPCTSTR lpszSection, bool bDefault)
{
	if (bGet)
		b = GetBool(lpszEntry, bDefault, lpszSection);
	else
		WriteBool(lpszEntry, b, lpszSection);
}

void CIni::SerGetPoint(bool bGet, CPoint &pt, LPCTSTR lpszEntry, LPCTSTR lpszSection, const CPoint &ptDefault)
{
	if (bGet)
		pt = GetPoint(lpszEntry, ptDefault, lpszSection);
	else
		WritePoint(lpszEntry, pt, lpszSection);
}

void CIni::SerGetRect(bool bGet, CRect &rect, LPCTSTR lpszEntry, LPCTSTR lpszSection, const CRect &rectDefault)
{
	if (bGet)
		rect = GetRect(lpszEntry, rectDefault, lpszSection);
	else
		WriteRect(lpszEntry, rect, lpszSection);
}

void CIni::SerGetColRef(bool bGet, COLORREF &cr, LPCTSTR lpszEntry, LPCTSTR lpszSection, COLORREF crDefault)
{
	if (bGet)
		cr = GetColRef(lpszEntry, crDefault, lpszSection);
	else
		WriteColRef(lpszEntry, cr, lpszSection);
}

void CIni::SerGet(bool bGet, CString &rstr, LPCTSTR lpszEntry, LPCTSTR lpszSection, LPCTSTR lpszDefault)
{
	SerGetString(bGet, rstr, lpszEntry, lpszSection, lpszDefault);
}

void CIni::SerGet(bool bGet, double &f, LPCTSTR lpszEntry, LPCTSTR lpszSection, double fDefault)
{
	SerGetDouble(bGet, f, lpszEntry, lpszSection, fDefault);
}

void CIni::SerGet(bool bGet, float &f, LPCTSTR lpszEntry, LPCTSTR lpszSection, float fDefault)
{
	SerGetFloat(bGet, f, lpszEntry, lpszSection, fDefault);
}

void CIni::SerGet(bool bGet, int &n, LPCTSTR lpszEntry, LPCTSTR lpszSection, int nDefault)
{
	SerGetInt(bGet, n, lpszEntry, lpszSection, nDefault);
}

void CIni::SerGet(bool bGet, short &n, LPCTSTR lpszEntry, LPCTSTR lpszSection, int nDefault)
{
	int nTemp = n;
	SerGetInt(bGet, nTemp, lpszEntry, lpszSection, nDefault);
	n = (short)nTemp;
}

void CIni::SerGet(bool bGet, DWORD &n, LPCTSTR lpszEntry, LPCTSTR lpszSection, DWORD nDefault)
{
	SerGetDWORD(bGet, n, lpszEntry, lpszSection, nDefault);
}

void CIni::SerGet(bool bGet, WORD &n, LPCTSTR lpszEntry, LPCTSTR lpszSection, DWORD nDefault)
{
	DWORD dwTemp = n;
	SerGetDWORD(bGet, dwTemp, lpszEntry, lpszSection, nDefault);
	n = (WORD)dwTemp;
}

void CIni::SerGet(bool bGet, CPoint &pt, LPCTSTR lpszEntry, LPCTSTR lpszSection, const CPoint &ptDefault)
{
	SerGetPoint(bGet, pt, lpszEntry, lpszSection, ptDefault);
}

void CIni::SerGet(bool bGet, CRect &rect, LPCTSTR lpszEntry, LPCTSTR lpszSection, const CRect &rectDefault)
{
	SerGetRect(bGet, rect, lpszEntry, lpszSection, rectDefault);
}

void CIni::SerGet(bool bGet, CString *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, LPCTSTR lpszDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, ar[i]);
				if (ar[i].IsEmpty())
					ar[i] = lpszDefault;
			}
		} else {
			for (int i = 0; i < nCount; ++i) {
				if (i)
					strBuffer += _T(",");
				strBuffer += ar[i];
			}
			WriteString(lpszEntry, strBuffer, lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, double *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, double fDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = strTemp.IsEmpty() ? fDefault : _tstof(strTemp);
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%g"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, float *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, float fDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = strTemp.IsEmpty() ? fDefault : (float)_tstof(strTemp);
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%g"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, BYTE *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, BYTE nDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = strTemp.IsEmpty() ? nDefault : (BYTE)_tstoi(strTemp);
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%d"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, int *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, int iDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = strTemp.IsEmpty() ? iDefault : _tstoi(strTemp);
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%d"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, short *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, int iDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = (short)(strTemp.IsEmpty() ? iDefault : _tstoi(strTemp));
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%d"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, DWORD *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, DWORD dwDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = strTemp.IsEmpty() ? dwDefault : (DWORD)_tstoi(strTemp);
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%lu"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, WORD *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, DWORD dwDefault)
{
	if (nCount > 0) {
		CString strBuffer;
		if (bGet) {
			strBuffer = GetString(lpszEntry, _T(""), lpszSection);
			CString strTemp;
			int nOffset = 0;
			for (int i = 0; i < nCount; ++i) {
				nOffset = Parse(strBuffer, nOffset, strTemp);
				ar[i] = (WORD)(strTemp.IsEmpty() ? dwDefault : _tstoi(strTemp));
			}
		} else {
			for (int i = 0; i < nCount; ++i)
				strBuffer.AppendFormat(_T(",%d"), ar[i]);
			WriteString(lpszEntry, CPTR(strBuffer, 1), lpszSection);
		}
	}
}

void CIni::SerGet(bool bGet, CPoint *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, const CPoint &ptDefault)
{
	CString strBuffer;
	for (int i = 0; i < nCount; ++i) {
		strBuffer.Format(_T("%s_%i"), lpszEntry, i);
		SerGet(bGet, ar[i], strBuffer, lpszSection, ptDefault);
	}
}

void CIni::SerGet(bool bGet, CRect *ar, int nCount, LPCTSTR lpszEntry, LPCTSTR lpszSection, const CRect &rcDefault)
{
	CString strBuffer;
	for (int i = 0; i < nCount; ++i) {
		strBuffer.Format(_T("%s_%i"), lpszEntry, i);
		SerGet(bGet, ar[i], strBuffer, lpszSection, rcDefault);
	}
}

int CIni::Parse(const CString &strIn, int nOffset, CString &strOut)
{
	strOut.Empty();
	int nLength = strIn.GetLength();

	if (nOffset < nLength) {
		if (nOffset != 0 && strIn[nOffset] == _T(','))
			++nOffset;

		while (nOffset < nLength && _istspace(strIn[nOffset]))
			++nOffset;

		while (nOffset < nLength) {
			strOut += strIn[nOffset];
			if (strIn[++nOffset] == _T(','))
				break;
		}
		strOut.Trim();
	}
	return nOffset;
}

void CIni::Write(LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszValue)
{
	PutEmuleProfile(lpszSection, lpszEntry, lpszValue ? (LPCSTR)CStringA(lpszValue) : NULL);
}

void CIni::WriteUTF8(LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszValue)
{
	PutEmuleProfile(lpszSection, lpszEntry, lpszValue ? CStringA(lpszValue) : NULL);
}

bool CIni::GetBinary(LPCTSTR lpszEntry, BYTE **ppData, UINT *pBytes, LPCTSTR pszSection)
{
	const CString &str(GetString(lpszEntry, NULL, pszSection));
	int nLen = str.GetLength();
	ASSERT(nLen % 2 == 0);
	if (nLen <= 1) {
		*pBytes = 0;
		return false;
	}
	if (!*ppData)
		*ppData = new BYTE[nLen / 2];
	LPBYTE pb = *ppData;
	*pBytes = UINT(nLen / 2);
	for (int i = 0; i < nLen; i += 2)
		*pb++ = (BYTE)(((str[i + 1] - _T('A')) << 4) + (str[i] - _T('A')));
	return true;
}

bool CIni::WriteBinary(LPCTSTR lpszEntry, LPBYTE pData, size_t nBytes, LPCTSTR lpszSection)
{
	// convert to string and write out
	LPTSTR lpsz = new TCHAR[nBytes * 2 + 1];
	LPTSTR p = lpsz;
	for (; nBytes; --nBytes) {
		*p++ = (TCHAR)((*pData & 0x0F) + 'A'); //low nibble
		*p++ = (TCHAR)(((*pData++ >> 4) & 0x0F) + 'A'); //high nibble
	}
	*p = 0;

	WriteString(lpszEntry, lpsz, lpszSection);
	delete[] lpsz;
	return true;
}

void CIni::DeleteKey(LPCTSTR lpszKey)
{
	Write(m_strSection, lpszKey, NULL);
}