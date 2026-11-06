#include "stdafx.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifdef _DEBUG
static UINT g_uResNumber;
static UINT g_uTotalSize;

static BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR) noexcept
{
	++g_uResNumber;
	UINT uSize = 0;
	HRSRC hResInfo = ::FindResource(hModule, lpszName, lpszType);
	if (hResInfo) {
		uSize = ::SizeofResource(hModule, hResInfo);
		g_uTotalSize += uSize;
	}
#if 0
	TRACE(_T("%3u: "), g_uResNumber);
	if (IS_INTRESOURCE(lpszType)) {
		if ((DWORD)lpszType == (DWORD)RT_GROUP_ICON)
			TRACE(_T("RT_GROUP_ICON"));
		else if ((DWORD)lpszType == (DWORD)RT_ICON)
			TRACE(_T("RT_ICON"));
		else if ((DWORD)lpszType == (DWORD)RT_BITMAP)
			TRACE(_T("RT_BITMAP"));
		else
			TRACE(_T("type=%u"), (UINT)lpszType);
	} else
		TRACE(_T("type=\"%s\""), lpszType);
	TRACE(_T("  size=%5u"), uSize);
	if (IS_INTRESOURCE(lpszName))
		TRACE(_T("  name=*%u"), (UINT)lpszName);
	else
		TRACE(_T("  name=\"%s\""), lpszName);
	TRACE(_T("\n"));
#endif
	return TRUE;
}

bool CheckResources()
{
	g_uTotalSize = 0;
	g_uResNumber = 0;
	EnumResourceNames(AfxGetInstanceHandle(), RT_GROUP_ICON, EnumResNameProc, 0);
	TRACE("RT_GROUP_ICON resources: %u (%u bytes)\n", g_uResNumber, g_uTotalSize);

	g_uTotalSize = 0;
	g_uResNumber = 0;
	EnumResourceNames(AfxGetInstanceHandle(), RT_ICON, EnumResNameProc, 0);
	TRACE("RT_ICON resources: %u (%u bytes)\n", g_uResNumber, g_uTotalSize);

	g_uTotalSize = 0;
	g_uResNumber = 0;
	EnumResourceNames(AfxGetInstanceHandle(), RT_BITMAP, EnumResNameProc, 0);
	TRACE("RT_BITMAP resources: %u (%u bytes)\n", g_uResNumber, g_uTotalSize);

	return true;
}
#endif

/*
int fooAsCode(int a)
{
	return a + 30;
00401000 8B 44 24 04      mov         eax,dword ptr [esp+4]
00401004 83 C0 1E         add         eax,1Eh
00401007 C3               ret
}
*/
unsigned char fooAsData[] = {
	0x8B,0x44,0x24,0x04,
	0x83,0xC0,0x1E,
	0xC3
};

extern "C" int(*convertDataAddrToCodeAddr(void *p))(int)
{
	return (int(*)(int))p;
}

int g_fooResult;

bool SelfTest()
{
#ifdef _DEBUG
	//CheckResources();
#endif

	// Test DEP
	//int (* volatile pfnFooAsData)(int) = (int (*)(int))convertDataAddrToCodeAddr(fooAsData);
	//g_fooResult = (*pfnFooAsData)(5);

	// Test a crash
	//*(int*)0=0;

	return true;
}