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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#include "stdafx.h"
#include "emule.h"
#include "CreditsThread.h"
#include "opcodes.h"
#include "OtherFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


// define background colour
#define BACK_RGB	(COLORREF)0xFFFFFF

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

IMPLEMENT_DYNAMIC(CCreditsThread, CWinThread)

BEGIN_MESSAGE_MAP(CCreditsThread, CWinThread)
	//{{AFX_MSG_MAP(CCreditsThread)
		// NOTE - the ClassWizard will add and remove mapping macros here.
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

CCreditsThread::CCreditsThread(CWnd *pWnd, HDC hDC, LPCRECT rectScreen)
	: m_hDC(hDC)
	, m_rectScreen(rectScreen)
	, m_pbmpOldCredits()
	, m_nCreditsBmpWidth()
	, m_nCreditsBmpHeight()
	, m_nDelay(30)
	, m_nScrollInc(SCROLL_UP)
	, m_nScrollPos()
	, m_Run()
{
	m_pMainWnd = pWnd;
	m_rgnScreen.CreateRectRgnIndirect(m_rectScreen);
}

BOOL CCreditsThread::InitInstance()
{
	InitThreadLocale();
	return TRUE;
}

int CCreditsThread::Run()
{
	m_dc.Attach(m_hDC);
	CreateCredits();
	// loop and wait for exit notification
	while (m_Run)
		SingleStep();
	m_dc.Detach();

	if (m_dcCredits.m_hDC && m_pbmpOldCredits) {
		m_dcCredits.SelectObject(m_pbmpOldCredits);
		m_bmpCredits.DeleteObject();
	}
	return 0;
}

void CCreditsThread::SingleStep()
{
	static int nScrollY = 0;	// track the current scroll position

	// timer variables
	LARGE_INTEGER nFrequency;
	LARGE_INTEGER nStart{};	// C4701: only read when bTimerValid, which the compiler cannot see

	bool bTimerValid = QueryPerformanceFrequency(&nFrequency);
	if (bTimerValid)
		QueryPerformanceCounter(&nStart);	// get start time

	m_dc.BitBlt(m_rectScreen.left, m_rectScreen.top, m_rectScreen.Width(), m_rectScreen.Height(), &m_dcCredits, 0, nScrollY, SRCCOPY);

	// continue scrolling
	nScrollY += m_nScrollInc;
	if (nScrollY >= m_nCreditsBmpHeight)
		nScrollY = 0;	// scrolling up
	else if (nScrollY < 0)
		nScrollY = m_nCreditsBmpHeight;	// scrolling down

	int nTimeInMilliseconds;
	if (bTimerValid) {
		LARGE_INTEGER nEnd;
		QueryPerformanceCounter(&nEnd);
		nTimeInMilliseconds = (int)(SEC2MS(nEnd.QuadPart - nStart.QuadPart) / nFrequency.QuadPart);
	} else
		nTimeInMilliseconds = 0;
	// delay scrolling by the specified time
	if (nTimeInMilliseconds <= m_nDelay)
		::Sleep(m_nDelay - nTimeInMilliseconds);
}

void CCreditsThread::CreateCredits()
{
	InitFonts();
	InitColors();
	InitText();

	m_dc.SelectClipRgn(&m_rgnScreen);

	CDC dcScreen;
	dcScreen.CreateCompatibleDC(&m_dc);
	CBitmap bmpScreen;
	bmpScreen.CreateCompatibleBitmap(&m_dc, m_rectScreen.Width(), m_rectScreen.Height());
	CBitmap *pbmpOldScreen = dcScreen.SelectObject(&bmpScreen);

	m_nCreditsBmpWidth = m_rectScreen.Width();
	m_nCreditsBmpHeight = CalcCreditsHeight();

	m_dcCredits.CreateCompatibleDC(&m_dc);
	m_bmpCredits.CreateCompatibleBitmap(&m_dc, m_nCreditsBmpWidth, m_nCreditsBmpHeight);
	m_pbmpOldCredits = m_dcCredits.SelectObject(&m_bmpCredits);

	m_dcCredits.FillSolidRect(0, 0, m_nCreditsBmpWidth, m_nCreditsBmpHeight, BACK_RGB); //sets BkColor

	CFont *pOldFont = m_dcCredits.SelectObject(m_arFonts[0]);
	int nLastFont = 0;
	int nTextHeight = m_arFontHeights[0];

	int nLastColor = -1;
	unsigned y = 0;
	for (INT_PTR n = 0; n < m_arCredits.GetCount(); ++n) {
		const CString &cs(m_arCredits[n]);
		if (cs.GetLength() < 3)
			continue;
		switch (cs[0]) {
		case _T('B'):	// it's a bitmap
			{
				CBitmap bmp;
				if (!bmp.LoadBitmap(CPTR(cs, 2))) {
					CString sMsg;
					sMsg.Format(_T("Could not find bitmap resource \"%s\". Be sure to assign the bitmap a QUOTED resource name"), CPTR(cs, 2));
					AfxMessageBox(sMsg);
					return;
				}

				BITMAP bmInfo;
				bmp.GetBitmap(&bmInfo);

				CDC dc;
				dc.CreateCompatibleDC(&m_dcCredits);
				CBitmap *pOldBmp = dc.SelectObject(&bmp);

				// draw the bitmap
				m_dcCredits.BitBlt((m_rectScreen.Width() - bmInfo.bmWidth) / 2, y, bmInfo.bmWidth, bmInfo.bmHeight, &dc, 0, 0, SRCCOPY);

				dc.SelectObject(pOldBmp);
				bmp.DeleteObject();

				y += bmInfo.bmHeight;
			}
			break;
		case _T('S'):	// it's a vertical space
			y += _ttoi(CPTR(cs, 2));
			break;
		default:		// it's a text string
			{
				int nFont = _ttoi(cs.Left(2));
				if (nFont != nLastFont) {
					nLastFont = nFont;
					m_dcCredits.SelectObject(m_arFonts[nFont]);
					nTextHeight = m_arFontHeights[nFont];
				}

				int nColor = _ttoi(cs.Mid(3, 2));
				if (nColor != nLastColor) {
					m_dcCredits.SetTextColor(m_arColors[nColor]);
					nLastColor = nColor;
				}

				RECT rect = { 0, (LONG)y, m_rectScreen.Width(), (LONG)y + nTextHeight };
				m_dcCredits.DrawText(CPTR(cs, 6), -1, &rect, DT_CENTER);

				y += nTextHeight;
			}
		}
	}

	m_dcCredits.SelectObject(pOldFont);
	dcScreen.SelectObject(pbmpOldScreen);
	bmpScreen.DeleteObject();

	// clean up the fonts we created
	for (INT_PTR i = m_arFonts.GetCount(); --i >= 0;) {
		m_arFonts[i]->DeleteObject();
		delete m_arFonts[i];
	}
	m_arFonts.RemoveAll();
}

// create each font we'll need and add to the fonts array
void CCreditsThread::InitFonts()
{
	CDC dcMem;
	dcMem.CreateCompatibleDC(&m_dc);

	LOGFONT lf = {};
	// font 0
	// SMALL ARIAL
	lf.lfHeight = 12;
	lf.lfWeight = FW_MEDIUM;
	lf.lfQuality = NONANTIALIASED_QUALITY;
	_tcscpy(lf.lfFaceName, _T("Arial"));
	CFont *font0 = new CFont;
	font0->CreateFontIndirect(&lf);
	m_arFonts.Add(font0);

	CFont *pOldFont = dcMem.SelectObject(font0);
	int nTextHeight = dcMem.GetTextExtent(_T("Wy")).cy;
	m_arFontHeights.Add(nTextHeight);

	// font 1
	// MEDIUM BOLD ARIAL
	memset((void*)&lf, 0, sizeof lf);
	lf.lfHeight = 14;
	lf.lfWeight = FW_SEMIBOLD;
	lf.lfQuality = NONANTIALIASED_QUALITY;
	_tcscpy(lf.lfFaceName, _T("Arial"));
	CFont *font1 = new CFont;
	font1->CreateFontIndirect(&lf);
	m_arFonts.Add(font1);

	dcMem.SelectObject(font1);
	nTextHeight = dcMem.GetTextExtent(_T("Wy")).cy;
	m_arFontHeights.Add(nTextHeight);

	// font 2
	// LARGE ITALIC HEAVY BOLD TIMES ROMAN
	memset((void*)&lf, 0, sizeof lf);
	lf.lfHeight = 16;
	lf.lfWeight = FW_BOLD;
	//lf.lfItalic = TRUE;
	lf.lfQuality = ANTIALIASED_QUALITY;
	_tcscpy(lf.lfFaceName, _T("Arial"));
	CFont *font2 = new CFont;
	font2->CreateFontIndirect(&lf);
	m_arFonts.Add(font2);

	dcMem.SelectObject(font2);
	nTextHeight = dcMem.GetTextExtent(_T("Wy")).cy;
	m_arFontHeights.Add(nTextHeight);

	// font 3
	memset((void*)&lf, 0, sizeof lf);
	lf.lfHeight = 25;
	lf.lfWeight = FW_HEAVY;
	lf.lfQuality = ANTIALIASED_QUALITY;
	_tcscpy(lf.lfFaceName, _T("Arial"));
	CFont *font3 = new CFont;
	font3->CreateFontIndirect(&lf);
	m_arFonts.Add(font3);

	dcMem.SelectObject(font3);
	nTextHeight = dcMem.GetTextExtent(_T("Wy")).cy;
	m_arFontHeights.Add(nTextHeight);

	dcMem.SelectObject(pOldFont);
}

void CCreditsThread::InitColors()
{
	// define each color we'll be using

	m_arColors.Add(PALETTERGB(  0,   0,   0));	// 0 = BLACK
	m_arColors.Add(PALETTERGB( 90,  90,  90));	// 1 = very dark gray
	m_arColors.Add(PALETTERGB(128, 128, 128));	// 2 = DARK GRAY
	m_arColors.Add(PALETTERGB(192, 192, 192));	// 3 = LIGHT GRAY
	m_arColors.Add(PALETTERGB(200,  50,  50));	// 4 = very light gray
	m_arColors.Add(PALETTERGB(255, 255, 128));	// 5 = light yellow
	m_arColors.Add(PALETTERGB(  0,   0, 128));	// 6 = dark blue
	m_arColors.Add(PALETTERGB(128, 128, 255));	// 7 = light blue
	m_arColors.Add(PALETTERGB(  0, 106,   0));	// 8 = dark green
}

void CCreditsThread::InitText()
{
	// 1st pair of digits identifies the font to use
	// 2nd pair of digits identifies the color to use
	// B = Bitmap
	// S = Space (moves down the specified number of pixels)

	/*
		You may NOT modify this copyright message. You may add your name, if you
		changed or improved this code, but you may not delete any part of this message,
		make it invisible etc.
	*/

	static LPCTSTR const lines[] =
	{
		  _T("01:06:Copyright (C) 2002-2026 Merkur")
		, _T("S:50")
		, _T("02:04:Developers")
		, _T("S:5")
		, _T("01:06:Ornis")

		, _T("S:50")

		, _T("02:04:Testers")
		, _T("S:5")
		, _T("01:06:Monk")
		, _T("S:5")
		, _T("01:06:Daan")
		, _T("S:5")
		, _T("01:06:Elandal")
		, _T("S:5")
		, _T("01:06:Frozen_North")
		, _T("S:5")
		, _T("01:06:kayfam")
		, _T("S:5")
		, _T("01:06:Khandurian")
		, _T("S:5")
		, _T("01:06:Masta2002")
		, _T("S:5")
		, _T("01:06:mrLabr")
		, _T("S:5")
		, _T("01:06:Nesi-San")
		, _T("S:5")
		, _T("01:06:SeveredCross")
		, _T("S:5")
		, _T("01:06:Skynetman")

		, _T("S:50")
		, _T("02:04:Retired Members")
		, _T("S:5")
		, _T("01:06:Merkur (the Founder)")
		, _T("S:5")
		, _T("01:06:tecxx")
		, _T("S:5")
		, _T("01:06:Pach2")
		, _T("S:5")
		, _T("01:06:Juanjo")
		, _T("S:5")
		, _T("01:06:Barry")
		, _T("S:5")
		, _T("01:06:Dirus")
		, _T("S:5")
		, _T("01:06:Unknown1")

		, _T("S:50")
		, _T("02:04:Thanks to these programmers")
		, _T("02:04:for publishing useful code parts")
		, _T("S:5")
		, _T("01:06:Paolo Messina (ResizableDialog class)")
		, _T("S:5")
		, _T("01:6:PJ Naughter (HttpDownload Dialog)")
		, _T("S:5")
		, _T("01:06:Jim Connor (Scrolling Credits)")
		, _T("S:5")
		, _T("01:06:Yury Goltsman (extended Progressbar)")
		, _T("S:5")
		, _T("01:06:Magomed G. Abdurakhmanov (Hyperlink ctrl)")
		, _T("S:5")
		, _T("01:06:Arthur Westerman (Titled menu)")
		, _T("S:5")
		, _T("01:06:Tim Kosse (AsyncSocket-Proxy support)")
		, _T("S:5")
		, _T("01:06:Keith Rule (Memory DC)")
		, _T("S:50")

		, _T("02:07:And thanks to the following")
		, _T("02:07:people for translating eMule")
		, _T("02:07:into different languages:")
		, _T("S:20")

		, _T("01:06:Arabic: Dody")
		, _T("S:05")
		, _T("01:06:Albanian: Besmir")
		, _T("S:05")
		, _T("01:06:Basque: TXiKi")
		, _T("S:05")
		, _T("01:06:Breton: KAD-Korvigelloù an Drouizig")
		, _T("S:05")
		, _T("01:06:Bulgarian: DapKo, Dumper")
		, _T("S:05")
		, _T("01:06:Catalan: LeChuck")
		, _T("S:05")
		, _T("01:06:Chinese Simplified: Tim Chen, Qilu T.")
		, _T("S:05")
		, _T("01:06:Chinese Traditional: CML, Donlong, Ryan")
		, _T("S:05")
		, _T("01:06:Czech: Patejl")
		, _T("S:05")
		, _T("01:06:Danish: Tiede, Cirrus, Itchy")
		, _T("S:05")
		, _T("01:06:Estonian: Symbio")
		, _T("S:05")
		, _T("01:06:Dutch: Mr.Bean")
		, _T("S:05")
		, _T("01:06:Finnish: Nikerabbit")
		, _T("S:05")
		, _T("01:06:French: Motte, Emzc, Lalrobin")
		, _T("S:05")
		, _T("01:06:Galician: Juan, Emilio R.")
		, _T("S:05")
		, _T("01:06:Greek: Michael Papadakis")
		, _T("S:05")
		, _T("01:06:Italian: Trevi, FrankyFive")
		, _T("S:05")
		, _T("01:06:Japanese: DukeDog, Shinro T.")
		, _T("S:05")
		, _T("01:06:Hebrew: Avi-3k")
		, _T("S:05")
		, _T("01:06:Hungarian: r0ll3r")
		, _T("S:05")
		, _T("01:06:Korean: pooz")
		, _T("S:05")
		, _T("01:06:Latvian: Zivs")
		, _T("S:05")
		, _T("01:06:Lithuanian: Daan")
		, _T("S:05")
		, _T("01:06:Maltese: Reuben")
		, _T("S:05")
		, _T("01:06:Norwegian (Bokmal): Iznogood")
		, _T("S:05")
		, _T("01:06:Norwegian (Nynorsk): Hallvor")
		, _T("S:05")
		, _T("01:06:Polish: Tomasz \"TMouse\" Broniarek")
		, _T("S:05")
		, _T("01:06:Portuguese: Filipe, Luнs Claro")
		, _T("S:05")
		, _T("01:06:Portuguese Brazilian: DarthMaul,Brasco,Ducho")
		, _T("S:05")
		, _T("01:06:Romanian: Dragos")
		, _T("S:05")
		, _T("01:06:Russian: T-Mac, BRMAIL")
		, _T("S:05")
		, _T("01:06:Slovenian: Rok Kralj")
		, _T("S:05")
		, _T("01:06:Spanish Castellano: Azuredraco, Javier L., |_Hell_|")
		, _T("S:05")
		, _T("01:06:Swedish: Andre")
		, _T("S:05")
		, _T("01:06:Turkish: Burak Y.")
		, _T("S:05")
		, _T("01:06:Ukrainian: Kex")
		, _T("S:05")
		, _T("01:06:Vietnamese: Paul Tran HQ Loc")

		, _T("S:50")
		, _T("02:04:Part of eMule is based on Kademlia,")
		, _T("S:5")
		, _T("02:04:peer-to-peer routing based on a XOR metric")
		, _T("S:10")
		, _T("01:06:Copyright (C) 2002 Petar Maymounkov")
		, _T("S:5")
		, _T("01:06:(petar@maymounkov.org)")
		, NULL
	};

	// start at the bottom of the screen
	CString sTmp;
	sTmp.Format(_T("S:%d"), m_rectScreen.Height());
	m_arCredits.Add(sTmp);

	m_arCredits.Add(_T("03:00:eMule"));
	sTmp.Format(_T("02:01:Version %s"), (LPCTSTR)theApp.m_strCurVersionLong);
	m_arCredits.Add(sTmp);
	//add the rest of the credits
	for (LPCTSTR const *p = lines; *p; ++p)
		m_arCredits.Add(*p);
}

int CCreditsThread::CalcCreditsHeight()
{
	unsigned nHeight = 0;

	for (INT_PTR n = 0; n < m_arCredits.GetCount(); ++n) {
		const CString &cs(m_arCredits[n]);
		if (cs.GetLength() < 3)
			continue;
		switch (cs[0]) {
		case _T('B'):	// it's a bitmap
			{
				CBitmap bmp;
				if (!bmp.LoadBitmap(CPTR(cs, 2))) {
					CString sMsg;
					sMsg.Format(_T("Could not find bitmap resource \"%s\". Be sure to assign the bitmap a QUOTED resource name"), CPTR(cs, 2));
					AfxMessageBox(sMsg);
					return -1;
				}

				BITMAP bmInfo;
				bmp.GetBitmap(&bmInfo);

				nHeight += bmInfo.bmHeight;
			}
			break;
		case _T('S'):	// it's a vertical space
			nHeight += _ttoi(CPTR(cs, 2));
			break;
		default:		// it's a text string
			{
				int nFont = _ttoi(cs.Left(2));
				nHeight += m_arFontHeights[nFont];
			}
		}
	}
	ASSERT((int)nHeight > 0);
	return (int)nHeight;
}