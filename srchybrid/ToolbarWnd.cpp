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
#include "emuledlg.h"
#include "toolbarwnd.h"
#include "HelpIDs.h"
#include "OtherFunctions.h"
#include "MenuCmds.h"
#include "DownloadListCtrl.h"
#include "TransferDlg.h"
#include "Preferences.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CToolbarWnd, CDialogBar);

BEGIN_MESSAGE_MAP(CToolbarWnd, CDialogBar)
	ON_WM_SIZE()
	ON_WM_DESTROY()
	ON_WM_SYSCOLORCHANGE()
	ON_MESSAGE(WM_INITDIALOG, OnInitDialog)
	ON_WM_SETCURSOR()
	ON_WM_HELPINFO()
	ON_NOTIFY(TBN_DROPDOWN, IDC_DTOOLBAR, OnBtnDropDown)
	ON_WM_SYSCOMMAND()
	ON_WM_CONTEXTMENU()
END_MESSAGE_MAP()


CToolbarWnd::CToolbarWnd()
	: m_hcurMove(::LoadCursor(NULL, IDC_SIZEALL)) // load default windows system cursor (a shared resource)
	, m_pCommandTargetWnd()
{
}

void CToolbarWnd::DoDataExchange(CDataExchange *pDX)
{
	CDialogBar::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_DTOOLBAR, m_btnBar);
}

#define DTOOLBAR_NUM_BUTTONS 18
void CToolbarWnd::FillToolbar()
{
	m_btnBar.DeleteAllButtons();

	static const int btndata[DTOOLBAR_NUM_BUTTONS][4] =
	{	//bmp cmd					state							string ID
		{  0, MP_PRIOLOW,			BTNS_DROPDOWN | BTNS_AUTOSIZE,	IDS_PRIORITY }, // + IDS_DOWNLOAD
		{  1, MP_PAUSE,				BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_PAUSE },
		{  2, MP_STOP,				BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_STOP },
		{  3, MP_RESUME,			BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_RESUME },
		{  4, MP_CANCEL,			BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_MAIN_BTN_CANCEL, },
		{ -1, 0,					BTNS_SEP,						-1 },
		{  5, MP_OPEN,				BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_OPEN },
		{  6, MP_OPENFOLDER,		BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_OPENFOLDER },
		{  7, MP_PREVIEW,			BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_PREVIEW },
		{  8, MP_METINFO,			BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_INFO },
		{  9, MP_VIEWFILECOMMENTS,	BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_CMT_SHOWALL },
		{ 10, MP_SHOWED2KLINK,		BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_SHOWED2KLINK },
		{ -1, 0,					BTNS_SEP,						-1 },
		{ 11, MP_NEWCAT,			BTNS_DROPDOWN | BTNS_AUTOSIZE,	IDS_TOCAT },
		{ 12, MP_CLEARCOMPLETED,	BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_DL_CLEAR },
		{ 13, MP_SEARCHRELATED,		BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_SEARCHRELATED },
		{ -1, 0,					BTNS_SEP,						-1 },
		{ 14, MP_FIND,				BTNS_BUTTON | BTNS_AUTOSIZE,	IDS_FIND } // +TBSTATE_ENABLED
	};

	TBBUTTON atb1[DTOOLBAR_NUM_BUTTONS]{};
	for (int i = 0; i < DTOOLBAR_NUM_BUTTONS; ++i) {
		atb1[i].iBitmap = btndata[i][0];
		atb1[i].idCommand = btndata[i][1];
		atb1[i].fsState = (i == 17) ? TBSTATE_WRAP | TBSTATE_ENABLED : TBSTATE_WRAP;
		atb1[i].fsStyle = (BYTE)btndata[i][2];
		if (btndata[i][3] >= 0)
			if (i)
				atb1[i].iString = m_btnBar.AddString(GetResString(btndata[i][3]));
			else {
				CString s(GetResString(btndata[i][3]));
				s.AppendFormat(_T(" (%s)"), (LPCTSTR)GetResString(IDS_DOWNLOAD));
				atb1[i].iString = m_btnBar.AddString(s);
			}

	}

	m_btnBar.AddButtons(_countof(atb1), atb1);
}

LRESULT CToolbarWnd::OnInitDialog(WPARAM, LPARAM)
{
	static LPCTSTR const sIconNames[15] = {
			  _T("FILEPRIORITY"), _T("PAUSE"), _T("STOP"), _T("RESUME"), _T("DELETE")
			, _T("OPENFILE"), _T("OPENFOLDER"), _T("PREVIEW"), _T("FILEINFO"), _T("FILECOMMENTS")
			, _T("ED2KLINK"), _T("CATEGORY"), _T("CLEARCOMPLETE"), _T("KadFileSearch"), _T("Search") };

	Default();
	InitWindowStyles(this);

	CRect sizeDefault;
	GetWindowRect(&sizeDefault);
	static const RECT rcBorders = { 4, 4, 4, 4 };
	SetBorders(&rcBorders);
	m_szFloat.SetSize(sizeDefault.Width() + rcBorders.left + rcBorders.right + ::GetSystemMetrics(SM_CXEDGE) * 2
		, sizeDefault.Height() + rcBorders.top + rcBorders.bottom + ::GetSystemMetrics(SM_CYEDGE) * 2);
	m_szMRU = m_szFloat;
	UpdateData(FALSE);

	// Initialize the toolbar
	int nFlags = theApp.m_iDfltImageListColorFlags | ILC_MASK;

	CImageList iml;
	iml.Create(16, 16, nFlags, 1, 1);
	for (unsigned i = 0; i < _countof(sIconNames); ++i)
		iml.Add(CTempIconLoader(sIconNames[i]));
	CImageList *pImlOld = m_btnBar.SetImageList(&iml);
	iml.Detach();
	if (pImlOld)
		pImlOld->DeleteImageList();

	m_btnBar.ModifyStyle(TBSTYLE_TRANSPARENT, 0);
	m_btnBar.SetMaxTextRows(0);

	Localize();
	return TRUE;
}

#define	MIN_HORZ_WIDTH	200
#define	MIN_VERT_WIDTH	36

CSize CToolbarWnd::CalcDynamicLayout(int nLength, DWORD dwMode)
{
	CFrameWnd *pFrm = GetDockingFrame();

	// This function is typically called with
	// CSize sizeHorz = m_pBar->CalcDynamicLayout(0, LM_HORZ | LM_HORZDOCK);
	// CSize sizeVert = m_pBar->CalcDynamicLayout(0, LM_VERTDOCK);
	// CSize sizeFloat = m_pBar->CalcDynamicLayout(0, LM_HORZ | LM_MRUWIDTH);

	CRect rcFrmClnt;
	pFrm->GetClientRect(&rcFrmClnt);
	CRect rcInside(rcFrmClnt);
	CalcInsideRect(rcInside, dwMode & LM_HORZDOCK);
	RECT rcBorders = { rcInside.left - rcFrmClnt.left, rcInside.top - rcFrmClnt.top
				 , rcFrmClnt.right - rcInside.right, rcFrmClnt.bottom - rcInside.bottom };

	if (dwMode & (LM_HORZDOCK | LM_VERTDOCK)) {
		if (dwMode & LM_VERTDOCK) {
			CSize szFloat(MIN_VERT_WIDTH
						, rcFrmClnt.Height() + ::GetSystemMetrics(SM_CYEDGE) * 2);
			m_szFloat = szFloat;
			return szFloat;
		}
		if (dwMode & LM_HORZDOCK) {
			CSize szFloat(rcFrmClnt.Width() + ::GetSystemMetrics(SM_CXEDGE) * 2
						, m_sizeDefault.cy + rcBorders.top + rcBorders.bottom);
			m_szFloat = szFloat;
			return szFloat;
		}
		return CDialogBar::CalcDynamicLayout(nLength, dwMode);
	}

	if (dwMode & LM_MRUWIDTH)
		return m_szMRU;

	if (dwMode & LM_COMMIT) {
		m_szMRU = m_szFloat;
		return m_szFloat;
	}

	CSize szFloat;
	if ((dwMode & LM_LENGTHY) == 0) {
		szFloat.cx = nLength;
		if (nLength < m_sizeDefault.cx + rcBorders.left + rcBorders.right)
			szFloat.SetSize(MIN_VERT_WIDTH, MIN_HORZ_WIDTH);
		else
			szFloat.cy = m_sizeDefault.cy + rcBorders.top + rcBorders.bottom;
	} else {
		szFloat.cy = nLength;
		if (nLength < MIN_HORZ_WIDTH) {
			szFloat.SetSize(m_sizeDefault.cx + rcBorders.left + rcBorders.right
				, m_sizeDefault.cy + rcBorders.top + rcBorders.bottom);
		} else
			szFloat.cx = MIN_VERT_WIDTH;
	}

	m_szFloat = szFloat;
	return szFloat;
}

BOOL CToolbarWnd::OnSetCursor(CWnd *pWnd, UINT nHitTest, UINT message)
{
	if (m_hcurMove && ((m_dwStyle & (CBRS_GRIPPER | CBRS_FLOATING)) == CBRS_GRIPPER) && pWnd->GetSafeHwnd() == m_hWnd) {
		CPoint ptCursor;
		if (::GetCursorPos(&ptCursor)) {
			ScreenToClient(&ptCursor);
			CRect rcClnt;
			GetClientRect(&rcClnt);
			if (rcClnt.PtInRect(ptCursor))
				if ((m_dwStyle & CBRS_ORIENT_HORZ ? ptCursor.x : ptCursor.y) <= 10) {
					::SetCursor(m_hcurMove); //mouse over the gripper
					return TRUE;
				}
		}
	}
	return CDialogBar::OnSetCursor(pWnd, nHitTest, message);
}

void CToolbarWnd::OnSize(UINT nType, int cx, int cy)
{
	CDialogBar::OnSize(nType, cx, cy);
	if (m_btnBar.m_hWnd == 0)
		return;

	CRect rcClient;
	GetClientRect(&rcClient);
	if (cx >= MIN_HORZ_WIDTH) {
		CalcInsideRect(rcClient, TRUE);
		m_btnBar.MoveWindow(rcClient.left + 1, rcClient.top, rcClient.Width() - 8, 22);
		//int iWidthOpts = rcClient.right - (rcClient.left + m_rcOpts.left);
		/*HDWP hdwp = BeginDeferWindowPos(0);
		if (hdwp) {
			UINT uFlags = SWP_NOZORDER | SWP_NOACTIVATE;
			//hdwp = DeferWindowPos(hdwp, *GetDlgItem(IDC_MSTATIC3), NULL, rcClient.left + m_rcNameLbl.left, rcClient.top + m_rcNameLbl.top, m_rcNameLbl.Width(), m_rcNameLbl.Height(), uFlags);
			VERIFY( EndDeferWindowPos(hdwp) );
		}*/
	} else { //cx < MIN_HORZ_WIDTH
		CalcInsideRect(rcClient, FALSE);
		m_btnBar.MoveWindow(rcClient.left, rcClient.top + 1, 24, rcClient.Height() - 1);
	}
}

void CToolbarWnd::OnUpdateCmdUI(CFrameWnd* /*pTarget*/, BOOL /*bDisableIfNoHndler*/)
{
	if (m_pCommandTargetWnd != NULL && !theApp.IsClosing()) {
		CList<int> liCommands;
		if (m_pCommandTargetWnd->ReportAvailableCommands(liCommands))
			OnAvailableCommandsChanged(&liCommands);
	}
	// Disable MFC's command routing by not passing the message flow to the base class
}

void CToolbarWnd::OnDestroy()
{
	CDialogBar::OnDestroy();
}

void CToolbarWnd::OnSysColorChange()
{
	CDialogBar::OnSysColorChange();
	//SetAllIcons();
}

void CToolbarWnd::Localize()
{
	SetWindowText(GetResString(IDS_DOWNLOADCOMMANDS));
	FillToolbar();
}

BOOL CToolbarWnd::PreTranslateMessage(MSG *pMsg)
{
	return (pMsg->message != WM_KEYDOWN || pMsg->wParam != VK_ESCAPE) && CDialogBar::PreTranslateMessage(pMsg);
}

BOOL CToolbarWnd::OnHelpInfo(HELPINFO*)
{
	theApp.ShowHelp(eMule_FAQ_GUI_Transfers);
	return TRUE;
}

void CToolbarWnd::OnAvailableCommandsChanged(CList<int> *liCommands)
{
	TBBUTTONINFO tbbi;
	tbbi.cbSize = (UINT)sizeof tbbi;
	tbbi.dwMask = TBIF_COMMAND | TBIF_BYINDEX | TBIF_STATE | TBIF_STYLE;

	for (int i = m_btnBar.GetButtonCount(); --i >= 0;)
		if (m_btnBar.GetButtonInfo(i, &tbbi) >= 0 && (tbbi.fsStyle & BTNS_SEP) == 0)
			m_btnBar.EnableButton(tbbi.idCommand, static_cast<BOOL>(liCommands->Find(tbbi.idCommand) != NULL));
}

BOOL CToolbarWnd::OnCommand(WPARAM wParam, LPARAM)
{
	if (LOWORD(wParam) == MP_TOGGLEDTOOLBAR) {
		theApp.emuledlg->transferwnd->ShowToolbar(false);
		thePrefs.SetDownloadToolbar(false);
	} else if (m_pCommandTargetWnd != 0)
		m_pCommandTargetWnd->SendMessage(WM_COMMAND, wParam, 0);
	return TRUE;
}

void CToolbarWnd::OnBtnDropDown(LPNMHDR pNMHDR, LRESULT *pResult)
{
	TBNOTIFY *tbn = (TBNOTIFY*)pNMHDR;
	if (tbn->iItem == MP_PRIOLOW) {
		RECT rc;
		m_btnBar.GetItemRect(m_btnBar.CommandToIndex(MP_PRIOLOW), &rc);
		m_btnBar.ClientToScreen(&rc);
		m_pCommandTargetWnd->GetPrioMenu()->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, rc.left, rc.bottom, this);
	} else if (tbn->iItem == MP_NEWCAT) {
		RECT rc;
		m_btnBar.GetItemRect(m_btnBar.CommandToIndex(MP_NEWCAT), &rc);
		m_btnBar.ClientToScreen(&rc);
		CMenu menu;
		menu.CreatePopupMenu();
		m_pCommandTargetWnd->FillCatsMenu(menu);
		menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, rc.left, rc.bottom, this);
	} else
		ASSERT(0);
	*pResult = TBDDRET_DEFAULT;
}

void CToolbarWnd::OnContextMenu(CWnd*, CPoint point)
{
	CMenu menu;
	menu.CreatePopupMenu();
	menu.AppendMenu(MF_STRING, MP_TOGGLEDTOOLBAR, GetResString(IDS_CLOSETOOLBAR));
	menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);
}

void CToolbarWnd::DelayShow(BOOL bShow)
{
	// Yes, it is somewhat ugly but still the best way (without partially rewriting 3 MFC classes)
	// to know if the user clicked on the Close-Button of our floating Bar
	if (!bShow && m_pDockSite != NULL && m_pDockBar != NULL) {
		if (m_pDockBar->m_bFloating) {
			CWnd *pDockFrame = m_pDockBar->GetParent();
			ASSERT(pDockFrame != NULL);
			if (pDockFrame != NULL) {
				CPoint point;
				::GetCursorPos(&point);
				LRESULT res = pDockFrame->SendMessage(WM_NCHITTEST, 0, MAKELONG(point.x, point.y));
				if (res == HTCLOSE)
					thePrefs.SetDownloadToolbar(false);
			}
		}
	}
	__super::DelayShow(bShow);
}

void CToolbarWnd::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) != SC_KEYMENU)
		__super::OnSysCommand(nID, lParam);
	else if (lParam == EMULE_HOTMENU_ACCEL)
		theApp.emuledlg->SendMessage(WM_COMMAND, IDC_HOTMENU);
	else
		theApp.emuledlg->SendMessage(WM_SYSCOMMAND, nID, lParam);
}