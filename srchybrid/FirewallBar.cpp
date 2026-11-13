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
#include "FirewallBar.h"
#include "emule.h"
#include "emuledlg.h"
#include "FirewallCheck.h"
#include "OtherFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace
{
	const UINT MP_FIREWALL_ALLOW = 1;
	const UINT MP_FIREWALL_IGNORE = 2;
}

BEGIN_MESSAGE_MAP(CFirewallBar, CWnd)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_LBUTTONUP()
END_MESSAGE_MAP()

CFirewallBar::CFirewallBar()
	: m_hIcon()
	, m_bCanAllow()
{
}

bool CFirewallBar::CreateBar(CWnd *pParent)
{
	const int iIconSize = ::GetSystemMetrics(SM_CXSMICON);
	m_hIcon = (HICON)::LoadImage(NULL, IDI_WARNING, IMAGE_ICON, iIconSize, iIconSize, LR_SHARED);
	LPCTSTR pszClass = AfxRegisterWndClass(CS_HREDRAW | CS_VREDRAW, ::LoadCursor(NULL, IDC_HAND));
	if (!CreateEx(0, pszClass, GetResString(IDS_FIREWALLBAR_TEXT), WS_CHILD | WS_CLIPSIBLINGS, CRect(), pParent, 0))
		return false;
	SetFont(pParent->GetFont(), FALSE);
	return true;
}

// One line of text, or the icon if it is taller, with some room above and below.
int CFirewallBar::GetHeight()
{
	CClientDC dc(this);
	CFont *pOldFont = dc.SelectObject(GetFont());
	TEXTMETRIC tm;
	dc.GetTextMetrics(&tm);
	dc.SelectObject(pOldFont);
	return max(tm.tmHeight, ::GetSystemMetrics(SM_CYSMICON)) + tm.tmHeight / 2;
}

void CFirewallBar::OnPaint()
{
	CPaintDC dc(this);
	CRect rc;
	GetClientRect(&rc);
	dc.FillSolidRect(&rc, ::GetSysColor(COLOR_INFOBK));
	dc.FillSolidRect(rc.left, rc.bottom - 1, rc.Width(), 1, ::GetSysColor(COLOR_3DSHADOW));

	const int iIconSize = ::GetSystemMetrics(SM_CXSMICON);
	const int iMargin = iIconSize / 2;
	if (m_hIcon != NULL)
		::DrawIconEx(dc, rc.left + iMargin, rc.top + (rc.Height() - iIconSize) / 2, m_hIcon, iIconSize, iIconSize, 0, NULL, DI_NORMAL);

	CFont *pOldFont = dc.SelectObject(GetFont());
	dc.SetBkMode(TRANSPARENT);
	dc.SetTextColor(::GetSysColor(COLOR_INFOTEXT));
	rc.left += iMargin + iIconSize + iMargin;
	dc.DrawText(GetResString(IDS_FIREWALLBAR_TEXT), &rc, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
	dc.SelectObject(pOldFont);
}

void CFirewallBar::OnLButtonUp(UINT /*nFlags*/, CPoint point)
{
	CMenu menu;
	if (!menu.CreatePopupMenu())
		return;
	menu.AppendMenu(MF_STRING | (m_bCanAllow ? 0 : MF_GRAYED), MP_FIREWALL_ALLOW, GetResString(IDS_FIREWALLBAR_ALLOW));
	menu.AppendMenu(MF_STRING, MP_FIREWALL_IGNORE, GetResString(IDS_FIREWALLBAR_IGNORE));
	ClientToScreen(&point);
	switch (menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_NONOTIFY, point.x, point.y, this)) {
	case MP_FIREWALL_ALLOW:
		if (theApp.m_pFirewallCheck != NULL)
			theApp.m_pFirewallCheck->OpenPorts(GetParent()->m_hWnd);
		break;
	case MP_FIREWALL_IGNORE:
		theApp.emuledlg->ShowFirewallBar(false);
	}
}
