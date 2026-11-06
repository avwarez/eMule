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

// The bar under the toolbar that tells the user Windows Firewall blocks the inbound connections,
// like the information bar of the old browsers: a click on it opens a menu to open the ports
// (as administrator) or to ignore the warning until the firewall state changes again.
class CFirewallBar : public CWnd
{
public:
	CFirewallBar();

	bool CreateBar(CWnd *pParent);
	int GetHeight();
	void SetCanAllow(bool bCanAllow)		{ m_bCanAllow = bCanAllow; }

protected:
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC*)			{ return TRUE; }
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	DECLARE_MESSAGE_MAP()

private:
	HICON	m_hIcon;
	bool	m_bCanAllow;
};
