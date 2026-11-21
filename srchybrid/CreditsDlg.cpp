/*
	You may NOT modify this copyright message. You may add your name, if you
	changed or improved this code, but you mot not delete any part of this message or
	make it invisible etc.
*/
#include "stdafx.h"
#include "emule.h"
#include "CreditsDlg.h"
#include "CreditsThread.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


// drawable area of the dialog
#define SCREEN_LEFT		6
#define SCREEN_TOP		175
#define SCREEN_RIGHT	345
#define SCREEN_BOTTOM	296

const RECT CCreditsDlg::m_rectScreen = { SCREEN_LEFT, SCREEN_TOP, SCREEN_RIGHT, SCREEN_BOTTOM };

/////////////////////////////////////////////////////////////////////////////
// CCreditsDlg dialog


CCreditsDlg::CCreditsDlg(CWnd *pParent /*=NULL*/)
	: CDialog(CCreditsDlg::IDD, pParent)
	, m_pDC()
	, m_pThread()
{
}

CCreditsDlg::~CCreditsDlg()
{
	m_imgSplash.DeleteObject();
}

BEGIN_MESSAGE_MAP(CCreditsDlg, CDialog)
	ON_WM_LBUTTONDOWN()
	ON_WM_DESTROY()
	ON_WM_CREATE()
	ON_WM_PAINT()
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CCreditsDlg message handlers

/// <summary>
///
/// </summary>
/// <returns></returns>
BOOL CCreditsDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	VERIFY(m_imgSplash.Attach(theApp.LoadImage(_T("ABOUT"), _T("JPG"))));
	StartThread();

	return TRUE;
}

void CCreditsDlg::OnDestroy()
{
	KillThread();

	delete m_pDC;
	m_pDC = NULL;

	CDialog::OnDestroy();
}

void CCreditsDlg::StartThread()
{
	try {
		m_pThread = new CCreditsThread(this, m_pDC->GetSafeHdc(), &m_rectScreen);
		((CCreditsThread*)m_pThread)->SetRunning(true);
	} catch (...) {
		DebugLogCaughtException(__FUNCTION__);
		m_pThread = NULL;
		return;
	}

	// Create Thread in suspended state so we can set the Priority
	// before it starts getting away from us
	if (m_pThread->CreateThread(CREATE_SUSPENDED)) {
		// set idle priority to keep the thread from bogging down
		// other things that are running
		VERIFY(m_pThread->SetThreadPriority(THREAD_PRIORITY_IDLE));
		// Now the thread can run wild
		m_pThread->ResumeThread();
	} else {
		delete m_pThread;
		m_pThread = NULL;
	}
}

void CCreditsDlg::KillThread()
{
	if (m_pThread) {
		// tell the thread to exit
		((CCreditsThread*)m_pThread)->SetRunning(false);
		// wait for the thread to finish shutdown
		VERIFY(::WaitForSingleObject(m_pThread->m_hThread, INFINITE) == WAIT_OBJECT_0);
		m_pThread = NULL;
	}
}

int CCreditsDlg::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CDialog::OnCreate(lpCreateStruct) == -1)
		return -1;

	// m_pDC must be initialized here instead of the constructor
	// because the HWND isn't created until Create is called.
	m_pDC = new CClientDC(this);

	return 0;
}

void CCreditsDlg::OnPaint()
{
	if (!m_imgSplash.GetSafeHandle())
		return;

	CDC dcMem;
	CPaintDC dc(this); // device context for painting
	if (dcMem.CreateCompatibleDC(&dc)) {
		CBitmap *pOldBmp = dcMem.SelectObject(&m_imgSplash);
		BITMAP bmp;
		m_imgSplash.GetBitmap(&bmp);

		RECT rSplash;
		GetWindowRect(&rSplash);
		SetWindowPos(NULL, rSplash.left, rSplash.top, bmp.bmWidth, bmp.bmHeight, SWP_NOCOPYBITS | SWP_NOREDRAW | SWP_NOZORDER | SWP_NOSENDCHANGING);

		dc.BitBlt(0, 0, bmp.bmWidth, bmp.bmHeight, &dcMem, 0, 0, SRCCOPY);
		dcMem.SelectObject(pOldBmp);
	}
}

BOOL CCreditsDlg::PreTranslateMessage(MSG *pMsg)
{
	switch (pMsg->message) {
	case WM_KEYDOWN:
	case WM_SYSKEYDOWN:
	case WM_LBUTTONDOWN:
	case WM_RBUTTONDOWN:
	case WM_MBUTTONDOWN:
	case WM_NCLBUTTONDOWN:
	case WM_NCRBUTTONDOWN:
	case WM_NCMBUTTONDOWN:
		EndDialog(IDOK);
	}
	return CDialog::PreTranslateMessage(pMsg);
}