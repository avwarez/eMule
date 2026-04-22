/*CAsyncSocketEx by Tim Kosse (tim.kosse@filezilla-project.org)
			Version 1.3 (2003-04-26)
--------------------------------------------------------

Introduction:
-------------

CAsyncSocketEx is a replacement for the MFC class CAsyncSocket.
This class was written because CAsyncSocket is not the fastest WinSock
wrapper and it's very hard to add new functionality to CAsyncSocket
derived classes. This class offers the same functionality as CAsyncSocket.
Also, CAsyncSocketEx offers some enhancements which were not possible with
CAsyncSocket derived classes. This class offers the same functionality as CAsyncSocket.

License
-------

Feel free to use this class, as long as you don't claim that you wrote it
and this copyright notice stays intact in the source files.
If you use this class in commercial applications, please send a short message
to tim.kosse@filezilla-project.org
*/

#include "stdafx.h"
#include "DebugHelpers.h"
#include "AsyncSocketEx.h"
#include "AsyncSocketExLayer.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <algorithm>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

THREADLOCAL CAsyncSocketEx::t_AsyncSocketExThreadData *CAsyncSocketEx::thread_local_data = NULL;

// ---------------------------------------------------------------------------
// Internal message used to deliver async DNS results to the helper window.
// Chosen below the existing WM_SOCKETEX_TRIGGER range to avoid conflicts.
//
// Cross-platform note: this is the only remaining Windows-message-based
// mechanism.  For a native Linux port, replace PostMessage + this handler
// with a platform-agnostic callback queue (e.g. eventfd + std::queue).
// ---------------------------------------------------------------------------
#define WM_SOCKETEX_DNSRESULT  (WM_USER + 0x100)   // 0x0500

// Heap-allocated struct carried in the lParam of WM_SOCKETEX_DNSRESULT.
// hSentinel is a monotonic uint64 request-ID cast into HANDLE for ABI compat
// with the existing m_hAsyncGetHostByNameHandle field.  The ID is produced by
// a process-wide atomic counter (see g_nDnsNextRequestId) and is guaranteed
// never to be reused for the lifetime of the process — so a stale DNS message
// that arrives after Close() + re-Connect() can never accidentally match a
// different socket's sentinel.  (The old scheme used m_dnsCancelFlag.get(),
// a heap address that malloc is free to reuse once the shared_ptr drops.)
struct DnsResultMsg
{
	HANDLE     hSentinel;   // matches CAsyncSocketEx::m_hAsyncGetHostByNameHandle
	int        nErrorCode;  // 0 = success
	SOCKADDR_IN addr;       // valid when nErrorCode == 0
};

// Monotonic DNS-request ID generator.  Starts at 1 so that 0 (NULL HANDLE)
// always means "no request in flight".  fetch_add with relaxed ordering is
// sufficient: the value is published via the channel mutex + message queue.
// uintptr_t matches the width of HANDLE on both 32-bit and 64-bit builds, so
// no truncation is ever required when casting to the sentinel field.
static std::atomic<uintptr_t> g_nDnsNextRequestId{1};

// ---------------------------------------------------------------------------
// DnsChannel — liveness bridge between CAsyncSocketExHelperWindow and any
// in-flight DNS threads that will PostMessage to its HWND.
//
// Problem solved: a detached std::thread captures a raw HWND; if the helper
// window is destroyed while the thread is still running (e.g. during
// application shutdown), PostMessage to the stale HWND is undefined behaviour.
//
// Solution: the helper window owns a shared_ptr<DnsChannel>.  DNS threads
// capture the same shared_ptr by value.  The window's destructor nullifies
// hwnd *under the mutex* before calling DestroyWindow.  The DNS thread takes
// the same mutex before reading hwnd and calling PostMessage, so the two
// operations are mutually exclusive:
//   - If the thread wins: it sees a valid hwnd, posts the message, releases
//     the mutex.  The destructor then nullifies and destroys.
//   - If the destructor wins: hwnd is already NULL when the thread checks,
//     the thread discards the result cleanly.
//
// Cross-platform note: on a POSIX port replace hwnd/PostMessage with
// a std::function<void(DnsResultMsg*)> callback protected by the same mutex.
// ---------------------------------------------------------------------------
struct DnsChannel {
	std::mutex mutex;
	HWND       hwnd;
	explicit DnsChannel(HWND h) noexcept : hwnd(h) {}
	DnsChannel(const DnsChannel&) = delete;
	DnsChannel& operator=(const DnsChannel&) = delete;
};

// ---------------------------------------------------------------------------
// CSocketDispatchThread
//
// Replaces WSAAsyncSelect + the HWND-based event source.
// One instance lives inside CAsyncSocketExHelperWindow (one per thread).
//
// Responsibilities:
//   - Register sockets with WSAEventSelect (sets non-blocking mode too).
//   - Run a background thread that waits on a shared WSAEVENT.
//   - When any socket has network events, enumerate them and PostMessage
//     to the helper window exactly as WSAAsyncSelect would have done.
//
// Cross-platform migration path:
//   Phase 2 (Linux):  replace the WSAEventSelect/WSAEnumNetworkEvents calls
//   with poll(2)/epoll_wait(2).  Replace PostMessage with a platform-agnostic
//   delivery mechanism (eventfd + queue).  The dispatch loop logic is identical.
// ---------------------------------------------------------------------------
class CSocketDispatchThread
{
public:
	explicit CSocketDispatchThread(HWND hWnd)
		: m_hWnd(hWnd)
		, m_bRunning(true)
	{
		m_hSharedEvent = WSACreateEvent();
		ASSERT(m_hSharedEvent != WSA_INVALID_EVENT);
		m_thread = std::thread([this] { RunInternal(); });
	}

	~CSocketDispatchThread()
	{
		m_bRunning = false;
		WSASetEvent(m_hSharedEvent); // wake thread so it sees m_bRunning == false
		if (m_thread.joinable())
			m_thread.join();
		WSACloseEvent(m_hSharedEvent);
	}

	CSocketDispatchThread(const CSocketDispatchThread&) = delete;
	CSocketDispatchThread& operator=(const CSocketDispatchThread&) = delete;

	// Called from the main thread when a socket is attached or its event mask changes.
	// WSAEventSelect sets the socket to non-blocking mode automatically.
	void AddSocket(SOCKET hSocket, int nSocketIndex, long lEvents)
	{
		if (hSocket == INVALID_SOCKET)
			return;
		WSAEventSelect(hSocket, m_hSharedEvent, lEvents);
		{
			std::lock_guard<std::mutex> lock(m_pendingMutex);
			m_pending.push_back({Op::ADD, hSocket, nSocketIndex});
		}
		WSASetEvent(m_hSharedEvent);
	}

	// Called from the main thread when a socket is detached (before or after close).
	void RemoveSocket(SOCKET hSocket)
	{
		if (hSocket == INVALID_SOCKET)
			return;
		WSAEventSelect(hSocket, NULL, 0); // deregister
		{
			std::lock_guard<std::mutex> lock(m_pendingMutex);
			m_pending.push_back({Op::REMOVE, hSocket, -1});
		}
		WSASetEvent(m_hSharedEvent);
	}

private:
	struct SocketEntry
	{
		SOCKET hSocket;
		int    nSocketIndex;
	};

	struct Op
	{
		enum Type { ADD, REMOVE } type;
		SOCKET hSocket;
		int    nSocketIndex;
	};

	HWND             m_hWnd;
	WSAEVENT         m_hSharedEvent;
	std::atomic<bool> m_bRunning;

	std::mutex       m_pendingMutex;
	std::vector<Op>  m_pending;

	// Owned exclusively by the dispatch thread — no locking needed:
	std::vector<SocketEntry> m_sockets;

	std::thread m_thread;

	// -----------------------------------------------------------------------
	void RunInternal()
	{
		while (m_bRunning) {
			// --- Apply pending add/remove operations ----------------------
			{
				std::vector<Op> pending;
				{
					std::lock_guard<std::mutex> lock(m_pendingMutex);
					pending.swap(m_pending);
				}
				for (const Op &op : pending) {
					if (op.type == Op::ADD) {
						auto it = std::find_if(m_sockets.begin(), m_sockets.end(),
							[&](const SocketEntry &e) { return e.hSocket == op.hSocket; });
						if (it == m_sockets.end())
							m_sockets.push_back({op.hSocket, op.nSocketIndex});
						else
							it->nSocketIndex = op.nSocketIndex; // update index (re-attach)
					} else {
						m_sockets.erase(
							std::remove_if(m_sockets.begin(), m_sockets.end(),
								[&](const SocketEntry &e){ return e.hSocket == op.hSocket; }),
							m_sockets.end());
					}
				}
			}

			// --- Wait for any socket event (or wakeup) --------------------
			WSAWaitForMultipleEvents(1, &m_hSharedEvent, FALSE, 100 /*ms*/, FALSE);

			if (!m_bRunning)
				break;

			// Reset BEFORE enumeration: new events arriving during enumeration
			// will immediately re-signal the event and be caught next iteration.
			WSAResetEvent(m_hSharedEvent);

			// --- Enumerate all sockets for pending network events ---------
			for (const SocketEntry &e : m_sockets) {
				WSANETWORKEVENTS ne = {};
				if (WSAEnumNetworkEvents(e.hSocket, NULL, &ne) == SOCKET_ERROR)
					continue; // socket closed/invalid — pending REMOVE will clean it up

				if (!ne.lNetworkEvents)
					continue;

				// Post one message per event type, matching the format that
				// the original WSAAsyncSelect notifications used, so the
				// existing WindowProc dispatch logic is completely unchanged.
				auto post = [&](int event, int bitIndex) {
					if (ne.lNetworkEvents & event)
						::PostMessage(m_hWnd,
							WM_SOCKETEX_NOTIFY + e.nSocketIndex,
							(WPARAM)e.hSocket,
							MAKELPARAM(event, ne.iErrorCode[bitIndex]));
				};
				post(FD_READ,    FD_READ_BIT);
				post(FD_WRITE,   FD_WRITE_BIT);
				post(FD_CONNECT, FD_CONNECT_BIT);
				post(FD_CLOSE,   FD_CLOSE_BIT);
				post(FD_ACCEPT,  FD_ACCEPT_BIT);
				post(FD_OOB,     FD_OOB_BIT);
			}
		}
	}
};

// ---------------------------------------------------------------------------
// Helper Window
// ---------------------------------------------------------------------------

class CAsyncSocketExHelperWindow
{
public:
	explicit CAsyncSocketExHelperWindow(CAsyncSocketEx::t_AsyncSocketExThreadData *pThreadData)
		: m_nWindowDataSize(512)
		, m_nWindowDataPos()
		, m_nSocketCount()
		, m_pThreadData(pThreadData)
		, m_pDispatcher(nullptr)
	{
		static LPCTSTR const sHelperWnd = _T("CAsyncSocketEx Helper Window");
		m_pAsyncSocketExWindowData = new t_AsyncSocketExWindowData[m_nWindowDataSize]{};

		WNDCLASSEX wndclass{};
		wndclass.cbSize = (UINT)sizeof wndclass;
		wndclass.lpfnWndProc = WindowProc;
		wndclass.hInstance = ::GetModuleHandle(NULL);
		wndclass.lpszClassName = sHelperWnd;
		::RegisterClassEx(&wndclass);

		m_hWnd = ::CreateWindow(sHelperWnd, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, 0);
		if (m_hWnd)
			::SetWindowLongPtr(m_hWnd, GWLP_USERDATA, (LONG_PTR)this);
		else
			ASSERT(0);

		// DnsChannel must be created before the dispatch thread (and certainly
		// before any DNS thread) so all parties share the same channel.
		m_dnsChannel = std::make_shared<DnsChannel>(m_hWnd);

		// Create the dispatch thread AFTER the window is ready,
		// so PostMessage in the thread has a valid HWND.
		m_pDispatcher = new CSocketDispatchThread(m_hWnd);
	}

	virtual ~CAsyncSocketExHelperWindow()
	{
		// Nullify the DNS channel FIRST, under its mutex, so any in-flight
		// DNS thread that is about to PostMessage will see hwnd==NULL and
		// discard its result instead of posting to a destroyed window.
		// This must happen before DestroyWindow, not after.
		{
			std::lock_guard<std::mutex> lk(m_dnsChannel->mutex);
			m_dnsChannel->hwnd = NULL;
		}

		// Stop the dispatch thread before destroying the window it posts to.
		delete m_pDispatcher;
		m_pDispatcher = nullptr;

		delete[] m_pAsyncSocketExWindowData;
		m_pAsyncSocketExWindowData = NULL;
		m_nWindowDataSize = 0;
		m_nSocketCount = 0;

		if (m_hWnd) {
			DestroyWindow(m_hWnd);
			m_hWnd = 0;
		}
	}

	CAsyncSocketExHelperWindow(const CAsyncSocketExHelperWindow&) = delete;
	CAsyncSocketExHelperWindow& operator=(const CAsyncSocketExHelperWindow&) = delete;

	BOOL AddSocket(CAsyncSocketEx *pSocket, int &nSocketIndex)
	{
		if (!pSocket) {
			ASSERT(0);
			return FALSE;
		}
		if (!m_nWindowDataSize) {
			ASSERT(!m_nSocketCount);
			m_nWindowDataSize = 512;
			m_pAsyncSocketExWindowData = new t_AsyncSocketExWindowData[512]{};
		}

		if (nSocketIndex >= 0) {
			ASSERT(m_pAsyncSocketExWindowData);
			ASSERT(m_nWindowDataSize > nSocketIndex);
			ASSERT(m_pAsyncSocketExWindowData[nSocketIndex].m_pSocket == pSocket);
			ASSERT(m_nSocketCount);
			return m_pAsyncSocketExWindowData != NULL;
		}

		// Grow if needed
		if (m_nSocketCount >= m_nWindowDataSize - 10) {
			int nOldWindowDataSize = m_nWindowDataSize;
			ASSERT(m_nWindowDataSize < MAX_SOCKETS);
			m_nWindowDataSize += 512;
			if (m_nWindowDataSize > MAX_SOCKETS)
				m_nWindowDataSize = MAX_SOCKETS;
			t_AsyncSocketExWindowData *tmp = m_pAsyncSocketExWindowData;
			m_pAsyncSocketExWindowData = new t_AsyncSocketExWindowData[m_nWindowDataSize];
			memcpy(m_pAsyncSocketExWindowData, tmp, nOldWindowDataSize * sizeof(t_AsyncSocketExWindowData));
			memset(&m_pAsyncSocketExWindowData[nOldWindowDataSize], 0,
				(m_nWindowDataSize - nOldWindowDataSize) * sizeof(t_AsyncSocketExWindowData));
			delete[] tmp;
		}

		for (int i = m_nWindowDataPos; i < m_nWindowDataSize + m_nWindowDataPos; ++i) {
			int idx = i % m_nWindowDataSize;
			if (!m_pAsyncSocketExWindowData[idx].m_pSocket) {
				m_pAsyncSocketExWindowData[idx].m_pSocket = pSocket;
				nSocketIndex = idx;
				m_nWindowDataPos = (i + 1) % m_nWindowDataSize;
				++m_nSocketCount;
				return TRUE;
			}
		}
		return FALSE;
	}

	// hOld: the socket handle at the time of detach (may differ from pSocket->m_SocketData.hSocket
	// which is already INVALID_SOCKET by the time this is called from DetachHandle).
	BOOL RemoveSocket(const CAsyncSocketEx *pSocket, int &nSocketIndex, SOCKET hOld = INVALID_SOCKET)
	{
		if (!pSocket) {
			ASSERT(0);
			return FALSE;
		}
		if (nSocketIndex >= 0) {
			// Remove queued socket notifications for this slot
			MSG msg;
			while (::PeekMessage(&msg, m_hWnd,
				WM_SOCKETEX_NOTIFY + nSocketIndex,
				WM_SOCKETEX_NOTIFY + nSocketIndex, PM_REMOVE));

			// Tell the dispatch thread to stop watching this socket.
			// Use hOld since pSocket->m_SocketData.hSocket is already INVALID_SOCKET.
			if (m_pDispatcher && hOld != INVALID_SOCKET)
				m_pDispatcher->RemoveSocket(hOld);

			ASSERT(m_pAsyncSocketExWindowData);
			ASSERT(m_nWindowDataSize > 0);
			ASSERT(m_nSocketCount > 0);
			ASSERT(m_pAsyncSocketExWindowData[nSocketIndex].m_pSocket == pSocket);
			m_pAsyncSocketExWindowData[nSocketIndex].m_pSocket = NULL;
			nSocketIndex = -1;
			--m_nSocketCount;
		}
		return TRUE;
	}

	void RemoveLayers(const CAsyncSocketEx *pOrigSocket)
	{
		std::vector<MSG> msgList;
		for (MSG msg; ::PeekMessage(&msg, m_hWnd, WM_SOCKETEX_TRIGGER, WM_SOCKETEX_TRIGGER, PM_REMOVE);) {
			if (msg.wParam >= static_cast<WPARAM>(m_nWindowDataSize))
				continue;
			const CAsyncSocketEx *pSocket = m_pAsyncSocketExWindowData[msg.wParam].m_pSocket;
			CAsyncSocketExLayer::t_LayerNotifyMsg *pMsg = reinterpret_cast<CAsyncSocketExLayer::t_LayerNotifyMsg*>(msg.lParam);
			if (!pMsg || !pSocket || pSocket->m_SocketData.hSocket == INVALID_SOCKET
				|| pSocket == pOrigSocket || pSocket->m_SocketData.hSocket != pMsg->hSocket)
				delete pMsg;
			else
				msgList.push_back(msg);
		}
		for (const MSG &m : msgList)
			if (!::PostMessage(m_hWnd, m.message, m.wParam, m.lParam))
				delete reinterpret_cast<CAsyncSocketExLayer::t_LayerNotifyMsg*>(m.lParam);
	}

	// Returns the shared DNS channel so DNS threads can validate window liveness.
	std::shared_ptr<DnsChannel> GetDnsChannel() const { return m_dnsChannel; }

	// Register (or update) a socket with the dispatch thread.
	// Called by CAsyncSocketEx::AsyncSelect.
	void RegisterSocket(SOCKET hSocket, int nSocketIndex, long lEvents)
	{
		if (m_pDispatcher)
			m_pDispatcher->AddSocket(hSocket, nSocketIndex, lEvents);
	}

	static LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		if (message >= WM_SOCKETEX_NOTIFY) {
			ASSERT(hWnd);
			CAsyncSocketExHelperWindow *pWnd =
				reinterpret_cast<CAsyncSocketExHelperWindow*>(::GetWindowLongPtr(hWnd, GWLP_USERDATA));
			if (!pWnd) {
				ASSERT(0);
				return 0;
			}

			if (message < static_cast<UINT>(WM_SOCKETEX_NOTIFY + pWnd->m_nWindowDataSize)) {
				CAsyncSocketEx *pSocket = pWnd->m_pAsyncSocketExWindowData[message - WM_SOCKETEX_NOTIFY].m_pSocket;
				if (!pSocket)
					return 0;
				SOCKET hSocket = wParam;
				if (hSocket == INVALID_SOCKET || pSocket->m_SocketData.hSocket != hSocket)
					return 0;

				int nEvent     = (int)WSAGETSELECTEVENT(lParam);
				int nErrorCode = (int)WSAGETSELECTERROR(lParam);

				if (!pSocket->m_pFirstLayer) {
					switch (nEvent) {
					case FD_READ:
					case FD_FORCEREAD:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() == connecting && !nErrorCode) {
							pSocket->m_nPendingEvents |= nEvent;
							break;
						}
						if (pSocket->GetState() == attached)
							pSocket->SetState(connected);
						if (pSocket->GetState() != connected)
							break;
						if (pSocket->m_SocketData.bIsClosing && nEvent != FD_FORCEREAD)
							break;
						if (nErrorCode)
							pSocket->SetState(aborted);
#endif
						if (pSocket->m_lEvent & FD_READ)
							pSocket->OnReceive(nErrorCode);
						break;
					case FD_WRITE:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() == connecting && !nErrorCode) {
							pSocket->m_nPendingEvents |= FD_WRITE;
							break;
						}
						if (pSocket->GetState() == attached && !nErrorCode)
							pSocket->SetState(connected);
						if (pSocket->GetState() != connected)
							break;
						if (nErrorCode)
							pSocket->SetState(aborted);
#endif
						if (pSocket->m_lEvent & FD_WRITE)
							pSocket->OnSend(nErrorCode);
						break;
					case FD_CONNECT:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() == connecting) {
							if (nErrorCode && pSocket->m_SocketData.nextAddr && pSocket->TryNextProtocol())
								break;
							pSocket->SetState(connected);
						} else if (pSocket->GetState() == attached && !nErrorCode)
							pSocket->SetState(connected);
#endif
						if (pSocket->m_lEvent & FD_CONNECT)
							pSocket->OnConnect(nErrorCode);
#ifndef NOSOCKETSTATES
						if (!nErrorCode && pWnd->m_pAsyncSocketExWindowData
							&& pSocket == pWnd->m_pAsyncSocketExWindowData[message - WM_SOCKETEX_NOTIFY].m_pSocket) {
							if ((pSocket->m_nPendingEvents & (FD_READ | FD_FORCEREAD)) && pSocket->GetState() == connected)
								pSocket->OnReceive(0);
							if ((pSocket->m_nPendingEvents & FD_WRITE) && pSocket->GetState() == connected)
								pSocket->OnSend(0);
						}
						pSocket->m_nPendingEvents = 0;
#endif
						break;
					case FD_ACCEPT:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() != listening && pSocket->GetState() != attached)
							break;
#endif
						if (pSocket->m_lEvent & FD_ACCEPT)
							pSocket->OnAccept(nErrorCode);
						break;
					case FD_CLOSE:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() != connected && pSocket->GetState() != attached)
							break;
						{
							DWORD nBytes;
							if (!nErrorCode && pSocket->IOCtl(FIONREAD, &nBytes) && nBytes > 0) {
								pSocket->ResendCloseNotify();
								pSocket->m_SocketData.bIsClosing = true;
								pSocket->OnReceive(WSAESHUTDOWN);
								break;
							}
						}
						pSocket->SetState(nErrorCode ? aborted : closed);
#endif
						pSocket->OnClose(nErrorCode);
						break;
					}
				} else {
					if (nEvent == FD_READ) {
						if (pSocket->m_SocketData.bIsClosing)
							return 0;
						DWORD nBytes;
						if (!pSocket->IOCtl(FIONREAD, &nBytes))
							nErrorCode = WSAGetLastError();
					} else if (nEvent == FD_CLOSE) {
						DWORD nBytes;
						if (!nErrorCode && pSocket->IOCtl(FIONREAD, &nBytes) && nBytes > 0) {
							pSocket->ResendCloseNotify();
							nEvent = FD_READ;
						} else
							pSocket->m_SocketData.bIsClosing = true;
					}
					if (pSocket->m_pLastLayer)
						pSocket->m_pLastLayer->CallEvent(nEvent, nErrorCode);
				}
			}
			return 0;
		}

		switch (message) {
		case WM_SOCKETEX_TRIGGER:
			{
				ASSERT(hWnd);
				CAsyncSocketExHelperWindow *pWnd =
					reinterpret_cast<CAsyncSocketExHelperWindow*>(::GetWindowLongPtr(hWnd, GWLP_USERDATA));
				ASSERT(pWnd);
				if (!pWnd || wParam >= static_cast<WPARAM>(pWnd->m_nWindowDataSize))
					return 0;

				CAsyncSocketEx *pSocket = pWnd->m_pAsyncSocketExWindowData[wParam].m_pSocket;
				CAsyncSocketExLayer::t_LayerNotifyMsg *pMsg =
					reinterpret_cast<CAsyncSocketExLayer::t_LayerNotifyMsg*>(lParam);
				if (!pMsg || !pSocket || pSocket->m_SocketData.hSocket == INVALID_SOCKET
					|| pSocket->m_SocketData.hSocket != pMsg->hSocket) {
					delete pMsg;
					return 0;
				}
				int nEvent     = WSAGETSELECTEVENT(pMsg->lEvent);
				int nErrorCode = WSAGETSELECTERROR(pMsg->lEvent);

				if (pMsg->pLayer)
					pMsg->pLayer->CallEvent(nEvent, nErrorCode);
				else {
					switch (nEvent) {
					case FD_READ:
					case FD_FORCEREAD:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() == connecting && !nErrorCode) {
							pSocket->m_nPendingEvents |= nEvent;
							break;
						}
						if (pSocket->GetState() == attached && !nErrorCode)
							pSocket->SetState(connected);
						if (pSocket->GetState() != connected)
							break;
						if (nErrorCode)
							pSocket->SetState(aborted);
#endif
						if (pSocket->m_lEvent & FD_READ)
							pSocket->OnReceive(nErrorCode);
						break;
					case FD_WRITE:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() == connecting && !nErrorCode) {
							pSocket->m_nPendingEvents |= FD_WRITE;
							break;
						}
						if (pSocket->GetState() == attached && !nErrorCode)
							pSocket->SetState(connected);
						if (pSocket->GetState() != connected)
							break;
						if (nErrorCode)
							pSocket->SetState(aborted);
#endif
						if (pSocket->m_lEvent & FD_WRITE)
							pSocket->OnSend(nErrorCode);
						break;
					case FD_CONNECT:
#ifndef NOSOCKETSTATES
						if (pSocket->GetState() == connecting)
							pSocket->SetState(connected);
						else if (pSocket->GetState() == attached && !nErrorCode)
							pSocket->SetState(connected);
#endif
						if (pSocket->m_lEvent & FD_CONNECT)
							pSocket->OnConnect(nErrorCode);
#ifndef NOSOCKETSTATES
						if (!nErrorCode && pSocket->GetState() == connected) {
							if ((pSocket->m_nPendingEvents & FD_READ) && pSocket->m_lEvent & FD_READ)
								pSocket->OnReceive(0);
							if ((pSocket->m_nPendingEvents & FD_FORCEREAD) && pSocket->m_lEvent & FD_READ)
								pSocket->OnReceive(0);
							if (pSocket->m_nPendingEvents & FD_WRITE && pSocket->m_lEvent & FD_WRITE)
								pSocket->OnSend(0);
						}
						pSocket->m_nPendingEvents = 0;
#endif
						break;
					case FD_ACCEPT:
#ifndef NOSOCKETSTATES
						if ((pSocket->GetState() == listening || pSocket->GetState() == attached)
							&& (pSocket->m_lEvent & FD_ACCEPT))
#endif
						{
							pSocket->OnAccept(nErrorCode);
						}
						break;
					case FD_CLOSE:
#ifndef NOSOCKETSTATES
						if ((pSocket->GetState() == connected || pSocket->GetState() == attached)
							&& (pSocket->m_lEvent & FD_CLOSE))
						{
							pSocket->SetState(nErrorCode ? aborted : closed);
#else
						{
#endif
							pSocket->OnClose(nErrorCode);
						}
						break;
					}
				}
				delete pMsg;
				return 0;
			}

		case WM_TIMER:
			{
				if (wParam != 1)
					return 0;
				ASSERT(hWnd);
				CAsyncSocketExHelperWindow *pWnd =
					reinterpret_cast<CAsyncSocketExHelperWindow*>(::GetWindowLongPtr(hWnd, GWLP_USERDATA));
				if (!pWnd || !pWnd->m_pThreadData) {
					ASSERT(0);
					return 0;
				}
				if (pWnd->m_pThreadData->layerCloseNotify.empty()) {
					::KillTimer(hWnd, 1);
					return 0;
				}
				const CAsyncSocketEx *socket = pWnd->m_pThreadData->layerCloseNotify.front();
				pWnd->m_pThreadData->layerCloseNotify.pop_front();
				if (pWnd->m_pThreadData->layerCloseNotify.empty())
					::KillTimer(hWnd, 1);
				if (socket)
					::PostMessage(hWnd, WM_SOCKETEX_NOTIFY + socket->m_SocketData.nSocketIndex,
						socket->m_SocketData.hSocket, FD_CLOSE);
			}
			return 0;

		// ---------------------------------------------------------------------------
		// WM_SOCKETEX_DNSRESULT — delivered by the detached getaddrinfo thread.
		// lParam is a heap-allocated DnsResultMsg; we own it and must delete it.
		// ---------------------------------------------------------------------------
		case WM_SOCKETEX_DNSRESULT:
			{
				DnsResultMsg *pResult = reinterpret_cast<DnsResultMsg*>(lParam);
				if (!pResult)
					return 0;

				CAsyncSocketExHelperWindow *pWnd =
					reinterpret_cast<CAsyncSocketExHelperWindow*>(::GetWindowLongPtr(hWnd, GWLP_USERDATA));
				if (!pWnd) {
					delete pResult;
					return 0;
				}

				// Find the socket that initiated this DNS request
				CAsyncSocketEx *pSocket = nullptr;
				for (int i = 0; i < pWnd->m_nWindowDataSize; ++i) {
					CAsyncSocketEx *p = pWnd->m_pAsyncSocketExWindowData[i].m_pSocket;
					if (p && p->m_hAsyncGetHostByNameHandle == pResult->hSentinel) {
						pSocket = p;
						break;
					}
				}

				if (pSocket) {
					pSocket->m_hAsyncGetHostByNameHandle = 0;
					if (pResult->nErrorCode) {
						pSocket->OnConnect(pResult->nErrorCode);
					} else {
						SOCKADDR_IN addr = pResult->addr;
						if (pSocket->OnHostNameResolved(&addr)) {
							BOOL res = pSocket->Connect((LPSOCKADDR)&addr, sizeof addr);
							if (!res && WSAGetLastError() != WSAEWOULDBLOCK)
								pSocket->OnConnect(WSAGetLastError());
						}
					}
				}
				delete pResult;
				return 0;
			}

		case WM_SOCKETEX_CALLBACK:
			{
				if (!hWnd)
					return 0;
				CAsyncSocketExHelperWindow *pWnd =
					reinterpret_cast<CAsyncSocketExHelperWindow*>(::GetWindowLongPtr(hWnd, GWLP_USERDATA));
				if (!pWnd || wParam >= static_cast<WPARAM>(pWnd->m_nWindowDataSize))
					return 0;
				CAsyncSocketEx *pSocket = pWnd->m_pAsyncSocketExWindowData[wParam].m_pSocket;
				if (!pSocket)
					return 0;
				std::vector<t_callbackMsg> tmp;
				tmp.swap(pSocket->m_pendingCallbacks);
				pSocket->OnLayerCallback(tmp);
			}
		}
		return DefWindowProc(hWnd, message, wParam, lParam);
	}

	HWND GetHwnd() { return m_hWnd; }

private:
	HWND m_hWnd;
	struct t_AsyncSocketExWindowData
	{
		CAsyncSocketEx *m_pSocket;
	} *m_pAsyncSocketExWindowData;
	int m_nWindowDataSize;
	int m_nWindowDataPos;
	int m_nSocketCount;
	CAsyncSocketEx::t_AsyncSocketExThreadData *m_pThreadData;
	CSocketDispatchThread *m_pDispatcher;
	std::shared_ptr<DnsChannel> m_dnsChannel;
};

// ===========================================================================
// CAsyncSocketEx
// ===========================================================================

IMPLEMENT_DYNAMIC(CAsyncSocketEx, CObject)

CAsyncSocketEx::CAsyncSocketEx()
	: m_pLocalAsyncSocketExThreadData()
	, m_pAsyncGetHostByNameBuffer()
	, m_hAsyncGetHostByNameHandle()
	, m_nAsyncGetHostByNamePort()
#ifndef NOSOCKETSTATES
	, m_nState(notsock)
	, m_nPendingEvents()
#endif
	, m_pFirstLayer()
	, m_pLastLayer()
	, m_nSocketPort()
	, m_lEvent()
{
	m_SocketData.addrInfo   = NULL;
	m_SocketData.nextAddr   = NULL;
	m_SocketData.hSocket    = INVALID_SOCKET;
	m_SocketData.nSocketIndex = -1;
	m_SocketData.nFamily    = AF_UNSPEC;
	m_SocketData.bIsClosing = false;
}

CAsyncSocketEx::~CAsyncSocketEx()
{
	CAsyncSocketEx::Close();
	FreeAsyncSocketExInstance();
}

bool CAsyncSocketEx::Create(UINT nSocketPort /*=0*/, int nSocketType /*=SOCK_STREAM*/,
	long lEvent /*=FD_DEFAULT*/, const CString &sSocketAddress /*=CString()*/,
	ADDRESS_FAMILY nFamily /*=AF_INET*/, bool reusable /*=false*/)
{
	if (GetSocketHandle() != INVALID_SOCKET) {
		ASSERT(0);
		WSASetLastError(WSAEALREADY);
		return false;
	}
	if (!InitAsyncSocketExInstance()) {
		ASSERT(0);
		WSASetLastError(WSANOTINITIALISED);
		return false;
	}
	m_SocketData.nFamily = nFamily;

	if (m_pFirstLayer) {
		bool res = m_pFirstLayer->Create(nSocketPort, nSocketType, lEvent, sSocketAddress, nFamily, reusable);
#ifndef NOSOCKETSTATES
		if (res)
			SetState(unconnected);
#endif
		return res;
	}

	if (m_SocketData.nFamily == AF_UNSPEC) {
#ifndef NOSOCKETSTATES
		SetState(unconnected);
#endif
		m_lEvent      = lEvent;
		m_nSocketPort = nSocketPort;
		m_sSocketAddress = sSocketAddress;
		return true;
	}

	SOCKET hSocket = socket(m_SocketData.nFamily, nSocketType, 0);
	if (hSocket == INVALID_SOCKET)
		return false;
	m_SocketData.hSocket = hSocket;
	AttachHandle();

	if (!AsyncSelect(lEvent)) {
		Close();
		return false;
	}

	if (reusable && nSocketPort != 0) {
		BOOL value = TRUE;
		SetSockOpt(SO_REUSEADDR, reinterpret_cast<const void*>(&value), sizeof value);
	}
	if (!Bind(nSocketPort, sSocketAddress)) {
		Close();
		return false;
	}
#ifndef NOSOCKETSTATES
	SetState(unconnected);
#endif
	return true;
}

bool CAsyncSocketEx::OnHostNameResolved(const SOCKADDR_IN * /*pSockAddr*/)
{
	return true;
}

void CAsyncSocketEx::OnReceive(int /*nErrorCode*/) {}
void CAsyncSocketEx::OnSend(int /*nErrorCode*/)    {}
void CAsyncSocketEx::OnConnect(int /*nErrorCode*/) {}
void CAsyncSocketEx::OnAccept(int /*nErrorCode*/)  {}
void CAsyncSocketEx::OnClose(int /*nErrorCode*/)   {}

bool CAsyncSocketEx::Bind(UINT nSocketPort, const CString &sSocketAddress)
{
	m_sSocketAddress = sSocketAddress;
	m_nSocketPort    = nSocketPort;

	if (m_SocketData.nFamily == AF_UNSPEC)
		return true;

	const CStringA sAscii(sSocketAddress);
	if (sAscii.IsEmpty()) {
		if (m_SocketData.nFamily == AF_INET) {
			SOCKADDR_IN sockAddr = {};
			sockAddr.sin_family      = AF_INET;
			sockAddr.sin_addr.s_addr = INADDR_ANY;
			sockAddr.sin_port        = htons((u_short)nSocketPort);
			return Bind((LPSOCKADDR)&sockAddr, sizeof sockAddr);
		}
		if (m_SocketData.nFamily == AF_INET6) {
			SOCKADDR_IN6 sockAddr6 = {};
			sockAddr6.sin6_family   = AF_INET6;
			sockAddr6.sin6_addr     = in6addr_any;
			sockAddr6.sin6_port     = htons((u_short)nSocketPort);
			return Bind((LPSOCKADDR)&sockAddr6, sizeof sockAddr6);
		}
	} else {
		addrinfo hints = {};
		hints.ai_family   = m_SocketData.nFamily;
		hints.ai_socktype = SOCK_STREAM;
		CStringA port;
		port.Format("%u", nSocketPort);
		addrinfo *res0;
		if (getaddrinfo(sAscii, port, &hints, &res0))
			return false;
		bool ret = false;
		for (addrinfo *res = res0; res; res = res->ai_next)
			if (Bind(res->ai_addr, (int)res->ai_addrlen)) {
				ret = true;
				break;
			}
		freeaddrinfo(res0);
		return ret;
	}
	return false;
}

BOOL CAsyncSocketEx::Bind(const LPSOCKADDR lpSockAddr, int nSockAddrLen)
{
	return !bind(m_SocketData.hSocket, lpSockAddr, nSockAddrLen);
}

void CAsyncSocketEx::AttachHandle()
{
	ASSERT(m_pLocalAsyncSocketExThreadData);
	VERIFY(m_pLocalAsyncSocketExThreadData->m_pHelperWindow->AddSocket(this, m_SocketData.nSocketIndex));
#ifndef NOSOCKETSTATES
	SetState(attached);
#endif
}

void CAsyncSocketEx::DetachHandle()
{
	// Save the handle BEFORE clearing it so RemoveSocket can deregister
	// the correct handle from the dispatch thread.
	const SOCKET hOld = m_SocketData.hSocket;
	m_SocketData.hSocket = INVALID_SOCKET;
	if (!m_pLocalAsyncSocketExThreadData) {
		ASSERT(0);
		return;
	}
	if (!m_pLocalAsyncSocketExThreadData->m_pHelperWindow) {
		ASSERT(0);
		return;
	}
	VERIFY(m_pLocalAsyncSocketExThreadData->m_pHelperWindow->RemoveSocket(this, m_SocketData.nSocketIndex, hOld));
#ifndef NOSOCKETSTATES
	SetState(notsock);
#endif
}

void CAsyncSocketEx::Close()
{
#ifndef NOSOCKETSTATES
	m_nPendingEvents = 0;
#endif
	if (m_pFirstLayer)
		m_pFirstLayer->Close();
	if (m_SocketData.hSocket != INVALID_SOCKET) {
		VERIFY(closesocket(m_SocketData.hSocket) != SOCKET_ERROR);
		DetachHandle();
	}
	if (m_SocketData.addrInfo) {
		freeaddrinfo(m_SocketData.addrInfo);
		m_SocketData.addrInfo = NULL;
		m_SocketData.nextAddr = NULL;
	}
	m_SocketData.nFamily = AF_UNSPEC;
	m_sSocketAddress.Empty();
	m_nSocketPort = 0;
	RemoveAllLayers();

	delete[] m_pAsyncGetHostByNameBuffer;
	m_pAsyncGetHostByNameBuffer = NULL;

	// Cancel any pending DNS thread.  The thread captures the shared_ptr by
	// value; setting the flag ensures it will not post to a dead socket.
	if (m_hAsyncGetHostByNameHandle) {
		if (m_dnsCancelFlag)
			m_dnsCancelFlag->store(true);
		m_hAsyncGetHostByNameHandle = 0;
	}
	m_SocketData.bIsClosing = false;
}

bool CAsyncSocketEx::InitAsyncSocketExInstance()
{
	if (!m_pLocalAsyncSocketExThreadData) {
		if (!thread_local_data) {
			try {
				thread_local_data = new t_AsyncSocketExThreadData{};
				thread_local_data->m_pHelperWindow = new CAsyncSocketExHelperWindow(thread_local_data);
			} catch (...) {
				if (thread_local_data) {
					delete thread_local_data;
					thread_local_data = NULL;
				}
				return false;
			}
		}
		m_pLocalAsyncSocketExThreadData = thread_local_data;
		++m_pLocalAsyncSocketExThreadData->nInstanceCount;
	}
	return true;
}

void CAsyncSocketEx::FreeAsyncSocketExInstance()
{
	if (!m_pLocalAsyncSocketExThreadData)
		return;

	std::list<CAsyncSocketEx*> &socks = m_pLocalAsyncSocketExThreadData->layerCloseNotify;
	auto iter = std::find(socks.begin(), socks.end(), this);
	if (iter != socks.end()) {
		socks.erase(iter);
		if (socks.empty())
			::KillTimer(m_pLocalAsyncSocketExThreadData->m_pHelperWindow->GetHwnd(), 1);
	}

	if (!--m_pLocalAsyncSocketExThreadData->nInstanceCount) {
		m_pLocalAsyncSocketExThreadData = NULL;
		delete thread_local_data->m_pHelperWindow;
		delete thread_local_data;
		thread_local_data = NULL;
	}
}

int CAsyncSocketEx::Receive(void *lpBuf, int nBufLen, int nFlags /*=0*/)
{
	if (m_pFirstLayer)
		return m_pFirstLayer->Receive(lpBuf, nBufLen, nFlags);
	return recv(m_SocketData.hSocket, (LPSTR)lpBuf, nBufLen, nFlags);
}

int CAsyncSocketEx::Send(const void *lpBuf, int nBufLen, int nFlags /*=0*/)
{
	if (m_pFirstLayer)
		return m_pFirstLayer->Send(lpBuf, nBufLen, nFlags);
	return send(m_SocketData.hSocket, (LPSTR)lpBuf, nBufLen, nFlags);
}

bool CAsyncSocketEx::Connect(const CString &sHostAddress, UINT nHostPort)
{
	if (m_pFirstLayer) {
		bool res = m_pFirstLayer->Connect(sHostAddress, nHostPort);
#ifndef NOSOCKETSTATES
		if (res || GetLastError() == WSAEWOULDBLOCK)
			SetState(connecting);
#endif
		return res;
	}

	const CStringA sAscii(sHostAddress);
	ASSERT(!sAscii.IsEmpty());

	if (m_SocketData.nFamily == AF_INET) {
		SOCKADDR_IN sockAddr = {};
		sockAddr.sin_family      = AF_INET;
		sockAddr.sin_addr.s_addr = inet_addr(sAscii);

		if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
			// Non-numeric hostname: resolve asynchronously in a detached thread.
			// Cross-platform note: getaddrinfo is POSIX-standard and works on all
			// platforms.  Replace PostMessage + WM_SOCKETEX_DNSRESULT with an
			// eventfd/queue mechanism for a native Linux port.

			// FIX Bug #2 (revised): the old scheme used m_dnsCancelFlag.get()
			// as the sentinel.  That address *is* unique while the shared_ptr
			// is alive, but once the last reference drops the heap can re-issue
			// the same address to a later allocation — including a re-Connect()
			// on the same socket or a Connect() on a different socket.  A stale
			// DNS result still in the message queue would then match the wrong
			// socket.  Use a monotonic uint64 ID instead: it is never reused,
			// so the lookup at WM_SOCKETEX_DNSRESULT is always unambiguous.
			m_dnsCancelFlag = std::make_shared<std::atomic<bool>>(false);
			HANDLE hSentinel = reinterpret_cast<HANDLE>(
				g_nDnsNextRequestId.fetch_add(1, std::memory_order_relaxed));
			m_hAsyncGetHostByNameHandle = hSentinel;
			m_nAsyncGetHostByNamePort   = (USHORT)nHostPort;

			// FIX Bug #1: capture the DnsChannel (shared_ptr) instead of a raw
			// HWND.  The channel's mutex serialises PostMessage against the helper
			// window destructor, which nullifies hwnd under the same lock before
			// calling DestroyWindow.  This eliminates the TOCTOU race.
			auto cancelFlag = m_dnsCancelFlag;
			auto dnsChannel = m_pLocalAsyncSocketExThreadData->m_pHelperWindow->GetDnsChannel();
			UINT port       = nHostPort;
			std::string hostname(sAscii);

			std::thread([hSentinel, hostname, port, dnsChannel, cancelFlag]() {
				addrinfo hints = {};
				hints.ai_family   = AF_INET;
				hints.ai_socktype = SOCK_STREAM;

				addrinfo *res = nullptr;
				int err = ::getaddrinfo(hostname.c_str(), nullptr, &hints, &res);

				DnsResultMsg *pMsg = new DnsResultMsg{};
				pMsg->hSentinel = hSentinel;

				if (err || !res) {
					pMsg->nErrorCode = WSAHOST_NOT_FOUND;
				} else {
					pMsg->nErrorCode       = 0;
					pMsg->addr.sin_family  = AF_INET;
					pMsg->addr.sin_addr    = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
					pMsg->addr.sin_port    = htons((u_short)port);
					freeaddrinfo(res);
				}

				// Acquire the channel mutex: mutually exclusive with the helper
				// window destructor that nullifies hwnd under the same lock.
				// If hwnd is non-null AND the per-socket cancel flag is clear, the
				// window is still alive and the socket still wants the result.
				{
					std::lock_guard<std::mutex> lk(dnsChannel->mutex);
					if (dnsChannel->hwnd && !cancelFlag->load()) {
						if (!::PostMessage(dnsChannel->hwnd, WM_SOCKETEX_DNSRESULT,
						                   0, reinterpret_cast<LPARAM>(pMsg)))
							delete pMsg;
						pMsg = nullptr; // ownership transferred to the message queue
					}
				}
				delete pMsg; // no-op if pMsg was transferred above
			}).detach();

			WSASetLastError(WSAEWOULDBLOCK);
#ifndef NOSOCKETSTATES
			SetState(connecting);
#endif
			return false;
		}

		sockAddr.sin_port = htons((u_short)nHostPort);
		return CAsyncSocketEx::Connect((LPSOCKADDR)&sockAddr, sizeof sockAddr);
	}

	if (m_SocketData.addrInfo) {
		freeaddrinfo(m_SocketData.addrInfo);
		m_SocketData.addrInfo = NULL;
		m_SocketData.nextAddr = NULL;
	}

	addrinfo hints = {};
	hints.ai_family   = m_SocketData.nFamily;
	hints.ai_socktype = SOCK_STREAM;
	CStringA port;
	port.Format("%u", nHostPort);
	if (getaddrinfo(sAscii, port, &hints, &m_SocketData.addrInfo))
		return false;

	bool ret = false;
	for (m_SocketData.nextAddr = m_SocketData.addrInfo; m_SocketData.nextAddr;
		 m_SocketData.nextAddr = m_SocketData.nextAddr->ai_next)
	{
		bool newSocket = (m_SocketData.nFamily == AF_UNSPEC);
		if (newSocket)
			m_SocketData.hSocket = socket(m_SocketData.nextAddr->ai_family,
				m_SocketData.nextAddr->ai_socktype, m_SocketData.nextAddr->ai_protocol);
		if (m_SocketData.hSocket == INVALID_SOCKET)
			continue;

		if (newSocket) {
			m_SocketData.nFamily = (ADDRESS_FAMILY)m_SocketData.nextAddr->ai_family;
			AttachHandle();
		}

		if (AsyncSelect(m_lEvent) && (!newSocket || Bind(m_nSocketPort, m_sSocketAddress))) {
			ret = Connect(m_SocketData.nextAddr->ai_addr, (int)m_SocketData.nextAddr->ai_addrlen);
			if (ret || GetLastError() == WSAEWOULDBLOCK)
				break;
		}

		if (newSocket) {
			m_SocketData.nFamily = AF_UNSPEC;
			closesocket(m_SocketData.hSocket);
			DetachHandle();
		}
	}

	if (m_SocketData.nextAddr)
		m_SocketData.nextAddr = m_SocketData.nextAddr->ai_next;
	if (!m_SocketData.nextAddr) {
		freeaddrinfo(m_SocketData.addrInfo);
		m_SocketData.addrInfo = NULL;
	}
	return ret && m_SocketData.hSocket != INVALID_SOCKET;
}

BOOL CAsyncSocketEx::Connect(const LPSOCKADDR lpSockAddr, int nSockAddrLen)
{
	BOOL res;
	if (m_pFirstLayer)
		res = m_pFirstLayer->Connect(lpSockAddr, nSockAddrLen);
	else
		res = !connect(m_SocketData.hSocket, lpSockAddr, nSockAddrLen);
#ifndef NOSOCKETSTATES
	if (res || GetLastError() == WSAEWOULDBLOCK)
		SetState(connecting);
#endif
	return res;
}

bool CAsyncSocketEx::GetPeerName(CString &rPeerAddress, UINT &rPeerPort)
{
	if (m_pFirstLayer)
		return m_pFirstLayer->GetPeerName(rPeerAddress, rPeerPort);
	if (m_SocketData.nFamily != AF_INET6 && m_SocketData.nFamily != AF_INET)
		return false;

	int nSockAddrLen = (int)((m_SocketData.nFamily == AF_INET6)
		? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN));
	LPSOCKADDR sockAddr = (LPSOCKADDR)new char[nSockAddrLen]();

	bool bResult = GetPeerName(sockAddr, &nSockAddrLen);
	if (bResult) {
		if (m_SocketData.nFamily == AF_INET6) {
			rPeerPort    = ntohs(((LPSOCKADDR_IN6)sockAddr)->sin6_port);
			rPeerAddress = Inet6AddrToString(((LPSOCKADDR_IN6)sockAddr)->sin6_addr);
		} else {
			rPeerPort    = ntohs(((LPSOCKADDR_IN)sockAddr)->sin_port);
			rPeerAddress = inet_ntoa(((LPSOCKADDR_IN)sockAddr)->sin_addr);
		}
	}
	delete[] sockAddr;
	return bResult;
}

BOOL CAsyncSocketEx::GetPeerName(LPSOCKADDR lpSockAddr, int *lpSockAddrLen)
{
	if (m_pFirstLayer)
		return m_pFirstLayer->GetPeerName(lpSockAddr, lpSockAddrLen);
	return !getpeername(m_SocketData.hSocket, lpSockAddr, lpSockAddrLen);
}

bool CAsyncSocketEx::GetSockName(CString &rSocketAddress, UINT &rSocketPort)
{
	if (m_SocketData.nFamily != AF_INET6 && m_SocketData.nFamily != AF_INET)
		return false;
	int nSockAddrLen = (int)((m_SocketData.nFamily == AF_INET6)
		? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN));
	LPSOCKADDR sockAddr = (LPSOCKADDR)new char[nSockAddrLen]();

	bool bResult = GetSockName(sockAddr, &nSockAddrLen);
	if (bResult) {
		if (m_SocketData.nFamily == AF_INET6) {
			rSocketPort    = ntohs(((LPSOCKADDR_IN6)sockAddr)->sin6_port);
			rSocketAddress = Inet6AddrToString(((LPSOCKADDR_IN6)sockAddr)->sin6_addr);
		} else {
			rSocketPort    = ntohs(((LPSOCKADDR_IN)sockAddr)->sin_port);
			rSocketAddress = inet_ntoa(((LPSOCKADDR_IN)sockAddr)->sin_addr);
		}
	}
	delete[] sockAddr;
	return bResult;
}

BOOL CAsyncSocketEx::GetSockName(LPSOCKADDR lpSockAddr, int *lpSockAddrLen)
{
	return !getsockname(m_SocketData.hSocket, lpSockAddr, lpSockAddrLen);
}

BOOL CAsyncSocketEx::ShutDown(int nHow /*=CAsyncSocket::sends*/)
{
	if (m_pFirstLayer)
		return m_pFirstLayer->ShutDown(nHow);
	return !shutdown(m_SocketData.hSocket, nHow);
}

SOCKET CAsyncSocketEx::Detach()
{
	SOCKET socket = m_SocketData.hSocket;
	DetachHandle();
	m_SocketData.nFamily = AF_UNSPEC;
	return socket;
}

BOOL CAsyncSocketEx::Attach(SOCKET hSocket, long lEvent /*=FD_DEFAULT*/)
{
	if (hSocket == INVALID_SOCKET)
		return FALSE;
	VERIFY(InitAsyncSocketExInstance());
	m_SocketData.hSocket = hSocket;
	AttachHandle();
	return AsyncSelect(lEvent);
}

// ---------------------------------------------------------------------------
// AsyncSelect — register the socket with the dispatch thread.
//
// When layers are in use: always register for FD_DEFAULT so the layer chain
// receives every low-level event; m_lEvent still filters which high-level
// callbacks reach the application.
// When no layers: register for exactly lEvent.
//
// Cross-platform note: on Linux replace RegisterSocket (which calls
// WSAEventSelect) with the platform-equivalent (e.g. epoll_ctl ADD/MOD).
// ---------------------------------------------------------------------------
BOOL CAsyncSocketEx::AsyncSelect(long lEvent /*=FD_DEFAULT*/)
{
	ASSERT(m_pLocalAsyncSocketExThreadData);
	m_lEvent = lEvent;

	if (m_SocketData.hSocket == INVALID_SOCKET && m_SocketData.nFamily == AF_UNSPEC)
		return TRUE;

	if (!m_pLocalAsyncSocketExThreadData->m_pHelperWindow)
		return FALSE;

	long registerEvents = m_pFirstLayer ? FD_DEFAULT : lEvent;
	m_pLocalAsyncSocketExThreadData->m_pHelperWindow->RegisterSocket(
		m_SocketData.hSocket, m_SocketData.nSocketIndex, registerEvents);
	return TRUE;
}

BOOL CAsyncSocketEx::Listen(int nConnectionBacklog /*=5*/)
{
	if (m_pFirstLayer)
		return m_pFirstLayer->Listen(nConnectionBacklog);
	if (!listen(m_SocketData.hSocket, nConnectionBacklog)) {
#ifndef NOSOCKETSTATES
		SetState(listening);
#endif
		return TRUE;
	}
	return FALSE;
}

BOOL CAsyncSocketEx::Accept(CAsyncSocketEx &rConnectedSocket,
	LPSOCKADDR lpSockAddr /*=NULL*/, int *lpSockAddrLen /*=NULL*/)
{
	ASSERT(rConnectedSocket.m_SocketData.hSocket == INVALID_SOCKET);
	if (m_pFirstLayer)
		return m_pFirstLayer->Accept(rConnectedSocket, lpSockAddr, lpSockAddrLen);

	SOCKET hTemp = accept(m_SocketData.hSocket, lpSockAddr, lpSockAddrLen);
	if (hTemp == INVALID_SOCKET)
		return FALSE;
	VERIFY(rConnectedSocket.InitAsyncSocketExInstance());
	rConnectedSocket.m_SocketData.hSocket = hTemp;
	rConnectedSocket.AttachHandle();
	rConnectedSocket.SetFamily(GetFamily());
#ifndef NOSOCKETSTATES
	rConnectedSocket.SetState(connected);
#endif
	return TRUE;
}

BOOL CAsyncSocketEx::IOCtl(long lCommand, DWORD *lpArgument)
{
	return !ioctlsocket(m_SocketData.hSocket, lCommand, lpArgument);
}

BOOL CAsyncSocketEx::TriggerEvent(long lEvent)
{
	if (m_SocketData.hSocket == INVALID_SOCKET)
		return FALSE;
	ASSERT(m_pLocalAsyncSocketExThreadData);
	ASSERT(m_pLocalAsyncSocketExThreadData->m_pHelperWindow);
	ASSERT(m_SocketData.nSocketIndex >= 0);

	if (m_pFirstLayer) {
		CAsyncSocketExLayer::t_LayerNotifyMsg *pMsg = new CAsyncSocketExLayer::t_LayerNotifyMsg;
		pMsg->hSocket = m_SocketData.hSocket;
		pMsg->lEvent  = WSAGETSELECTEVENT(lEvent);
		pMsg->pLayer  = NULL;
		BOOL res = ::PostMessage(GetHelperWindowHandle(), WM_SOCKETEX_TRIGGER,
			(WPARAM)m_SocketData.nSocketIndex, (LPARAM)pMsg);
		if (!res)
			delete pMsg;
		return res;
	}
	return ::PostMessage(GetHelperWindowHandle(),
		WM_SOCKETEX_NOTIFY + m_SocketData.nSocketIndex,
		m_SocketData.hSocket, WSAGETSELECTEVENT(lEvent));
}

HWND CAsyncSocketEx::GetHelperWindowHandle()
{
	if (!m_pLocalAsyncSocketExThreadData || !m_pLocalAsyncSocketExThreadData->m_pHelperWindow)
		return 0;
	return m_pLocalAsyncSocketExThreadData->m_pHelperWindow->GetHwnd();
}

BOOL CAsyncSocketEx::AddLayer(CAsyncSocketExLayer *pLayer)
{
	ASSERT(pLayer);
	if (m_pFirstLayer) {
		ASSERT(m_pLastLayer);
		m_pLastLayer = m_pLastLayer->AddLayer(pLayer, this);
		return m_pLastLayer != NULL;
	}
	ASSERT(!m_pLastLayer);
	pLayer->Init(NULL, this);
	m_pFirstLayer = pLayer;
	m_pLastLayer  = m_pFirstLayer;

	// Re-register for FD_DEFAULT now that a layer is attached.
	// No separate WSAAsyncSelect needed — AsyncSelect handles this.
	if (m_SocketData.hSocket != INVALID_SOCKET)
		AsyncSelect(m_lEvent);

	return TRUE;
}

void CAsyncSocketEx::RemoveAllLayers()
{
	CAsyncSocketEx::OnLayerCallback(m_pendingCallbacks);
	m_pFirstLayer = NULL;
	m_pLastLayer  = NULL;
	if (m_pLocalAsyncSocketExThreadData && m_pLocalAsyncSocketExThreadData->m_pHelperWindow)
		m_pLocalAsyncSocketExThreadData->m_pHelperWindow->RemoveLayers(this);
}

int CAsyncSocketEx::OnLayerCallback(std::vector<t_callbackMsg> &callbacks)
{
	while (!callbacks.empty()) {
		delete[] callbacks.back().str;
		callbacks.pop_back();
	}
	return 0;
}

bool CAsyncSocketEx::IsLayerAttached() const
{
	return m_pFirstLayer != NULL;
}

BOOL CAsyncSocketEx::GetSockOpt(int nOptionName, void *lpOptionValue, int *lpOptionLen, int nLevel /*=SOL_SOCKET*/)
{
	return !getsockopt(m_SocketData.hSocket, nLevel, nOptionName, (LPSTR)lpOptionValue, lpOptionLen);
}

BOOL CAsyncSocketEx::SetSockOpt(int nOptionName, const void *lpOptionValue, int nOptionLen, int nLevel /*=SOL_SOCKET*/)
{
	return !setsockopt(m_SocketData.hSocket, nLevel, nOptionName, (LPSTR)lpOptionValue, nOptionLen);
}

bool CAsyncSocketEx::SetFamily(ADDRESS_FAMILY nFamily)
{
	if (m_SocketData.nFamily != AF_UNSPEC)
		return false;
	m_SocketData.nFamily = nFamily;
	return true;
}

bool CAsyncSocketEx::TryNextProtocol()
{
	closesocket(m_SocketData.hSocket);
	DetachHandle();

	bool ret = false;
	for (; m_SocketData.nextAddr; m_SocketData.nextAddr = m_SocketData.nextAddr->ai_next) {
		m_SocketData.hSocket = socket(m_SocketData.nextAddr->ai_family,
			m_SocketData.nextAddr->ai_socktype, m_SocketData.nextAddr->ai_protocol);
		if (m_SocketData.hSocket == INVALID_SOCKET)
			continue;

		m_SocketData.nFamily = (ADDRESS_FAMILY)m_SocketData.nextAddr->ai_family;
		AttachHandle();

		// AsyncSelect now handles both layered and non-layered paths.
		if (AsyncSelect(m_lEvent) && Bind(m_nSocketPort, m_sSocketAddress)) {
			ret = Connect(m_SocketData.nextAddr->ai_addr, (int)m_SocketData.nextAddr->ai_addrlen);
			if (ret || GetLastError() == WSAEWOULDBLOCK)
				break;
		}

		closesocket(m_SocketData.hSocket);
		DetachHandle();
	}

	if (m_SocketData.nextAddr)
		m_SocketData.nextAddr = m_SocketData.nextAddr->ai_next;
	if (!m_SocketData.nextAddr) {
		freeaddrinfo(m_SocketData.addrInfo);
		m_SocketData.addrInfo = NULL;
	}
	return ret && m_SocketData.hSocket != INVALID_SOCKET;
}

void CAsyncSocketEx::AddCallbackNotification(const t_callbackMsg &msg)
{
	m_pendingCallbacks.push_back(msg);
	if (m_pendingCallbacks.size() == 1 && m_SocketData.nSocketIndex >= 0)
		::PostMessage(GetHelperWindowHandle(), WM_SOCKETEX_CALLBACK,
			(WPARAM)m_SocketData.nSocketIndex, 0);
}

void CAsyncSocketEx::ResendCloseNotify()
{
	std::list<CAsyncSocketEx*> &socks = m_pLocalAsyncSocketExThreadData->layerCloseNotify;
	auto iter = std::find(socks.begin(), socks.end(), this);
	if (iter == socks.end()) {
		socks.push_back(this);
		if (socks.size() == 1)
			::SetTimer(m_pLocalAsyncSocketExThreadData->m_pHelperWindow->GetHwnd(), 1, 10, NULL);
	}
}

#ifdef _DEBUG
void CAsyncSocketEx::AssertValid() const
{
	CObject::AssertValid();
	(void)m_SocketData;
	(void)m_lEvent;
	(void)m_pAsyncGetHostByNameBuffer;
	(void)m_hAsyncGetHostByNameHandle;
	(void)m_nAsyncGetHostByNamePort;
	(void)m_nSocketPort;
	(void)m_pendingCallbacks;
	(void)m_pFirstLayer;
	(void)m_pLastLayer;
}

void CAsyncSocketEx::Dump(CDumpContext &dc) const
{
	CObject::Dump(dc);
}
#endif
