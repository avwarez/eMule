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
#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <functional>
#include <iterator>
#include <map>
#include <vector>
#include "emule.h"
#include "emuleDlg.h"
#include "NatTraversal.h"
#include "ClientList.h"
#include "ClientUDPSocket.h"
#include "IPFilter.h"
#include "ListenSocket.h"
#include "Opcodes.h"
#include "OtherFunctions.h"
#include "Packets.h"
#include "PartFile.h"
#include "Server.h"
#include "ServerConnect.h"
#include "SharedFileList.h"
#include "Preferences.h"
#include "SafeFile.h"
#include "Statistics.h"
#include "UpDownClient.h"
#include "Log.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/Prefs.h"
#include "kademlia/utils/UInt128.h"
#include "natd/natd.hpp"
#include "natd/resolve.hpp"
#include "natd/winsock_io.hpp"
#include "kcp/ikcp.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// eMule's datagrams on a punched path: <OP_UDPRESERVEDPROT1><transport><flags><token 12> and a
// KCP segment. EncryptedDatagramSocket keeps that first byte for later UDP headers: no plain
// eMule protocol and no obfuscated datagram starts with it.
#define NATD_PATH_HEADER		15
#define NATD_PATH_SEGMENT		1200	// KCP's MTU: with the header, IP and UDP, below 1280 bytes
#define NATD_PATH_KEEPALIVE		0x01	// flags: no segment, for the NATs' mappings
#define NATD_PATH_FIN			0x02	// flags: no segment, the sender's stream is over and acknowledged
#define NATD_PATH_DEAD_AFTER	3		// natd's keepalive intervals with nothing from the peer
#define NATD_PATH_FINS			3		// a FIN goes this many times, NATD_PATH_FIN_GAP apart: a lost one
#define NATD_PATH_FIN_GAP		((DWORD)300)	// would leave the peer waiting for the path to go silent
#define NATD_PATH_LINGER		((DWORD)SEC2MS(10))	// a stream eMule closed, until its FIN is through
// Through a relay (the server, the source's buddy): a request goes once more after
// NATD_RELAY_RESEND; through the server it waits for the peer's request back at most
// NATD_RELAY_WAIT. A punch that timed out is asked for once more, with a new request, while the
// socket has been connecting for less than eMule's connection timeout (as TCP sends its SYN again
// within it), NATD_RELAY_TRIES punches at most.
#define NATD_RELAY_RESEND		((DWORD)SEC2MS(3))
#define NATD_RELAY_WAIT			((DWORD)SEC2MS(20))
#define NATD_RELAY_RETRY_WITHIN	((DWORD)CONNECTION_TIMEOUT)
#define NATD_RELAY_TRIES		3
#define NATD_SERVER_PINGS		5		// status requests for the server's UDP key, 20 s apart
#define NATD_SERVER_PING_RETRY	((DWORD)SEC2MS(20))
// The connection waits for the discovery at most this long. natd's discovery ends within
// about 40 s even when no STUN server answers: the rest is for resolving their names.
#define NATD_CONNECT_WAIT		((DWORD)SEC2MS(60))

namespace
{
	// natd's id of the client UDP socket; the sockets natd opens itself (discovery samples) get
	// ids from 1 up from natd::WinsockDatagramIo
	const natd::SocketId kPrimarySocket = 0;

	CString EndpointStr(const natd::Endpoint &ep)
	{
		CString str;
		str.Format(_T("%s:%u"), (LPCTSTR)ipstr(htonl(ep.ip)), ep.port);
		return str;
	}

	sockaddr_in SockAddr(uint32 dwIP, uint16 nPort)
	{
		sockaddr_in sa = {};
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = dwIP;
		sa.sin_port = htons(nPort);
		return sa;
	}

	// The punch nonce, from the system's CSPRNG: the session token is derived from it, and
	// GetRandomUInt32() (rand() seeded from the tick count) can be guessed
	uint64 RandomUInt64()
	{
		uint64 n = 0;
		natd::defaultRandomBytes()(reinterpret_cast<uint8_t*>(&n), sizeof n);
		return n;
	}

	// The marker is natd's offer
	void WriteMarker(CSafeMemFile &data, uint64 nNonce)
	{
		const std::array<uint8_t, natd::kOfferSize> abyOffer(natd::encodeOffer(natd::Offer{NATD_MARKER_PUNCH, nNonce}));
		data.Write(abyOffer.data(), (UINT)abyOffer.size());
	}

	// The punch request after the endpoint (SNatCallback), as we send it: our ID, our crypt
	// settings and our user hash
	void WriteCallback(CSafeMemFile &data, uint32 nID)
	{
		data.WriteUInt32(nID);
		data.WriteUInt8((uint8)((GetMyConnectOptions(true, false) & 0x07) | NATD_CALLBACK_HASH));
		data.WriteHash16(thePrefs.GetUserHash());
	}

	LPCTSTR ViaStr(uint8 byVia)
	{
		switch (byVia) {
		case NATD_VIA_BUDDY:
			return _T("through the buddy");
		case NATD_VIA_DIRECT:
			return _T("directly");
		case NATD_VIA_SERVER:
			return _T("through the server");
		default:
			return _T("");
		}
	}

	// The nonce of a punch through the server, where no marker fits: both peers know the
	// two IDs, the one of the side that starts the punch first
	uint64 ServerNonce(uint32 nStarterID, uint32 nOtherID)
	{
		return ((uint64)nStarterID << 32) | nOtherID;
	}

	// natd's socket interface: the client UDP socket, plus the plain sockets natd opens for its
	// samples. Datagrams go out at once, past the UDP send queue: natd and KCP pace their own,
	// and the stream above them was paced by the upload throttler already.
	class CNatdIo final : public natd::IDatagramIo
	{
	public:
		natd::WinsockDatagramIo m_extra;

		std::optional<natd::SocketId> openSocket(uint16_t nPreferredLocalPort) override
		{
			return m_extra.openSocket(nPreferredLocalPort);
		}

		void closeSocket(natd::SocketId id) override
		{
			if (id != kPrimarySocket)
				m_extra.closeSocket(id);
		}

		natd::Endpoint localEndpoint(natd::SocketId id) const override
		{
			if (id != kPrimarySocket)
				return m_extra.localEndpoint(id);
			natd::Endpoint ep;
			sockaddr_in sa = {};
			int iLen = (int)sizeof sa;
			if (theApp.clientudp != NULL && ::getsockname(theApp.clientudp->m_hSocket, reinterpret_cast<sockaddr*>(&sa), &iLen) == 0) {
				ep.ip = ntohl(sa.sin_addr.s_addr);
				ep.port = ntohs(sa.sin_port);
			}
			return ep;
		}

		bool send(natd::SocketId id, const natd::Endpoint &to, const uint8_t *pData, size_t nLen) override
		{
			if (id != kPrimarySocket)
				return m_extra.send(id, to, pData, nLen);
			if (theApp.clientudp == NULL || theApp.clientudp->m_hSocket == INVALID_SOCKET || nLen > 8192)
				return false;
			const sockaddr_in sa(SockAddr(htonl(to.ip), to.port));
			return ::sendto(theApp.clientudp->m_hSocket, reinterpret_cast<const char*>(pData), (int)nLen, 0
				, reinterpret_cast<const sockaddr*>(&sa), (int)sizeof sa) == (int)nLen;
		}
	};
}

// natd::Agent does the NAT's part: discovery, endpoint checks and the punch, which hands the path
// over (natd::PunchResult). What goes over the path is eMule's: the sessions below, an eD2K
// stream each, under the sockets of the punched connections.
namespace
{
	// The transport of an eD2K stream over a punched path: KCP (kcp/, MIT) in stream mode,
	// normal mode (congestion control on) with fast retransmission (a segment skipped by two
	// ACKs goes again, without waiting for its RTO), segments of at most NATD_PATH_SEGMENT bytes
	// sent through output. Both peers run it (NATD_TRANSPORT_KCP, in every datagram of the path).
	class CNatdKcpTransport
	{
	public:
		CNatdKcpTransport(const natd::TxId &token, std::function<void(const uint8_t*, size_t)> output, natd::TimePoint now)
			: m_output(std::move(output))
			, m_epoch(now)
		{
			const IUINT32 conv = (IUINT32)token[0] | (IUINT32)token[1] << 8 | (IUINT32)token[2] << 16 | (IUINT32)token[3] << 24;
			m_pKcp = ikcp_create(conv, this);
			ikcp_setoutput(m_pKcp, &CNatdKcpTransport::Output);
			m_pKcp->stream = 1;
			ikcp_setmtu(m_pKcp, NATD_PATH_SEGMENT);
			ikcp_wndsize(m_pKcp, kWindow, kWindow);
			ikcp_nodelay(m_pKcp, 0, 20, 2, 0);
		}
		~CNatdKcpTransport()
		{
			ikcp_release(m_pKcp);
		}
		CNatdKcpTransport(const CNatdKcpTransport&) = delete;
		CNatdKcpTransport& operator=(const CNatdKcpTransport&) = delete;

		void input(const uint8_t *pData, size_t nLen)
		{
			ikcp_input(m_pKcp, reinterpret_cast<const char*>(pData), (long)nLen);
			Drain();
			// the ACKs of what came, at once: KCP sends them only when it flushes, and poll() comes
			// at eMule's timer, up to 100 ms later, which the peer would count in its RTT. The flush
			// also sends what the ACKs let into the window, and a window opened by Drain().
			ikcp_flush(m_pKcp);
		}

		size_t write(const uint8_t *pData, size_t nLen)
		{
			const int nRoom = 2 * kWindow - ikcp_waitsnd(m_pKcp);
			if (nRoom <= 0 || nLen == 0)
				return 0;
			// ikcp_send refuses a call of IKCP_WND_RCV (128) segments or more: feed it in slices
			size_t nLeft = (std::min)(nLen, (size_t)nRoom * (size_t)m_pKcp->mss);
			size_t nDone = 0;
			const size_t nSlice = (size_t)kMaxSegmentsPerSend * (size_t)m_pKcp->mss;
			while (nLeft > 0) {
				const size_t n = (std::min)(nLeft, nSlice);
				if (ikcp_send(m_pKcp, reinterpret_cast<const char*>(pData + nDone), (int)n) < 0)
					break;
				nDone += n;
				nLeft -= n;
			}
			if (nDone > 0)
				ikcp_flush(m_pKcp);
			return nDone;
		}

		bool writable() const
		{
			return ikcp_waitsnd(m_pKcp) < 2 * kWindow;
		}

		size_t readable() const
		{
			return m_rx.size() - m_nRxHead;
		}

		size_t read(uint8_t *pOut, size_t nMax)
		{
			const size_t n = (std::min)(nMax, m_rx.size() - m_nRxHead);
			memcpy(pOut, m_rx.data() + m_nRxHead, n);
			m_nRxHead += n;
			if (m_nRxHead == m_rx.size()) {
				m_rx.clear();
				m_nRxHead = 0;
			}
			Drain();
			return n;
		}

		void poll(natd::TimePoint now)
		{
			const IUINT32 cur = Ms(now);
			ikcp_update(m_pKcp, cur);
			Drain();
			// write() flushes off KCP's interval grid, so a segment can be due for retransmission
			// before the next scheduled flush: ikcp_check() then says "now" while ikcp_update() does
			// nothing until the grid point. Retransmit what is due at once.
			if (ikcp_check(m_pKcp, cur) == cur)
				ikcp_flush(m_pKcp);
		}

		bool flushed() const
		{
			return ikcp_waitsnd(m_pKcp) == 0;
		}

		bool failed() const
		{
			return m_pKcp->state == (IUINT32)-1;
		}

		// the sn of the next segment the stream is waiting for: one below it is a copy
		IUINT32 nextExpected() const
		{
			return m_pKcp->rcv_nxt;
		}

	private:
		static const int kWindow = 256;				// send and receive windows, in segments
		static const int kMaxSegmentsPerSend = 64;	// < IKCP_WND_RCV (128), see ikcp_send

		static int Output(const char *pBuf, int nLen, ikcpcb*, void *pUser) noexcept	// called from C (KCP)
		{
			static_cast<CNatdKcpTransport*>(pUser)->m_output(reinterpret_cast<const uint8_t*>(pBuf), (size_t)nLen);
			return 0;
		}

		IUINT32 Ms(natd::TimePoint t) const
		{
			return (IUINT32)std::chrono::duration_cast<natd::Duration>(t - m_epoch).count();
		}

		// what KCP has in order, straight into the buffer the stream reads from, up to a window not
		// read yet: the rest stays in KCP, whose receive window then closes and stops the sender, as
		// a full TCP buffer does when eMule reads slower (download limit)
		void Drain()
		{
			while (m_rx.size() - m_nRxHead < (size_t)kWindow * m_pKcp->mss) {
				const int nSize = ikcp_peeksize(m_pKcp);
				if (nSize <= 0)
					break;
				if (m_nRxHead > 0 && m_nRxHead >= m_rx.size() / 2) {	// what was read goes, once it is half: each byte moves about once
					m_rx.erase(m_rx.begin(), m_rx.begin() + (ptrdiff_t)m_nRxHead);
					m_nRxHead = 0;
				}
				const size_t nOld = m_rx.size();
				m_rx.resize(nOld + (size_t)nSize);
				const int nGot = ikcp_recv(m_pKcp, reinterpret_cast<char*>(m_rx.data() + nOld), nSize);
				m_rx.resize(nOld + (size_t)(std::max)(nGot, 0));
				if (nGot <= 0)
					break;
			}
		}

		std::function<void(const uint8_t*, size_t)> m_output;
		natd::TimePoint m_epoch;
		ikcpcb *m_pKcp = NULL;
		std::vector<uint8_t> m_rx;	// received, not read yet from m_nRxHead on
		size_t m_nRxHead = 0;
	};

	// A punch session of natd::Agent, then the path it handed over: the socket over it, the
	// events it is due, and the eD2K stream on the path
	struct SSession
	{
		CNatdSocketLayer	*pLayer = NULL;		// NULL once the socket is gone (or before, incoming)
		natd::Endpoint		remote;				// the peer's: as asked, the punched one once punched
		long				lPendingEvents = 0;	// FD_*, raised to the socket by the main thread
		int					nPendingError = 0;
		bool				bReadPosted = false;	// an FD_READ is on its way to the socket
		bool				bClosePosted = false;
		bool				bOver = false;		// the punch failed, or the path ended
		uint32				nServerPeer = 0;	// through the server, the peer's ID there
		// once punched: the path and the stream on it
		natd::PunchResult	path;
		std::unique_ptr<CNatdKcpTransport> pKcp;
		natd::TimePoint		tHeard{};			// the last datagram from the peer
		natd::TimePoint		tKeepalive{};		// a keepalive goes then, if nothing went before
		DWORD				dwDetached = 0;		// the socket is gone: a FIN once what was written is through
		bool				bWantWrite = false;	// a Write() found the window full
		bool				bPeerFin = false;
		IUINT32				snSentNext = 0;		// the first KCP sn not sent yet: one below it goes again
	};
}

struct CNatTraversal::Impl
{
	CNatdIo io;
	std::unique_ptr<natd::StunResolver> pStun;	// the STUN servers, their names resolved off the main thread; made when first needed
	std::unique_ptr<natd::Agent> pAgent;
	int nLoggedVerdict = -1;	// the verdict the user's log gave last (Verdict)
	// 2: punchable through every channel (endpoint-independent mapping); 1: through a relay
	// only, the server or a Kad buddy, whose punch also reaches a NAT with port blocks or
	// sequential ports (Bounded, Predictable); 0: not at all
	int Verdict() const
	{
		return pAgent->directPunchable() ? 2 : pAgent->punchable() ? 1 : 0;
	}
	static LPCTSTR VerdictStr(int nVerdict)
	{
		return nVerdict == 2 ? _T("possible") : nVerdict == 1 ? _T("possible through the server and the Kad buddies only") : _T("not possible");
	}

	CCriticalSection cs;	// pAgent and the sessions
	std::map<natd::SessionId, SSession> sessions;
	uint64 nPathsDead = 0;
	uint64 nPathsAddressChanged = 0;

	Impl()
	{
		natd::AgentConfig cfg;
		cfg.discovery.primarySocket = kPrimarySocket;	// the caps and waits of the punches: natd's
		pAgent = std::make_unique<natd::Agent>(cfg, io);
	}
	void StartDiscovery(natd::TimePoint now);
	void Poll(natd::TimePoint now);
	void HandleEvents(natd::TimePoint now);
	// the user's log: whether downloads between LowIDs can go through UDP hole punching here
	void LogVerdict(LPCTSTR pszWhat)
	{
		nLoggedVerdict = Verdict();
		AddLogLine(false, _T("NAT traversal: public endpoint %s%s - downloads between LowIDs through UDP hole punching %s")
			, pszWhat, (LPCTSTR)EndpointStr(pAgent->publicEndpoint()), VerdictStr(nLoggedVerdict));
	}
	void Punched(natd::SessionId id, SSession &s, const natd::PunchResult &r, natd::TimePoint now, uint32 nPackets, uint16 nRounds);
	void Accept(natd::SessionId id, SSession &s);
	bool OnPath(const natd::Endpoint &from, const BYTE *pData, size_t nLen, natd::TimePoint now);
	void PollPaths(natd::TimePoint now);
	void SendPath(SSession &s, uint8 byFlags, const uint8_t *pSegment, size_t nLen);
	void SendDatagram(natd::SocketId socket, const natd::Endpoint &remote, const natd::TxId &token, uint8 byFlags, const uint8_t *pSegment, size_t nLen);
	void Fin(const SSession &s);
	// the FINs still to go of the streams already over
	struct SFin
	{
		natd::SocketId socket;
		natd::Endpoint remote;
		natd::TxId token;
		DWORD dwNext;
		int nLeft;
	};
	std::vector<SFin> fins;
	void EndPath(SSession &s, int nError);
	void Signal(SSession &s);
	void Erase(natd::SessionId id);
	void RaiseEvents();
	DWORD dwLastStats = 0;
	void LogStats(LPCTSTR pszWhen) const;
	// the connection to the server and to Kad waits for the discovery, as for UPnP. When
	// the wait began (0: not asked), and whether the dialog still waits to be told it is over
	DWORD dwConnectWait = 0;
	bool bConnectWaiting = false;

	// the server we are logged in to as a LowID, when it coordinates punches; main thread
	struct SServer
	{
		uint32	dwIP = 0;				// network order; 0: none
		uint16	nPort = 0;				// its TCP port
		uint32	nID = 0;				// our LowID there
		uint32	dwKey = 0;				// its UDP key for our IP, from the obfuscated status request
		uint16	nObfuscationPort = 0;	// its UDP port for obfuscated packets
		uint32	dwChallenge = 0;		// of the last status request
		DWORD	dwPinged = 0;
		uint32	nPings = 0;
		bool	bGaveUp = false;		// the last status request went unanswered: logged
		bool	Ready() const		{ return dwKey != 0; }
	} server;
	void ServerPing(DWORD dwNow);
	bool ServerRequest(uint32 nTargetID, LPCTSTR pszWhy);


	// Through the server: our requests until the peer's request back brings its endpoint, by
	// channel and key (the target's ID on the server). The requests that wait for nothing (our
	// requests through the source's buddy, the requests back) go once more after
	// NATD_RELAY_RESEND
	struct SWait
	{
		CNatdSocketLayer *pLayer;
		DWORD	dwSent;
		bool	bResent;
	};
	typedef std::pair<uint8, uint64> WaitKey;
	std::map<WaitKey, SWait> waits;
	struct SAgain
	{
		DWORD	dwSent;
		uint8	byVia;
		std::function<void()> send;
	};
	std::deque<SAgain> again;
	bool Ask(const CNatdSocketLayer &layer, uint64 nKey, LPCTSTR pszWhy);
	// our request through the source's buddy, once more after NATD_RELAY_RESEND: nothing
	// answers it but the source's punch
	void AskAgain(const CNatdSocketLayer &layer, uint64 nNonce);
	// OP_REASKCALLBACKUDP to the source's buddy, from the client UDP port, at once (the punch
	// packets that follow go at once too): <buddy ID 16><file 16>, the marker with nNonce, and
	// our request. pszWhy: for the log
	bool BuddyRequest(const uchar *pBuddyID, uint32 dwIP, uint16 nPort, const uchar *pFile, uint64 nNonce, LPCTSTR pszWhy);
};

#define NATD_STUN_FILE			_T("stun.dat")
#define NATD_STUN_FILE_MAX		0x10000	// bytes read of it
#define NATD_STUN_FILE_MIN		3		// servers it must have, or natd's list is used

// The STUN servers: stun.dat in the config directory when it is there, in place of natd's list.
// Text, a server a line as natd reads it (natd::stun::parseServerList): "host[:port] [alt=port]",
// '#' for a comment. The user's choice of who sees the client's address; natd_stunlist checks a
// list and writes one. Nothing makes the file or fetches it.
static std::vector<natd::stun::ServerEntry> StunServers()
{
	const CString strPath(thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + NATD_STUN_FILE);
	CFile file;
	if (!file.Open(strPath, CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary))
		return natd::stun::builtinServers();
	std::string strText;
	try {
		strText.resize((size_t)(std::min)(file.GetLength(), (ULONGLONG)NATD_STUN_FILE_MAX));
		strText.resize(strText.empty() ? 0 : file.Read(&strText[0], (UINT)strText.size()));
	} catch (CFileException *ex) {
		ex->Delete();
		strText.clear();
	}
	const std::vector<natd::stun::ServerEntry> list(natd::stun::parseServerList(strText));
	if (list.size() < NATD_STUN_FILE_MIN) {
		AddLogLine(false, _T("NAT traversal: %s has %u STUN servers, fewer than %u - the built-in list is used"), NATD_STUN_FILE, (unsigned)list.size(), (unsigned)NATD_STUN_FILE_MIN);
		return natd::stun::builtinServers();
	}
	AddLogLine(false, _T("NAT traversal: %u STUN servers from %s"), (unsigned)list.size(), NATD_STUN_FILE);
	return list;
}

void CNatTraversal::Impl::StartDiscovery(natd::TimePoint now)
{
	if (!pStun) {
		pStun = std::make_unique<natd::StunResolver>(StunServers());
		return;
	}
	if (!pStun->ready())
		return;
	const std::vector<natd::StunEndpoint> servers(pStun->servers());
	pAgent->start(now, servers);	// each client its own order of the servers
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: discovery started on UDP port %u with %u STUN servers"), thePrefs.GetUDPPort(), (unsigned)servers.size());
}

void CNatTraversal::Impl::Poll(natd::TimePoint now)
{
	pAgent->poll(now);
	HandleEvents(now);
	// the first verdict can come from a provisional result of the discovery: the final one may differ
	if (pAgent->profileReady() && Verdict() != nLoggedVerdict)
		LogVerdict(_T("now "));
}

// cs held
void CNatTraversal::Impl::HandleEvents(natd::TimePoint now)
{
	natd::AgentEvent e;
	while (pAgent->nextEvent(e)) {
		if (e.type == natd::AgentEventType::ProfileReady) {
			const natd::NatProfile &profile = pAgent->profile();
			LogVerdict(_T(""));
			if (thePrefs.GetVerbose())
				AddDebugLogLine(false, _T("NAT traversal: %hs, mapping %hs, filtering %hs"), natd::toString(profile.predictability)
					, natd::toString(profile.details.mapping), natd::toString(profile.details.filtering));
			continue;
		}
		if (e.type == natd::AgentEventType::EndpointChanged) {
			// the paths went with the old endpoint: their streams end as the TCP connections of a
			// client whose address changed. A LowID publishes its sources again: a punch through
			// its buddy goes towards the endpoint the index nodes saw them come from.
			LogVerdict(_T("changed to "));
			if (theApp.IsFirewalled() && theApp.sharedfiles != NULL)
				theApp.sharedfiles->ClearKadSourcePublishInfo();
			for (std::map<natd::SessionId, SSession>::iterator it = sessions.begin(); it != sessions.end(); ++it)
				if (it->second.pKcp && !it->second.bOver) {
					++nPathsAddressChanged;
					EndPath(it->second, WSAECONNRESET);
				}
			continue;
		}
		if (e.type == natd::AgentEventType::EndpointChecked) {
			if (thePrefs.GetVerbose())
				AddDebugLogLine(false, _T("NAT traversal: endpoint check: %hs, public endpoint %s"), natd::toString(pAgent->lastCheckResult()), (LPCTSTR)EndpointStr(pAgent->publicEndpoint()));
			continue;
		}
		const std::map<natd::SessionId, SSession>::iterator it = sessions.find(e.session);
		if (it == sessions.end()) {
			if (e.type == natd::AgentEventType::Punched)
				pAgent->cancel(e.session, now);	// a socket already gone
			continue;
		}
		SSession &s = it->second;
		if (e.type == natd::AgentEventType::Punched) {
			const std::optional<natd::PunchResult> r(pAgent->takeResult(e.session, now));
			if (r)
				Punched(e.session, s, *r, now, e.packets, e.rounds);
		} else if (e.type == natd::AgentEventType::PunchFailed) {
			if (thePrefs.GetVerbose())
				AddDebugLogLine(false, _T("NAT traversal: punch towards %s failed: %hs, %u packets in %u rounds"), (LPCTSTR)EndpointStr(s.remote), natd::toString(e.error)
					, e.packets, (unsigned)e.rounds);
			if (s.pLayer == NULL) {
				sessions.erase(it);	// a punch we were asked for, or a socket already gone
				continue;
			}
			// through a relay, timed out: once more with a new request (NATD_RELAY_TRIES). Through
			// the server it waits for the peer's request back again; through the source's buddy it
			// has a new nonce, so a new token, and we punch the source's endpoint again at once.
			CNatdSocketLayer *pLayer = s.pLayer;
			const DWORD dwNow = ::GetTickCount();
			const uint8 byVia = pLayer->GetVia();
			if (e.error == natd::PunchError::TimedOut && (byVia == NATD_VIA_SERVER || byVia == NATD_VIA_BUDDY)
				&& pLayer->GetTries() < NATD_RELAY_TRIES && dwNow - pLayer->GetAskedAt() < NATD_RELAY_RETRY_WITHIN && pLayer->IsConnecting())
			{
				if (byVia == NATD_VIA_SERVER) {
					const uint64 nKey = pLayer->GetServerPeer();
					if (waits.find(WaitKey(byVia, nKey)) == waits.end() && Ask(*pLayer, nKey, _T("ours, once more: the punch timed out"))) {
						sessions.erase(it);
						pLayer->Retry(nKey, NULL);
						waits[WaitKey(byVia, nKey)] = SWait{pLayer, dwNow, false};
						continue;
					}
				} else if (theApp.nattraversal->RetryThroughBuddy(pLayer)) {
					sessions.erase(it);
					continue;
				}
			}
			// as a TCP connection: refused, or timed out
			s.bOver = true;
			s.nPendingError = e.error == natd::PunchError::Refused ? WSAECONNREFUSED : WSAETIMEDOUT;
			s.lPendingEvents |= FD_CONNECT;
		}
	}
	RaiseEvents();
}

// The path is ours from here: the eD2K stream starts on it. Whichever side started the punch,
// the socket that asked connects, and the other side's socket is made now, as an accepted one.
void CNatTraversal::Impl::Punched(natd::SessionId id, SSession &s, const natd::PunchResult &r, natd::TimePoint now, uint32 nPackets, uint16 nRounds)
{
	s.path = r;
	s.remote = r.remote;
	SSession *pSession = &s;	// a map node: it stays where it is
	s.pKcp = std::make_unique<CNatdKcpTransport>(r.token, [this, pSession](const uint8_t *pSegment, size_t nLen) { SendPath(*pSession, 0, pSegment, nLen); }, now);
	s.tHeard = now;
	s.tKeepalive = now + r.keepalive;
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: punched to %s (%hs) after %u packets in %u rounds, stream open, keepalive every %u s"), (LPCTSTR)EndpointStr(r.remote)
			, natd::toString(r.strategy), nPackets, (unsigned)nRounds, (unsigned)(std::chrono::duration_cast<std::chrono::seconds>(r.keepalive).count()));
	if (s.pLayer != NULL)
		s.lPendingEvents |= FD_CONNECT;
	else
		Accept(id, s);
}

namespace
{
	// The IP filter and the bans on the address a punch goes to or comes from, logged as eMule logs
	// what it filters
	bool IsFilteredOrBanned(uint32 dwIP)
	{
		if (theApp.ipfilter->IsFiltered(dwIP)) {
			if (thePrefs.GetLogFilteredIPs())
				AddDebugLogLine(false, _T("NAT traversal: punch with filtered IP %s (%s) ignored"), (LPCTSTR)ipstr(dwIP), (LPCTSTR)theApp.ipfilter->GetLastHit());
			return true;
		}
		if (theApp.clientlist->IsBannedClient(dwIP)) {
			if (thePrefs.GetLogBannedClients())
				AddDebugLogLine(false, _T("NAT traversal: punch with banned IP %s ignored"), (LPCTSTR)ipstr(dwIP));
			return true;
		}
		return false;
	}

	// What a datagram of KCP's carries that is not new stream data, which the socket above counts as
	// over TCP: the segment headers, ACKs and window probes, and the data of a segment below snNew
	// (sent before, or received before). *pSnNext, if given, goes past the new ones.
	uint32 KcpOverhead(const uint8_t *p, size_t nLen, IUINT32 snNew, IUINT32 *pSnNext)
	{
		const size_t kSegmentHeader = 24;	// IKCP_OVERHEAD: conv 4, cmd 1, frg 1, wnd 2, ts 4, sn 4, una 4, len 4
		const uint8_t kCmdPush = 81;		// IKCP_CMD_PUSH
		uint32 nOverhead = 0;
		while (nLen >= kSegmentHeader) {
			const IUINT32 sn = PeekUInt32(p + 12);
			const size_t nData = (std::min)((size_t)PeekUInt32(p + 20), nLen - kSegmentHeader);
			nOverhead += (uint32)kSegmentHeader;
			if (p[4] != kCmdPush || (int)(sn - snNew) < 0)
				nOverhead += (uint32)nData;
			else if (pSnNext != NULL && (int)(sn + 1 - *pSnNext) > 0)
				*pSnNext = sn + 1;
			p += kSegmentHeader + nData;
			nLen -= kSegmentHeader + nData;
		}
		return nOverhead + (uint32)nLen;
	}
}

// Same steps as an accepted TCP connection in CListenSocket::OnAccept, but the socket has no
// TCP connection under it: the layer is the connection.
void CNatTraversal::Impl::Accept(natd::SessionId id, SSession &s)
{
	const uint32 dwIP = htonl(s.remote.ip);
	if (!theApp.listensocket->TooManySockets(true) && !IsFilteredOrBanned(dwIP)) {
		CClientReqSocket *pSocket = new CClientReqSocket;
		CNatdSocketLayer *pLayer = new CNatdSocketLayer(dwIP, s.remote.port, NULL, NATD_VIA_NONE);
		pSocket->AttachNatdLayer(pLayer);
		if (pSocket->Create()) {	// counts the connection, as CListenSocket::OnAccept does
			s.pLayer = pLayer;
			pLayer->Accepted(id);
			return;
		}
		pSocket->Safe_Delete();
	}
	Fin(s);	// the peer's socket connected: it closes now, as a refused one, not once the path is silent
	Erase(id);
}

// cs held. A datagram of a punched path; false when it is none of the paths open.
// A peer's traffic: the IP filter and the bans apply, as to the rest that reaches the port.
bool CNatTraversal::Impl::OnPath(const natd::Endpoint &from, const BYTE *pData, size_t nLen, natd::TimePoint now)
{
	if (nLen < NATD_PATH_HEADER || pData[0] != OP_UDPRESERVEDPROT1 || theApp.ipfilter->IsFiltered(htonl(from.ip)) || theApp.clientlist->IsBannedClient(htonl(from.ip)))
		return false;
	std::map<natd::SessionId, SSession>::iterator it = sessions.begin();	// a few: no index
	while (it != sessions.end() && (!it->second.pKcp || it->second.bOver || !(it->second.path.remote == from)
		|| memcmp(pData + 3, it->second.path.token.data(), it->second.path.token.size()) != 0))
		++it;
	if (it == sessions.end())
		return false;
	SSession &s = it->second;
	s.tHeard = now;
	if (pData[1] != NATD_TRANSPORT_KCP) {
		EndPath(s, WSAECONNRESET);	// the peer runs another transport: nothing on the path is for us
		return true;
	}
	// the stream is counted by the socket above, as over TCP: the rest of the datagram is overhead
	const bool bSegment = (pData[2] & (NATD_PATH_FIN | NATD_PATH_KEEPALIVE)) == 0 && nLen > NATD_PATH_HEADER;
	theStats.AddDownDataOverheadOther(bSegment ? NATD_PATH_HEADER + KcpOverhead(pData + NATD_PATH_HEADER, nLen - NATD_PATH_HEADER, s.pKcp->nextExpected(), NULL) : (uint32)nLen);
	if (pData[2] & NATD_PATH_FIN)
		s.bPeerFin = true;
	else if (bSegment)
		s.pKcp->input(pData + NATD_PATH_HEADER, nLen - NATD_PATH_HEADER);
	Signal(s);
	return true;
}

// cs held. Each path: KCP's timers; ended when it went silent for NATD_PATH_DEAD_AFTER keepalive
// intervals or KCP gave up, as a TCP connection that broke, and then our endpoint is checked (the
// NAT may have lost its mappings, or the address changed); a keepalive when nothing went for
// natd's interval; a FIN once the stream of a socket that went is through.
void CNatTraversal::Impl::PollPaths(natd::TimePoint now)
{
	const DWORD dwNow = ::GetTickCount();
	for (std::vector<SFin>::iterator it = fins.begin(); it != fins.end();) {
		if ((LONG)(dwNow - it->dwNext) < 0) {
			++it;
			continue;
		}
		SendDatagram(it->socket, it->remote, it->token, NATD_PATH_FIN, NULL, 0);
		theStats.AddUpDataOverheadOther(NATD_PATH_HEADER);
		it->dwNext += NATD_PATH_FIN_GAP;
		it = (--it->nLeft > 0) ? std::next(it) : fins.erase(it);
	}
	for (std::map<natd::SessionId, SSession>::iterator it = sessions.begin(); it != sessions.end();) {
		const natd::SessionId id = it->first;
		SSession &s = (it++)->second;
		if (!s.pKcp || s.bOver)
			continue;
		s.pKcp->poll(now);
		if (s.pKcp->failed() || now - s.tHeard >= s.path.keepalive * NATD_PATH_DEAD_AFTER) {
			if (thePrefs.GetVerbose())
				AddDebugLogLine(false, _T("NAT traversal: stream with %s ended: nothing from it for %u keepalive intervals, checking the public endpoint"), (LPCTSTR)EndpointStr(s.remote), (unsigned)NATD_PATH_DEAD_AFTER);
			++nPathsDead;
			EndPath(s, WSAECONNRESET);
			pAgent->checkEndpoint(now);
			if (s.pLayer == NULL)
				Erase(id);
			continue;
		}
		if (s.dwDetached != 0) {
			if (s.pKcp->flushed() || dwNow - s.dwDetached >= NATD_PATH_LINGER) {
				Fin(s);
				Erase(id);
			}
			continue;
		}
		if (now >= s.tKeepalive)
			SendPath(s, NATD_PATH_KEEPALIVE, NULL, 0);
		Signal(s);
	}
	RaiseEvents();
}

// cs held. One datagram on the path; the next keepalive after natd's interval, less a random
// tenth of it (RFC 8085 3.5: no clients in step).
void CNatTraversal::Impl::SendPath(SSession &s, uint8 byFlags, const uint8_t *pSegment, size_t nLen)
{
	if (nLen > NATD_PATH_SEGMENT)
		return;
	SendDatagram(s.path.socket, s.path.remote, s.path.token, byFlags, pSegment, nLen);
	theStats.AddUpDataOverheadOther(NATD_PATH_HEADER + (nLen > 0 ? KcpOverhead(pSegment, nLen, s.snSentNext, &s.snSentNext) : 0));
	const natd::Duration keepalive(s.path.keepalive);
	s.tKeepalive = natd::Clock::now() + keepalive - natd::Duration(GetRandomUInt16() % (keepalive.count() / 10 + 1));
}

// cs held. <OP_UDPRESERVEDPROT1><transport><flags><token> and the segment, nLen <= NATD_PATH_SEGMENT
void CNatTraversal::Impl::SendDatagram(natd::SocketId socket, const natd::Endpoint &remote, const natd::TxId &token, uint8 byFlags, const uint8_t *pSegment, size_t nLen)
{
	static_assert(NATD_PATH_HEADER == 3 + sizeof(natd::TxId), "the path header carries the token");
	BYTE abyDatagram[NATD_PATH_HEADER + NATD_PATH_SEGMENT];
	abyDatagram[0] = OP_UDPRESERVEDPROT1;
	abyDatagram[1] = NATD_TRANSPORT_KCP;
	abyDatagram[2] = byFlags;
	memcpy(abyDatagram + 3, token.data(), token.size());
	if (nLen > 0)
		memcpy(abyDatagram + NATD_PATH_HEADER, pSegment, nLen);
	io.send(socket, remote, abyDatagram, NATD_PATH_HEADER + nLen);
}

// cs held. The end of our stream, NATD_PATH_FINS times (PollPaths): the session can go at once.
void CNatTraversal::Impl::Fin(const SSession &s)
{
	SendDatagram(s.path.socket, s.path.remote, s.path.token, NATD_PATH_FIN, NULL, 0);
	theStats.AddUpDataOverheadOther(NATD_PATH_HEADER);
	fins.push_back(SFin{s.path.socket, s.path.remote, s.path.token, ::GetTickCount() + NATD_PATH_FIN_GAP, NATD_PATH_FINS - 1});
}

// cs held. The path is over, as a TCP connection that broke: the socket reads what arrived
// before, then closes with nError.
void CNatTraversal::Impl::EndPath(SSession &s, int nError)
{
	if (s.bOver)
		return;
	s.bOver = true;
	s.nPendingError = nError;
	Signal(s);
}

// cs held. The events the stream is due: data to read, room to write again, and its end once
// what arrived before it is read.
void CNatTraversal::Impl::Signal(SSession &s)
{
	if (s.pLayer == NULL || !s.pKcp)
		return;
	if (s.pKcp->readable() > 0)
		s.lPendingEvents |= FD_READ;
	if (s.bWantWrite && !s.bOver && s.pKcp->writable()) {
		s.bWantWrite = false;
		s.lPendingEvents |= FD_WRITE;
	}
	if ((s.bOver || s.bPeerFin) && s.pKcp->readable() == 0)
		s.lPendingEvents |= FD_CLOSE;
}

// cs held. The session goes: a punch still on is cancelled. A path is on the client UDP socket
// (eMule asks natd for direct punches only), which stays.
void CNatTraversal::Impl::Erase(natd::SessionId id)
{
	const std::map<natd::SessionId, SSession>::iterator it = sessions.find(id);
	if (it == sessions.end())
		return;
	if (!it->second.pKcp)
		pAgent->cancel(id, natd::Clock::now());
	sessions.erase(it);
}

// cs held
void CNatTraversal::Impl::RaiseEvents()
{
	for (std::map<natd::SessionId, SSession>::iterator it = sessions.begin(); it != sessions.end(); ++it) {
		SSession &s = it->second;
		if (s.lPendingEvents == 0 || s.pLayer == NULL)
			continue;
		const long lEvents = s.lPendingEvents;
		s.lPendingEvents = 0;
		if (lEvents & FD_CONNECT)
			s.pLayer->RaiseEvent(FD_CONNECT, s.pKcp && !s.bOver ? 0 : (s.nPendingError ? s.nPendingError : WSAETIMEDOUT));
		if ((lEvents & FD_READ) && !s.bReadPosted) {
			s.bReadPosted = true;
			s.pLayer->RaiseEvent(FD_READ, 0);
		}
		if (lEvents & FD_WRITE)
			s.pLayer->RaiseEvent(FD_WRITE, 0);
		if ((lEvents & FD_CLOSE) && !s.bClosePosted) {
			s.bClosePosted = true;
			s.pLayer->RaiseEvent(FD_CLOSE, s.nPendingError);
		}
	}
}

CNatTraversal::CNatTraversal()
	: m_pImpl(std::make_unique<Impl>())
	, m_bEnabled(thePrefs.IsNatTraversalEnabled())
{
	if (!m_bEnabled)
		theApp.QueueLogLine(false, _T("NAT traversal: off in the preferences, no NAT discovery and no punch"));	// before the window
}

// The natd counters, for an investigation: once an hour.
void CNatTraversal::Impl::LogStats(LPCTSTR pszWhen) const
{
	if (!thePrefs.GetVerbose() || !pAgent->started())
		return;
	const natd::AgentStats &st = pAgent->stats();
	AddDebugLogLine(false, _T("NAT traversal: counters (%s): punches started %I64u, queued %I64u, established %I64u, failed %I64u, refused %I64u; streams dead %I64u, ended for an address change %I64u; endpoint checks %I64u, reused %I64u, changes %I64u; sessions now %u")
		, pszWhen, st.punchesStarted, st.punchesQueued, st.punchesEstablished, st.punchesFailed, st.punchesRefused
		, nPathsDead, nPathsAddressChanged, st.endpointChecks, st.endpointChecksReused, st.endpointChanges, (unsigned)sessions.size());
}

// The FINs go back to back: nothing runs after to space them (NATD_PATH_FIN_GAP)
void CNatTraversal::Shutdown()
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	Impl &impl = *m_pImpl;
	for (std::vector<Impl::SFin>::const_iterator it = impl.fins.begin(); it != impl.fins.end(); ++it)
		for (int i = 0; i < it->nLeft; ++i)
			impl.SendDatagram(it->socket, it->remote, it->token, NATD_PATH_FIN, NULL, 0);
	impl.fins.clear();
	for (std::map<natd::SessionId, SSession>::iterator it = impl.sessions.begin(); it != impl.sessions.end(); ++it) {
		SSession &s = it->second;
		if (!s.pKcp || s.bOver)
			continue;
		for (int i = 0; i < NATD_PATH_FINS; ++i)
			impl.SendDatagram(s.path.socket, s.path.remote, s.path.token, NATD_PATH_FIN, NULL, 0);
		s.bOver = true;
	}
}

CNatTraversal::~CNatTraversal()
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	for (std::map<natd::SessionId, SSession>::iterator it = m_pImpl->sessions.begin(); it != m_pImpl->sessions.end(); ++it)
		if (it->second.pLayer != NULL) {
			it->second.pLayer->Orphan();
			it->second.pLayer = NULL;
		}
	m_pImpl->sessions.clear();
}

// natd's and STUN's formats, and the paths' first byte, which no other protocol of eMule uses:
// all the rest of the client UDP traffic (Kad, eD2K) goes on at once, without the lock
bool CNatTraversal::OnDatagram(const BYTE *pData, int nLen, uint32 dwIP, uint16 nPort)
{
	if (!m_bEnabled)
		return false;
	const bool bNatd = nLen > 0 && (natd::proto::isNatdPacket(pData, (size_t)nLen) || natd::stun::isStunPacket(pData, (size_t)nLen));
	if (!bNatd && (nLen <= 0 || pData[0] != OP_UDPRESERVEDPROT1))
		return false;
	CSingleLock lock(&m_pImpl->cs, TRUE);
	const natd::TimePoint now = natd::Clock::now();
	const natd::Endpoint from{ntohl(dwIP), nPort};
	if (bNatd) {	// natd's, also a late answer or a packet of a punch already over
		m_pImpl->pAgent->onDatagram(kPrimarySocket, from, pData, (size_t)nLen, now);
		m_pImpl->HandleEvents(now);
		return true;
	}
	// a path's, also a late one of a path already over (the peer's retransmissions, its FINs): no
	// other protocol of eMule starts with that byte, and eMule would only log it as unknown
	if (m_pImpl->OnPath(from, pData, (size_t)nLen, now))
		m_pImpl->RaiseEvents();
	return true;
}

void CNatTraversal::Process()
{
	if (!m_bEnabled)
		return;
	Impl &impl = *m_pImpl;
	const natd::TimePoint now = natd::Clock::now();
	CSingleLock lock(&impl.cs, TRUE);
	// before the connection, which waits for it (DelayConnection); else as soon as we are a
	// LowID: on the server, or in Kad once its firewall check is over (Kad says firewalled while
	// it checks) - a connection made without the wait (a server picked in the list, Kad started
	// from its window)
	if (!impl.pAgent->started() && theApp.clientudp != NULL && theApp.clientudp->m_hSocket != INVALID_SOCKET
		&& (impl.dwConnectWait != 0
			|| (theApp.IsFirewalled()
				&& ((theApp.serverconnect->IsConnected() && theApp.serverconnect->IsLowID())
					|| (Kademlia::CKademlia::IsConnected() && Kademlia::CKademlia::IsFirewalled() && !Kademlia::CKademlia::GetPrefs()->GetRecheckIP())))))
	{
		impl.StartDiscovery(now);
	}
	// the sockets natd opened itself: what arrived since the last call, without waiting
	impl.io.m_extra.wait(now, [&impl, now](natd::SocketId id, const natd::Endpoint &from, const uint8_t *pData, size_t nLen) {
		impl.pAgent->onDatagram(id, from, pData, nLen, now);
	});
	impl.Poll(now);
	impl.PollPaths(now);
	if (impl.pAgent->started() && ::GetTickCount() - impl.dwLastStats >= (DWORD)HR2MS(1)) {
		if (impl.dwLastStats != 0)
			impl.LogStats(_T("last hour"));
		impl.dwLastStats = ::GetTickCount();
	}
	ServerTimer();
	RelayTimer();
	bool bConnect = false;
	if (impl.bConnectWaiting && (impl.pAgent->profileReady() || ::GetTickCount() - impl.dwConnectWait >= NATD_CONNECT_WAIT)) {
		impl.bConnectWaiting = false;
		bConnect = true;
		if (!impl.pAgent->profileReady())
			AddLogLine(false, _T("NAT traversal: no result of the discovery after %u s, the connection waits no longer"), (unsigned)(NATD_CONNECT_WAIT / SEC2MS(1)));
	}
	lock.Unlock();
	if (bConnect)	// it may log in at once, which asks AnnounceServerPunch()
		theApp.emuledlg->EndStartupNetCheck();
}

// As UPnP before it (NatTraversal.h). The discovery's own mappings, about fifty, then do not
// come from the block of ports of the connection's, on a NAT with blocks per subscriber.
bool CNatTraversal::DelayConnection()
{
	if (!m_bEnabled)
		return false;
	Impl &impl = *m_pImpl;
	CSingleLock lock(&impl.cs, TRUE);
	if (impl.pAgent->profileReady() || theApp.clientudp == NULL || theApp.clientudp->m_hSocket == INVALID_SOCKET)
		return false;
	const DWORD dwNow = ::GetTickCount();
	if (impl.dwConnectWait == 0) {
		impl.dwConnectWait = dwNow ? dwNow : 1;
		AddLogLine(false, _T("NAT traversal: the connection waits for the NAT discovery, at most %u s"), (unsigned)(NATD_CONNECT_WAIT / SEC2MS(1)));
	} else if (dwNow - impl.dwConnectWait >= NATD_CONNECT_WAIT)
		return false;	// it had its time, once
	impl.bConnectWaiting = true;
	return true;
}

// The server we are logged in to: whether it coordinates punches for us (a LowID there, with
// the crypt layer for its obfuscated requests), and its UDP key.
void CNatTraversal::ServerTimer()
{
	Impl &impl = *m_pImpl;
	Impl::SServer &sv = impl.server;
	CServer *pCur = theApp.serverconnect->IsConnected() && theApp.serverconnect->IsLowID() ? theApp.serverconnect->GetCurrentServer() : NULL;
	const bool bCoordinates = pCur != NULL && (pCur->GetTCPFlags() & SRVCAP_NATTRAVERSAL) != 0 && thePrefs.IsCryptLayerEnabled();
	const uint32 dwIP = bCoordinates ? pCur->GetIP() : 0;
	const uint16 nPort = bCoordinates ? pCur->GetPort() : 0;
	const uint32 nID = bCoordinates ? theApp.serverconnect->GetClientID() : 0;
	const DWORD dwNow = ::GetTickCount();
	if (dwIP != sv.dwIP || nPort != sv.nPort || nID != sv.nID) {
		for (std::map<Impl::WaitKey, Impl::SWait>::iterator it = impl.waits.begin(); it != impl.waits.end();) {
			const Impl::WaitKey key((it++)->first);
			if (key.first == NATD_VIA_SERVER)
				DropWait(key.first, key.second, WSAECONNREFUSED);
		}
		impl.again.erase(std::remove_if(impl.again.begin(), impl.again.end(), [](const Impl::SAgain &a) { return a.byVia == NATD_VIA_SERVER; }), impl.again.end());
		sv = Impl::SServer();
		sv.dwIP = dwIP;
		sv.nPort = nPort;
		sv.nID = nID;
		if (dwIP != 0 && thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: the server %s:%u coordinates punches between LowIDs, our ID %u"), (LPCTSTR)ipstr(dwIP), nPort, nID);
	}
	if (sv.dwIP == 0)
		return;
	// the UDP key the requests are obfuscated with
	if (sv.dwKey == 0 && sv.nPings < NATD_SERVER_PINGS && (sv.nPings == 0 || dwNow - sv.dwPinged >= NATD_SERVER_PING_RETRY))
		impl.ServerPing(dwNow);
	else if (sv.dwKey == 0 && !sv.bGaveUp && dwNow - sv.dwPinged >= NATD_SERVER_PING_RETRY) {
		sv.bGaveUp = true;
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: the server %s:%u did not answer %u status requests on UDP port %u: no punches through it until the next login, and its requests to us are dropped")
				, (LPCTSTR)ipstr(sv.dwIP), sv.nPort, sv.nPings, (unsigned)(uint16)(sv.nPort + 12));
	}
}

// The obfuscated status request, from the client UDP port: the server answers with the UDP key
// for our IP, obfuscated with the challenge (CServerList::ServerStats does the same from the
// server UDP socket)
void CNatTraversal::Impl::ServerPing(DWORD dwNow)
{
	uint32 dwChallenge = 0;
	while (dwChallenge == 0)
		natd::defaultRandomBytes()(reinterpret_cast<uint8_t*>(&dwChallenge), sizeof dwChallenge);
	BYTE abyPing[4 + 15];
	natd::defaultRandomBytes()(abyPing, sizeof abyPing);
	PokeUInt32(abyPing, dwChallenge);
	const size_t nLen = 4 + (abyPing[4] & 0x0f);	// up to 15 bytes of padding
	server.dwChallenge = dwChallenge;
	server.dwPinged = dwNow;
	++server.nPings;
	theStats.AddUpDataOverheadServer((uint32)nLen);
	io.send(kPrimarySocket, natd::Endpoint{ntohl(server.dwIP), (uint16)(server.nPort + 12)}, abyPing, nLen);
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: status request %u of %u to the server %s, UDP port %u, for its UDP key")
			, server.nPings, (unsigned)NATD_SERVER_PINGS, (LPCTSTR)ipstr(server.dwIP), (unsigned)(uint16)(server.nPort + 12));
}

// <target ID 4><our ID 4>, from the client UDP port: the server forwards it with the endpoint it
// saw it come from. False without the server's UDP key.
bool CNatTraversal::Impl::ServerRequest(uint32 nTargetID, LPCTSTR pszWhy)
{
	if (server.dwKey == 0) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: request to ID %u not sent (%s): no UDP key of the server yet"), nTargetID, pszWhy);
		return false;
	}
	BYTE abyBuf[64];
	BYTE *pPacket = abyBuf + CClientUDPSocket::ServerOverheadSize();
	pPacket[0] = OP_EDONKEYPROT;
	pPacket[1] = OP_NAT_CALLBACK_REQUEST;
	PokeUInt32(pPacket + 2, nTargetID);
	PokeUInt32(pPacket + 6, server.nID);
	const uint32 nLen = CClientUDPSocket::EncryptForServer(abyBuf, 10, server.dwKey);
	theStats.AddUpDataOverheadServer(nLen);
	io.send(kPrimarySocket, natd::Endpoint{ntohl(server.dwIP), server.nObfuscationPort}, abyBuf, nLen);
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: request to ID %u sent to the server, UDP port %u (%s)"), nTargetID, server.nObfuscationPort, pszWhy);
	return true;
}

bool CNatTraversal::Impl::BuddyRequest(const uchar *pBuddyID, uint32 dwIP, uint16 nPort, const uchar *pFile, uint64 nNonce, LPCTSTR pszWhy)
{
	if (IsFilteredOrBanned(dwIP) || nPort == 0)
		return false;
	CSafeMemFile data(128);
	data.WriteUInt8(OP_EMULEPROT);
	data.WriteUInt8(OP_REASKCALLBACKUDP);
	data.WriteHash16(pBuddyID);
	data.WriteHash16(pFile);
	WriteMarker(data, nNonce);
	WriteCallback(data, 0);
	const uint32 nLen = (uint32)data.GetLength();
	theStats.AddUpDataOverheadOther(nLen);
	const bool bSent = io.send(kPrimarySocket, natd::Endpoint{ntohl(dwIP), nPort}, data.GetBuffer(), nLen);
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: request to the source's buddy %s:%u%s (%s)"), (LPCTSTR)ipstr(dwIP), nPort, bSent ? _T("") : _T(" not sent"), pszWhy);
	return bSent;
}

bool CNatTraversal::Impl::Ask(const CNatdSocketLayer &layer, uint64 nKey, LPCTSTR pszWhy)
{
	if (layer.GetVia() == NATD_VIA_SERVER)
		return ServerRequest((uint32)nKey, pszWhy);
	return BuddyRequest(layer.GetRelayID(), layer.GetRelayIP(), layer.GetRelayPort(), layer.GetFile(), nKey, pszWhy);
}

void CNatTraversal::Impl::AskAgain(const CNatdSocketLayer &layer, uint64 nNonce)
{
	std::array<uchar, 16> abyBuddyID, abyFile;
	md4cpy(abyBuddyID.data(), layer.GetRelayID());
	md4cpy(abyFile.data(), layer.GetFile());
	const uint32 dwIP = layer.GetRelayIP();
	const uint16 nPort = layer.GetRelayPort();
	again.push_back(SAgain{::GetTickCount(), NATD_VIA_BUDDY, [this, abyBuddyID, dwIP, nPort, abyFile, nNonce]() {
		BuddyRequest(abyBuddyID.data(), dwIP, nPort, abyFile.data(), nNonce, _T("ours, again"));
	}});
}

bool CNatTraversal::OnServerDatagram(BYTE *pData, int nLen, const SOCKADDR_IN &from)
{
	Impl::SServer &sv = m_pImpl->server;
	const uint16 nPort = ntohs(from.sin_port);
	if (sv.dwIP == 0 || from.sin_addr.s_addr != sv.dwIP || (nPort != (uint16)(sv.nPort + 12) && nPort != sv.nObfuscationPort))
		return false;
	const uint32 dwKey = sv.dwKey != 0 ? sv.dwKey : sv.dwChallenge;
	if (dwKey == 0) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: datagram of %d bytes from the server, UDP port %u, dropped: nothing asked yet"), nLen, nPort);
		return true;
	}
	BYTE *pPacket;
	const int nPacket = CClientUDPSocket::DecryptFromServer(pData, nLen, &pPacket, dwKey, from);
	if (nPacket < 2 || pPacket == pData || pPacket[0] != OP_EDONKEYPROT) {	// only obfuscated ones
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: datagram of %d bytes from the server, UDP port %u, dropped: not obfuscated with the %s"), nLen, nPort
				, sv.dwKey != 0 ? _T("server's UDP key") : _T("challenge of our status request"));
		return true;
	}
	theStats.AddDownDataOverheadServer((uint32)nPacket);
	if (pPacket[1] == OP_GLOBSERVSTATRES) {
		if (sv.dwKey == 0 && nPacket >= 2 + 40 && PeekUInt32(pPacket + 2) == sv.dwChallenge) {
			sv.nObfuscationPort = PeekUInt16(pPacket + 2 + 32);
			if (sv.nObfuscationPort == 0)
				sv.nObfuscationPort = (uint16)(sv.nPort + 12);
			sv.dwKey = PeekUInt32(pPacket + 2 + 36);
			if (thePrefs.GetVerbose())
				AddDebugLogLine(false, _T("NAT traversal: punches can be asked through the server %s:%u (UDP port %u)%s"), (LPCTSTR)ipstr(sv.dwIP), sv.nPort, sv.nObfuscationPort
					, theApp.ipfilter->IsFiltered(sv.dwIP) ? _T(" - the server is in the IP filter, its answers let through") : _T(""));
		} else if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: status answer of the server dropped: %s"), sv.dwKey != 0 ? _T("we have its UDP key already")
				: nPacket < 2 + 40 ? _T("too short") : _T("not the challenge of our last request"));
	} else if (pPacket[1] == OP_NAT_CALLBACK_UDP)
		OnServerCallback(pPacket + 2, (uint32)(nPacket - 2), true);
	else if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: datagram from the server dropped: opcode 0x%02x"), pPacket[1]);
	return true;
}

// Lugdunum's NAT callback: <IP 4><UDP port 2> as the server saw them, then the request
void CNatTraversal::OnServerCallback(const BYTE *pData, uint32 nSize, bool bUdp)
{
	if (!m_bEnabled)
		return;
	LPCTSTR pszHow = bUdp ? _T("UDP") : _T("TCP");
	if (nSize < 6) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: punch request through the server (%s) dropped: %u bytes"), pszHow, nSize);
		return;
	}
	CSafeMemFile data(pData, nSize);
	const uint32 dwIP = data.ReadUInt32();
	const uint16 nPort = data.ReadUInt16();
	SNatCallback cb;
	if (!ReadCallback(data, dwIP, nPort, cb) || cb.nID == 0) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: punch request through the server (%s) from %s:%u not taken: no user hash or no ID"), pszHow, (LPCTSTR)ipstr(dwIP), nPort);
		return;
	}
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: punch request through the server (%s) from ID %u at %s:%u"), pszHow, cb.nID, (LPCTSTR)ipstr(dwIP), nPort);
	if (!m_pImpl->server.Ready()) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: punch request from ID %u dropped: no UDP key of the server, which our request back needs"), cb.nID);
		return;
	}
	OnServerPeer(cb);
}

void CNatTraversal::DropWait(uint8 byVia, uint64 nKey, int nError)
{
	const std::map<Impl::WaitKey, Impl::SWait>::iterator it = m_pImpl->waits.find(Impl::WaitKey(byVia, nKey));
	if (it == m_pImpl->waits.end())
		return;
	CNatdSocketLayer *pLayer = it->second.pLayer;
	m_pImpl->waits.erase(it);
	pLayer->m_nWait = 0;
	if (nError != 0)
		pLayer->RaiseEvent(FD_CONNECT, nError);
}

// The peer's request back through the relay, with its endpoint as the relay saw it: the socket
// waiting for it with that key gets the punch, towards that endpoint. False when none waits.
bool CNatTraversal::Answered(uint8 byVia, uint64 nKey, const SNatCallback &cb, const BYTE *pToken12, bool bConnect)
{
	const std::map<Impl::WaitKey, Impl::SWait>::const_iterator it = m_pImpl->waits.find(Impl::WaitKey(byVia, nKey));
	if (it == m_pImpl->waits.end())
		return false;
	CNatdSocketLayer *pLayer = it->second.pLayer;
	DropWait(byVia, nKey, 0);
	pLayer->m_dwIP = cb.dwIP;
	pLayer->m_nPort = cb.nPort;
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: our punch request answered %s, endpoint %s:%u"), ViaStr(byVia), (LPCTSTR)ipstr(cb.dwIP), cb.nPort);
	if (pLayer->GetLayerState() != connecting) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: punch with %s:%u not started: our socket is no longer connecting"), (LPCTSTR)ipstr(cb.dwIP), cb.nPort);
		pLayer->RaiseEvent(FD_CONNECT, WSAECONNREFUSED);
	} else if (!OpenSession(cb.dwIP, cb.nPort, pToken12 != NULL ? pToken12 : pLayer->GetToken(), bConnect, pLayer, byVia, pLayer->GetServerPeer()))
		pLayer->RaiseEvent(FD_CONNECT, WSAECONNREFUSED);
	return true;
}

// A request the server forwarded: the answer to ours, or a new one, which we punch and ask back.
// Two LowIDs that asked each other at once both get the one punch and both send their hello,
// which eMule answers as a repeated one; should both crypt layers start the handshake, that
// connection fails, and the next ask, no longer at once, gets through.
void CNatTraversal::OnServerPeer(const SNatCallback &cb)
{
	Impl &impl = *m_pImpl;
	const bool bConnect = impl.server.nID < cb.nID;
	const DWORD dwNow = ::GetTickCount();
	// a copy (each request goes twice) while the punch it asked for is on; once that punch is
	// over, the peer asks once more
	{
		CSingleLock lock(&impl.cs, TRUE);
		impl.Poll(natd::Clock::now());	// a punch whose time is up by now is over
		for (const std::pair<const natd::SessionId, SSession> &se : impl.sessions)
			if (se.second.nServerPeer == cb.nID && !se.second.bOver) {
				if (thePrefs.GetVerbose())
					AddDebugLogLine(false, _T("NAT traversal: punch request from ID %u already taken"), cb.nID);
				return;
			}
	}
	// what both sides know: the user hash of the one that starts and both IDs, its own first
	const natd::TxId token(bConnect ? natd::tokenFrom(thePrefs.GetUserHash(), 16, ServerNonce(impl.server.nID, cb.nID))
		: natd::tokenFrom(cb.abyHash, 16, ServerNonce(cb.nID, impl.server.nID)));
	if (Answered(NATD_VIA_SERVER, cb.nID, cb, token.data(), bConnect))
		return;
	// the request back before our first punch packet, which the next Process() sends: the
	// mapping towards the peer then comes right after the one the server sees (sequential ports)
	if (OpenSession(cb.dwIP, cb.nPort, token.data(), bConnect, NULL, NATD_VIA_SERVER, cb.nID) && impl.ServerRequest(cb.nID, _T("back, so that it learns our endpoint"))) {
		const uint32 nID = cb.nID;
		impl.again.push_back(Impl::SAgain{dwNow, NATD_VIA_SERVER, [&impl, nID]() { impl.ServerRequest(nID, _T("back, again")); }});
	}
}

void CNatTraversal::ForgetLayer(CNatdSocketLayer *pLayer)
{
	const std::map<Impl::WaitKey, Impl::SWait>::iterator it = m_pImpl->waits.find(Impl::WaitKey(pLayer->GetVia(), pLayer->m_nWait));
	if (it != m_pImpl->waits.end() && it->second.pLayer == pLayer)
		m_pImpl->waits.erase(it);
	pLayer->m_nWait = 0;
}

// Our requests through a relay not answered yet go once more, then time out; the requests back
// go once more
void CNatTraversal::RelayTimer()
{
	Impl &impl = *m_pImpl;
	const DWORD dwNow = ::GetTickCount();
	std::vector<Impl::WaitKey> expired;
	for (std::pair<const Impl::WaitKey, Impl::SWait> &w : impl.waits)
		if (dwNow - w.second.dwSent >= NATD_RELAY_WAIT)
			expired.push_back(w.first);
		else if (!w.second.bResent && dwNow - w.second.dwSent >= NATD_RELAY_RESEND) {
			impl.Ask(*w.second.pLayer, w.first.second, _T("ours, again: no answer yet"));
			w.second.bResent = true;
		}
	for (const Impl::WaitKey &key : expired) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: no answer %s to our punch request"), ViaStr(key.first));
		DropWait(key.first, key.second, WSAETIMEDOUT);
	}
	while (!impl.again.empty() && dwNow - impl.again.front().dwSent >= NATD_RELAY_RESEND) {
		impl.again.front().send();
		impl.again.pop_front();
	}
}

bool CNatTraversal::IsPunchable() const
{
	return m_pImpl->pAgent->punchable();
}

bool CNatTraversal::IsDirectPunchable() const
{
	return m_pImpl->pAgent->directPunchable();
}

// One check at a time, none within natd's checkReuse (a minute) of the last one, whose result stands.
void CNatTraversal::OnBuddyLost()
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	if (m_pImpl->pAgent->directPunchable()) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: buddy lost, checking the public endpoint%s"), m_pImpl->pAgent->checking() ? _T(" (a check is on already)") : _T(""));
		m_pImpl->pAgent->checkEndpoint(natd::Clock::now());
	}
}

// LowID->LowID (CemuleApp::CanDoCallback said no) between two clients that can be punched to,
// for a file we download from the source: the only case where a punch is tried.
uint8 CNatTraversal::PunchVia(const CUpDownClient &client) const
{
	if (!m_pImpl->pAgent->punchable() || client.GetRequestFile() == NULL || thePrefs.GetUDPPort() == 0)
		return NATD_VIA_NONE;
	// one channel a connection attempt, as eMule's callbacks, and in their order: the server
	// first, Kad only when the server cannot reach the source
	if (client.HasLowID() && ServerCanPunch(client.GetUserIDHybrid(), client.GetServerIP(), client.GetServerPort()))
		return NATD_VIA_SERVER;
	// a source that published in Kad that it can be punched to: directly, with an open UDP
	// port, or through its buddy, towards the endpoint its Kad record has (KademliaSearchFile).
	// The addresses are checked when they are punched to.
	if (client.IsNatdSource() && Kademlia::CKademlia::IsConnected() && Kademlia::CKademlia::IsFirewalled()
		&& client.GetConnectIP() != 0 && client.GetKadPort() != 0)
	{
		if (client.SupportsDirectUDPCallback()) {
			if (m_pImpl->pAgent->directPunchable() && !IsFilteredOrBanned(client.GetConnectIP()))
				return NATD_VIA_DIRECT;
		} else if (client.HasValidBuddyID() && client.GetBuddyIP() != 0 && client.GetBuddyPort() != 0)
			return NATD_VIA_BUDDY;
	}
	return NATD_VIA_NONE;
}

// the login normally comes after the discovery (DelayConnection)
bool CNatTraversal::AnnounceServerPunch() const
{
	return m_bEnabled && (!m_pImpl->pAgent->profileReady() || m_pImpl->pAgent->punchable());
}

bool CNatTraversal::ServerCanPunch(uint32 nID, uint32 dwServerIP, uint16 nServerPort) const
{
	const Impl::SServer &sv = m_pImpl->server;
	return sv.Ready() && m_pImpl->pAgent->punchable() && ::IsLowID(nID) && (nID & 1) != 0 && nID != sv.nID
		&& theApp.serverconnect->IsLocalServer(dwServerIP, nServerPort);
}

// Through Kad the token comes from our user hash and the marker's nonce; through the server the
// endpoint and the token come with the server's answer (OnServerPeer).
bool CNatTraversal::AttachOutgoing(CClientReqSocket *pSocket, CUpDownClient &client, uint8 byVia)
{
	if (byVia == NATD_VIA_NONE)
		return false;
	const uint64 nNonce = RandomUInt64();
	CNatdSocketLayer *pLayer;
	if (byVia == NATD_VIA_DIRECT) {
		// a source with an open UDP port: the three fields of OP_DIRECTCALLBACKREQ, which is all
		// an unpatched client reads, are the request's (the port, the user hash, the crypt
		// settings) and its endpoint is the one the datagram comes from
		CSafeMemFile data(64);
		data.WriteUInt16(thePrefs.GetPort());
		data.WriteHash16(thePrefs.GetUserHash());
		data.WriteUInt8(GetMyConnectOptions(true, false));
		WriteMarker(data, nNonce);
		Packet *packet = new Packet(data, OP_EMULEPROT);
		packet->opcode = OP_DIRECTCALLBACKREQ;
		theStats.AddUpDataOverheadOther(packet->size);
		theApp.clientudp->SendPacket(packet, client.GetConnectIP(), client.GetKadPort(), client.ShouldReceiveCryptUDPPackets(), client.GetUserHash(), false, 0);
		pLayer = new CNatdSocketLayer(client.GetConnectIP(), client.GetKadPort(), natd::tokenFrom(thePrefs.GetUserHash(), 16, nNonce).data(), byVia);
	} else if (byVia == NATD_VIA_BUDDY) {
		// through the source's buddy, which forwards our request with the endpoint it saw it
		// come from; nothing comes back but the source's punch, so the socket punches the
		// source's endpoint from its Kad record as soon as it connects, as for a direct punch
		pLayer = new CNatdSocketLayer(client.GetConnectIP(), client.GetKadPort(), natd::tokenFrom(thePrefs.GetUserHash(), 16, nNonce).data(), byVia);
		pLayer->m_dwRelayIP = client.GetBuddyIP();
		pLayer->m_nRelayPort = client.GetBuddyPort();
		md4cpy(pLayer->m_abyRelayID, client.GetBuddyID());
		md4cpy(pLayer->m_abyFile, client.GetRequestFile()->GetFileHash());
		if (!m_pImpl->Ask(*pLayer, nNonce, _T("ours"))) {
			delete pLayer;
			return false;
		}
		pLayer->m_dwAsked = ::GetTickCount();
		m_pImpl->AskAgain(*pLayer, nNonce);
	} else {
		// through the server, keyed by the target's ID there
		const uint64 nKey = client.GetUserIDHybrid();
		pLayer = new CNatdSocketLayer(0, 0, NULL, byVia);
		pLayer->m_nServerPeer = client.GetUserIDHybrid();
		if (!m_pImpl->Ask(*pLayer, nKey, _T("ours"))) {
			delete pLayer;
			return false;
		}
		DropWait(byVia, nKey, WSAECONNREFUSED);	// one request at a time to a target: an older one gives way
		pLayer->m_nWait = nKey;
		pLayer->m_dwAsked = ::GetTickCount();
		m_pImpl->waits[Impl::WaitKey(byVia, nKey)] = Impl::SWait{pLayer, pLayer->m_dwAsked, false};
	}
	pSocket->AttachNatdLayer(pLayer);
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: punch requested %s, %s"), ViaStr(byVia), (LPCTSTR)client.DbgGetClientInfo());
	return true;
}

bool CNatTraversal::ReadMarker(CSafeMemFile &data, uint64 &nNonce)
{
	if (data.GetLength() - data.GetPosition() < natd::kOfferSize)
		return false;
	const ULONGLONG nPos = data.GetPosition();
	BYTE abyOffer[natd::kOfferSize];
	data.Read(abyOffer, sizeof abyOffer);
	const std::optional<natd::Offer> offer(natd::decodeOffer(abyOffer, sizeof abyOffer));
	if (!offer || offer->kind != NATD_MARKER_PUNCH) {
		data.Seek((LONGLONG)nPos, CFile::begin);	// not ours: the rest of the packet is read as before
		return false;
	}
	nNonce = offer->nonce;
	return true;
}

bool CNatTraversal::ReadCallback(CSafeMemFile &data, uint32 dwIP, uint16 nPort, SNatCallback &cb)
{
	if (data.GetLength() - data.GetPosition() < 5)
		return false;
	cb.dwIP = dwIP;
	cb.nPort = nPort;
	cb.nID = data.ReadUInt32();
	const uint8 byCrypt = data.ReadUInt8();
	// no user hash, no token
	if ((byCrypt & NATD_CALLBACK_HASH) == 0 || data.GetLength() - data.GetPosition() < MDX_DIGEST_SIZE)
		return false;
	data.ReadHash16(cb.abyHash);
	return true;
}

// Through our buddy nothing goes back: the requester punches the endpoint our Kad record has,
// and our punch towards it is the answer.
// The requester's endpoint is the one a relay saw a UDP datagram come from, which a forged
// source address can make up, as it can for eMule's own callback: the punch towards it then
// finds no one punching back, and ends within natd's caps (small datagrams, at most maxPackets
// in its 20 s, a few punches at once).
bool CNatTraversal::StartIncoming(const SNatCallback &cb, uint64 nNonce, uint8 byVia)
{
	if (!m_bEnabled)
		return false;
	return OpenSession(cb.dwIP, cb.nPort, natd::tokenFrom(cb.abyHash, 16, nNonce).data(), false, NULL, byVia);
}

// A punch through the source's buddy timed out: a new request with a new nonce, and a new punch
// towards the source's endpoint at once. False when none started (the layer keeps its session).
bool CNatTraversal::RetryThroughBuddy(CNatdSocketLayer *pLayer)
{
	const uint64 nNonce = RandomUInt64();
	if (!m_pImpl->Ask(*pLayer, nNonce, _T("ours, once more: the punch timed out")))
		return false;
	const uint32 nOld = pLayer->m_nSession;
	pLayer->Retry(0, natd::tokenFrom(thePrefs.GetUserHash(), 16, nNonce).data());
	m_pImpl->AskAgain(*pLayer, nNonce);
	if (OpenSession(pLayer->GetIP(), pLayer->GetPort(), pLayer->GetToken(), true, pLayer, NATD_VIA_BUDDY))
		return true;
	pLayer->m_nSession = nOld;
	return false;
}

bool CNatTraversal::Connect(CNatdSocketLayer *pLayer)
{
	// through the server, the punch starts when the target's endpoint arrives
	if (pLayer->m_nWait != 0)
		return m_pImpl->waits.find(Impl::WaitKey(pLayer->GetVia(), pLayer->m_nWait)) != m_pImpl->waits.end();
	return OpenSession(pLayer->GetIP(), pLayer->GetPort(), pLayer->GetToken(), true, pLayer, pLayer->m_byVia);
}

bool CNatTraversal::OpenSession(uint32 dwIP, uint16 nPort, const BYTE *pToken12, bool bConnect, CNatdSocketLayer *pLayer, uint8 byVia, uint32 nServerPeer)
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	// the IP filter, as for anything we would send to or read from that address: a request
	// through a relay carries the endpoint the relay saw, which no filter has checked yet
	if (IsFilteredOrBanned(dwIP))
		return false;
	// through a relay the endpoints are fresh and the peer's NAT unknown (NatTraversal.h)
	const bool bFresh = byVia != NATD_VIA_DIRECT;
	LPCTSTR pszNot = NULL;
	if (bFresh ? !m_pImpl->pAgent->punchable() : !m_pImpl->pAgent->directPunchable())
		pszNot = _T("we cannot be punched to");
	else if (dwIP == 0 || nPort == 0)
		pszNot = _T("no endpoint to punch to");
	if (pszNot != NULL) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: punch %s with %s:%u not started: %s"), ViaStr(byVia), (LPCTSTR)ipstr(dwIP), nPort, pszNot);
		return false;
	}
	const natd::Endpoint remote{ntohl(dwIP), nPort};
	natd::TxId token;
	memcpy(token.data(), pToken12, token.size());
	const natd::TimePoint now = natd::Clock::now();
	// 0 also for a request repeated while the punch it asked for is still on
	const natd::PeerNat nat = bFresh ? natd::PeerNat::Unknown : natd::PeerNat::Stable;
	const natd::SessionId id = bConnect ? m_pImpl->pAgent->connect(remote, nat, token, now) : m_pImpl->pAgent->accept(remote, nat, token, now);
	if (id == 0) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("NAT traversal: punch %s with %s not started: a punch with it is on already, or the session limit is reached"), ViaStr(byVia), (LPCTSTR)EndpointStr(remote));
		return false;
	}
	SSession &s = m_pImpl->sessions[id];
	s.pLayer = pLayer;
	s.remote = remote;
	s.nServerPeer = nServerPeer;
	if (pLayer != NULL)
		pLayer->m_nSession = id;
	if (thePrefs.GetVerbose())
		AddDebugLogLine(false, _T("NAT traversal: punching towards %s (%s, %s, %s)"), (LPCTSTR)EndpointStr(remote), ViaStr(byVia)
			, pLayer != NULL ? _T("we asked") : _T("we were asked"), bConnect ? _T("we start") : _T("we answer"));
	m_pImpl->HandleEvents(now);
	return true;
}

int CNatTraversal::Write(uint32 nSession, const void *pBuf, int nLen)
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	const std::map<natd::SessionId, SSession>::iterator it = m_pImpl->sessions.find(nSession);
	if (it == m_pImpl->sessions.end() || !it->second.pKcp || it->second.bOver || it->second.pLayer == NULL) {
		WSASetLastError(WSAENOTCONN);
		return SOCKET_ERROR;
	}
	// 0: the window is full, an FD_WRITE follows
	const size_t nWritten = it->second.pKcp->write(static_cast<const uint8_t*>(pBuf), (size_t)nLen);
	if (nWritten == 0) {
		it->second.bWantWrite = true;
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}
	return (int)nWritten;
}

int CNatTraversal::Read(uint32 nSession, void *pBuf, int nLen)
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	const std::map<natd::SessionId, SSession>::iterator it = m_pImpl->sessions.find(nSession);
	if (it == m_pImpl->sessions.end() || !it->second.pKcp) {
		WSASetLastError(WSAENOTCONN);
		return SOCKET_ERROR;
	}
	SSession &s = it->second;
	s.bReadPosted = false;
	const size_t nRead = (nLen > 0 && s.pKcp) ? s.pKcp->read(static_cast<uint8_t*>(pBuf), (size_t)nLen) : 0;
	// what the read caused: an FD_READ again if more is there, the end once it is all read
	m_pImpl->Signal(s);
	m_pImpl->RaiseEvents();
	if (nRead == 0) {
		if (s.bOver || s.bPeerFin)
			return 0;
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}
	return (int)nRead;
}

// main thread: the layer goes away. A stream is closed with a FIN once what was written is
// through, at most NATD_PATH_LINGER later; a punch still on is cancelled.
void CNatTraversal::Detach(uint32 nSession)
{
	CSingleLock lock(&m_pImpl->cs, TRUE);
	const std::map<natd::SessionId, SSession>::iterator it = m_pImpl->sessions.find(nSession);
	if (it == m_pImpl->sessions.end())
		return;
	SSession &s = it->second;
	s.pLayer = NULL;
	if (s.pKcp && !s.bOver) {
		s.dwDetached = (std::max)(::GetTickCount(), (DWORD)1);
		return;
	}
	m_pImpl->Erase(nSession);
}

///////////////////////////////////////////////////////////////////////////////
// CNatdSocketLayer

CNatdSocketLayer::CNatdSocketLayer(uint32 dwIP, uint16 nPort, const BYTE *pToken12, uint8 byVia)
	: m_nSession()
	, m_nWait()
	, m_nServerPeer()
	, m_dwAsked()
	, m_nTries(1)
	, m_dwRelayIP()
	, m_nRelayPort()
	, m_abyRelayID()
	, m_abyFile()
	, m_dwIP(dwIP)
	, m_nPort(nPort)
	, m_byVia(byVia)
	, m_abyToken()
{
	if (pToken12 != NULL)
		memcpy(m_abyToken, pToken12, sizeof m_abyToken);
}

CNatdSocketLayer::~CNatdSocketLayer()
{
	Unhook();
}

void CNatdSocketLayer::Unhook()
{
	if (m_nSession != 0 && theApp.nattraversal != NULL)
		theApp.nattraversal->Detach(m_nSession);
	m_nSession = 0;
	if (m_nWait != 0 && theApp.nattraversal != NULL)
		theApp.nattraversal->ForgetLayer(this);
}

void CNatdSocketLayer::Retry(uint64 nWait, const BYTE *pToken12)
{
	m_nSession = 0;
	m_nWait = nWait;
	if (pToken12 != NULL)
		memcpy(m_abyToken, pToken12, sizeof m_abyToken);
	++m_nTries;
}

// incoming connection: the socket starts as an accepted one, and the first event makes it connected
void CNatdSocketLayer::Accepted(uint32 nSession)
{
	m_nSession = nSession;
	SetLayerState(connected);
	SetOwnerSocketState(attached);
	TriggerEvent(FD_WRITE, 0, TRUE);
}

void CNatdSocketLayer::RaiseEvent(long lEvent, int nErrorCode)
{
	if (lEvent == FD_CONNECT) {
		if (nErrorCode == 0)
			SetLayerState(connected);
		TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
		if (nErrorCode == 0)
			TriggerEvent(FD_WRITE, 0, TRUE);
	} else
		TriggerEvent(lEvent, nErrorCode, TRUE);
}

void CNatdSocketLayer::OnAccept(int)
{
}

void CNatdSocketLayer::OnClose(int)
{
}

void CNatdSocketLayer::OnConnect(int)
{
}

void CNatdSocketLayer::OnReceive(int)
{
}

void CNatdSocketLayer::OnSend(int)
{
}

void CNatdSocketLayer::Close()
{
	Unhook();
	CloseNext();
}

// The address is the one of the TCP port; the punch goes to the UDP endpoint this layer was made for
BOOL CNatdSocketLayer::Connect(const LPSOCKADDR, int)
{
	if (theApp.nattraversal == NULL || !theApp.nattraversal->Connect(this)) {
		WSASetLastError(WSAECONNREFUSED);
		return FALSE;
	}
	SetLayerState(connecting);
	WSASetLastError(WSAEWOULDBLOCK);
	return FALSE;
}

bool CNatdSocketLayer::Connect(const CString&, UINT)
{
	return Connect(NULL, 0) != FALSE;
}

BOOL CNatdSocketLayer::GetPeerName(CString &rPeerAddress, UINT &rPeerPort)
{
	rPeerAddress = ipstr(m_dwIP);
	rPeerPort = m_nPort;
	return TRUE;
}

BOOL CNatdSocketLayer::GetPeerName(LPSOCKADDR lpPeerAddr, int *lpPeerAddrLen)
{
	if (lpPeerAddr == NULL || lpPeerAddrLen == NULL || *lpPeerAddrLen < (int)sizeof(sockaddr_in)) {
		WSASetLastError(WSAEFAULT);
		return FALSE;
	}
	*reinterpret_cast<sockaddr_in*>(lpPeerAddr) = SockAddr(m_dwIP, m_nPort);
	*lpPeerAddrLen = (int)sizeof(sockaddr_in);
	return TRUE;
}

int CNatdSocketLayer::Receive(void *lpBuf, int nBufLen, int)
{
	if (m_nSession == 0 || theApp.nattraversal == NULL) {
		WSASetLastError(WSAENOTCONN);
		return SOCKET_ERROR;
	}
	return theApp.nattraversal->Read(m_nSession, lpBuf, nBufLen);
}

int CNatdSocketLayer::Send(const void *lpBuf, int nBufLen, int)
{
	const uint32 nSession = m_nSession;
	if (nSession == 0 || theApp.nattraversal == NULL) {
		WSASetLastError(WSAENOTCONN);
		return SOCKET_ERROR;
	}
	return theApp.nattraversal->Write(nSession, lpBuf, nBufLen);
}

BOOL CNatdSocketLayer::ShutDown(int)
{
	return TRUE;
}
