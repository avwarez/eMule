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
#pragma once
#include <memory>
#include "AsyncSocketExLayer.h"

// UDP hole punching between two LowIDs, with natd (the natd submodule): NAT discovery on the
// client UDP port (the one Kad uses), with public STUN servers only - no server of our own:
// natd's list, or the user's in stun.dat (config directory).
//
// The client is "punchable" when its NAT maps that port endpoint-independently (natd
// Predictability::Stable): the endpoint a third party sees is then the one every peer sees,
// so two punchable LowIDs can reach each other through the endpoints their buddies saw.
// Through the server a NAT that maps it to random ports inside a block of ports
// (Predictability::Bounded, mobile CGNs, 89nh) or to sequential ports (Predictable, 89nj) can
// be punched to as well: nothing tells either side the other's NAT there, so an
// endpoint-independent side punches the endpoint the server saw and, should nobody answer
// there, the block of ports around it and the ports just past it (natd::PeerNat::Unknown); the
// other side punches the endpoint from the client UDP port.
//
// A punch is used only where TCP cannot work: a LowID downloader and a LowID source that
// carries TAG_NATDCLIENT. The downloader asks the source through the source's buddy
// (OP_REASKCALLBACKUDP, which the buddy forwards as OP_REASKCALLBACKTCP with the endpoint it
// saw the request come from) or directly (OP_DIRECTCALLBACKREQ), with the natd marker at the
// end of the packet: both punch at once. natd hands over the punched path (the socket, the
// peer's endpoint, how often to send to keep it open), and the eD2K stream then runs over it
// in eMule's own datagrams (KCP) on the client UDP port, under a CClientReqSocket that knows
// nothing of it.
//
// The request is the same on every channel, the one the eD2K servers forward between two
// LowIDs (Lugdunum's NAT callback, SNatCallback): the requester's endpoint as the relay saw
// it, its ID on the server (0 off a server), its crypt settings and its user hash. The
// session token comes from that user hash and the nonce of the request.
//
// Through the server (89ng) - two LowIDs logged in to the same server that coordinates
// punches (Lugdunum's NAT callback, SRVCAP_NATTRAVERSAL; the Rust ed2k-server takes it too),
// whether or not they are in Kad: the requester sends OP_NAT_CALLBACK_REQUEST from the client
// UDP port, obfuscated with the server's UDP key; the server forwards it with the endpoint it
// saw (OP_NAT_CALLBACK_TCP/UDP). The source sends its own request back, which brings its
// endpoint to the requester the same way. No marker fits there, so both sides derive the
// session from what both know: the lower of the two IDs starts the punch, and the token comes
// from its user hash and the two IDs. Two LowIDs asking each other at once then still meet in
// one punch. Which side starts the punch does not say which side has the eD2K socket: the one
// that asked.
//
// The natd headers stay inside NatTraversal.cpp. Every method is called on the main thread,
// but Write(), which the upload throttler calls too.

class CClientReqSocket;
class CNatdSocketLayer;
class CSafeMemFile;
class CUpDownClient;

// The natd marker, at the end of a callback request: "NATD", version, type, nonce.
#define NATD_MARKER_PUNCH		1

// The channels a punch request goes through
#define NATD_VIA_NONE			0
#define NATD_VIA_BUDDY			1	// OP_REASKCALLBACKUDP to the source's buddy
#define NATD_VIA_DIRECT			2	// OP_DIRECTCALLBACKREQ to a source with an open UDP port
#define NATD_VIA_SERVER			3	// through the server both are logged in to (89ng)

// The punch request: <ID 4><crypt 1>[<user hash 16> if crypt & NATD_CALLBACK_HASH] after the
// endpoint the relay adds, as Lugdunum forwards it (OP_NAT_CALLBACK_*). crypt is the requester's
// crypt layer support, request and require in bits 0-2, as GetMyConnectOptions puts them; the
// punch needs only the user hash (the stream's crypt layer negotiates as over TCP).
#define NATD_CALLBACK_HASH		0x80
struct SNatCallback
{
	uint32	dwIP;			// network order
	uint16	nPort;			// the requester's UDP port
	uint32	nID;			// the requester's ID on the server, 0 for a request that came through no server
	uchar	abyHash[16];	// the requester's user hash
};

class CNatTraversal
{
public:
	CNatTraversal();
	~CNatTraversal();
	CNatTraversal(const CNatTraversal&) = delete;
	CNatTraversal& operator=(const CNatTraversal&) = delete;

	// A datagram received on the client UDP socket, before the IP filter and before eMule
	// decrypts or parses it: true when it was NAT traversal's (and is then done with). natd
	// takes its own only from the endpoints it addressed, the STUN servers among them, which
	// the IP filter often lists (hosting ranges). dwIP in network order.
	bool	OnDatagram(const BYTE *pData, int nLen, uint32 dwIP, uint16 nPort);
	// every 100 ms, from the upload timer
	void	Process();
	// eMule closes, before the client UDP socket goes: every punched stream still open ends with
	// its FINs at once, as a TCP connection gets its FIN, so that the peer does not wait for the
	// path to go silent (89ni)
	void	Shutdown();

	// The discovery found an endpoint-independent mapping of the client UDP port (the Kad
	// channels; the server takes a Bounded or Predictable one too, 89nh, 89nj).
	bool	IsPunchable() const;
	// The public endpoint as one number while punchable, 0 otherwise: a source record carries
	// it (the IP and UDP port the index node sees), so a change means publishing again.
	uint64	GetPunchEndpoint() const;
	// The TCP connection to the buddy broke: a new public address breaks it at once. The
	// endpoint is checked; if it changed, the punched streams end as TCP connections do.
	void	OnBuddyLost();

	// Downloader side. True when TCP cannot reach the client (LowID->LowID) but a punch can.
	bool	CanPunchTo(const CUpDownClient &client) const	{ return PunchVia(client) != NATD_VIA_NONE; }
	// The channel the punch request goes through (NATD_VIA_*).
	uint8	PunchVia(const CUpDownClient &client) const;
	// Sends the punch request through byVia (PunchVia) and gives the socket the layer that
	// punches when the socket connects; false when nothing was sent (the socket is then left as it was).
	bool	AttachOutgoing(CClientReqSocket *pSocket, CUpDownClient &client, uint8 byVia);

	// Source side: the marker at the current position of a callback request, if there is one.
	static bool ReadMarker(CSafeMemFile &data, uint64 &nNonce);
	// The request after the endpoint, at the current position; false without the user hash.
	// dwIP (network order) and nPort: the requester's endpoint, as the relay saw it.
	static bool ReadCallback(CSafeMemFile &data, uint32 dwIP, uint16 nPort, SNatCallback &cb);
	// A request arrived through byVia: punch towards the requester's endpoint, with the token
	// from its user hash and the nonce. False when the punch was not started.
	bool	StartIncoming(const SNatCallback &cb, uint64 nNonce, uint8 byVia);

	// 89ng, the server. A LowID on our server can be punched to through it: the server
	// coordinates punches for us, and the ID is odd (the client announced the NAT callback).
	bool	ServerCanPunch(uint32 nID, uint32 dwServerIP, uint16 nServerPort) const;
	// Whether the login announces the NAT callback (SRVCAP_NATTRAVERSAL): not once the discovery
	// found that we cannot be punched to, so that no LowID asks us through the server in vain.
	// Before the discovery, yes: it starts only when the server has given us a LowID.
	bool	AnnounceServerPunch() const;
	// OP_NAT_CALLBACK_TCP from the server we are logged in to (bUdp: OP_NAT_CALLBACK_UDP).
	void	OnServerCallback(const BYTE *pData, uint32 nSize, bool bUdp = false);
	// A datagram from the server on the client UDP socket (the answer to the status request
	// that gives its UDP key, OP_NAT_CALLBACK_UDP): true when it was one, and is done with.
	bool	OnServerDatagram(BYTE *pData, int nLen, const SOCKADDR_IN &from);
	// A layer waiting for the target's endpoint is gone
	void	ForgetLayer(CNatdSocketLayer *pLayer);

	// CNatdSocketLayer; Write() also from the upload throttler thread
	bool	Connect(CNatdSocketLayer *pLayer);
	int		Write(uint32 nSession, const void *pBuf, int nLen);
	int		Read(uint32 nSession, void *pBuf, int nLen);
	void	Detach(uint32 nSession);

private:
	// A punch session towards dwIP:nPort (network order IP): natd connects when bConnect, else
	// accepts. pLayer: the socket's, NULL for a socket made when the stream opens.
	bool	OpenSession(uint32 dwIP, uint16 nPort, const BYTE *pToken12, bool bConnect, CNatdSocketLayer *pLayer, uint8 byVia);
	void	ServerTimer();
	void	OnServerPeer(const SNatCallback &cb);
	// our request to that target, waiting for its endpoint, is over (nError 0: no event)
	void	DropWait(uint32 nTargetID, int nError);

	struct Impl;
	std::unique_ptr<Impl> m_pImpl;
};

// Under a CClientReqSocket whose eD2K stream goes over a punched UDP path. The socket handle
// under it is never connected and sees no traffic; the layer is the connection.
class CNatdSocketLayer : public CAsyncSocketExLayer
{
	friend class CNatTraversal;
public:
	// pToken12 NULL: not known yet (through the server, it comes with the peer)
	CNatdSocketLayer(uint32 dwIP, uint16 nPort, const BYTE *pToken12, uint8 byVia);
	virtual	~CNatdSocketLayer();

	// incoming: the punch is done, the socket starts as an accepted one
	void	Accepted(uint32 nSession);
	void	RaiseEvent(long lEvent, int nErrorCode);
	void	Orphan()								{ m_nSession = 0; }
	uint32	GetIP() const							{ return m_dwIP; }
	uint16	GetPort() const							{ return m_nPort; }
	const BYTE* GetToken() const					{ return m_abyToken; }

protected:
	// Events of the socket handle under this layer: there is no connection on it, so there
	// are none to pass on. The events of the stream skip the layer (RaiseEvent).
	virtual void OnAccept(int nErrorCode);
	virtual void OnClose(int nErrorCode);
	virtual void OnConnect(int nErrorCode);
	virtual void OnReceive(int nErrorCode);
	virtual void OnSend(int nErrorCode);

	virtual void Close();
	virtual BOOL Connect(const LPSOCKADDR lpSockAddr, int nSockAddrLen);
	virtual bool Connect(const CString &sHostAddress, UINT nHostPort);
	virtual BOOL GetPeerName(CString &rPeerAddress, UINT &rPeerPort);
	virtual BOOL GetPeerName(LPSOCKADDR lpPeerAddr, int *lpPeerAddrLen);
	virtual int Receive(void *lpBuf, int nBufLen, int nFlags = 0);
	virtual int Send(const void *lpBuf, int nBufLen, int nFlags = 0);
	virtual BOOL ShutDown(int nHow = CAsyncSocket::sends);

private:
	void	Unhook();		// the session goes, and the wait for the server's answer (89ng)

	uint32	m_nSession;		// 0: none (not connected yet, or gone)
	uint32	m_nServerTarget;	// 89ng: the ID of the target whose endpoint the server is to bring, 0 when known
	uint32	m_dwIP;			// network order
	uint16	m_nPort;		// host order, the UDP port of the peer
	uint8	m_byVia;		// NATD_VIA_*, the channel of the request
	BYTE	m_abyToken[12];
};
