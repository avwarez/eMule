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
// A punch is used only where TCP cannot work: between a LowID downloader and a LowID source.
// The requester sends its request from the client UDP port to a relay, which forwards it to the
// source with the endpoint it saw it come from; the source punches that endpoint. The requester
// learns the source's endpoint:
// - through the eD2K server: the source sends its own request back the same way, and the
//   requester punches the endpoint the server saw;
// - through the source's Kad buddy, which is any eMule and does nothing it does not do for a
//   reask: from the source's Kad record, whose IP and UDP port the index node saw the source
//   publish from (it adds them, CKademliaUDPListener::Process_KADEMLIA2_PUBLISH_SOURCE_REQ).
//   The requester punches it as soon as its request is out, and needs no buddy of its own.
// A request through a relay goes once more after a while (UDP), and a punch that times out is
// asked for once more within eMule's connection timeout, as TCP sends its SYN again.
// The endpoint a relay saw is fresh, so a NAT that maps endpoint-independently (natd Stable), to
// random ports in a block (Bounded, mobile CGNs) or to sequential ports (Predictable) can be
// punched to: nothing tells either side the other's NAT, so natd punches that endpoint and then
// the ports nearest to it, more each round, whatever the size of the block (PeerNat::Unknown).
// The endpoint of a Kad record is as old as the record, but kept by the source's Kad traffic:
// it is the one towards the requester too when the source's NAT maps endpoint-independently.
//
// The request is the one the eD2K servers forward between two LowIDs (Lugdunum's NAT callback,
// SNatCallback): the requester's endpoint as the relay saw it, its ID on the server (0 off a
// server), its crypt settings and its user hash.
// - Through the server (SRVCAP_NATTRAVERSAL; the Rust ed2k-server takes it too), whether or not
//   the two are in Kad: OP_NAT_CALLBACK_REQUEST, obfuscated with the server's UDP key, which the
//   server forwards as OP_NAT_CALLBACK_TCP/UDP. No marker fits there, so both sides derive the
//   session from what both know: the lower of the two IDs starts the punch, and the token comes
//   from its user hash and the two IDs. Two LowIDs asking each other at once then still meet in
//   one punch.
// - Through the source's buddy: OP_REASKCALLBACKUDP, which it forwards as OP_REASKCALLBACKTCP,
//   with the natd marker (the nonce) after the fields it reads. The token comes from the
//   requester's user hash and the nonce.
// - A source with an open UDP port is its own relay (OP_DIRECTCALLBACKREQ, with the marker): we
//   punch the endpoint it published, which needs our NAT to map endpoint-independently.
// Which side starts the punch does not say which side has the eD2K socket: the one that asked.
// natd hands over the punched path (the socket, the peer's endpoint, how often to send to keep it
// open), and the eD2K stream then runs over it in eMule's own datagrams (KCP) on the client UDP
// port, under a CClientReqSocket that knows nothing of it.
//
// The discovery runs before the connection to the server and to Kad, after UPnP, whatever the
// ID the client will get: the login then announces what it found, and its mappings do not mix
// with those of the connection.
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
#define NATD_VIA_SERVER			3	// through the server both are logged in to

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

	// The preference, as it was at startup: off, there is no discovery and no punch, nothing
	// is announced or published, and eMule is the plain eMule (a user with forwarded ports).
	bool	IsEnabled() const	{ return m_bEnabled; }
	// A datagram received on the client UDP socket, before the IP filter and before eMule
	// decrypts or parses it: true when it was NAT traversal's (and is then done with). natd
	// takes its own only from the endpoints it addressed, the STUN servers among them, which
	// the IP filter often lists (hosting ranges). dwIP in network order.
	bool	OnDatagram(const BYTE *pData, int nLen, uint32 dwIP, uint16 nPort);
	// every 100 ms, from the upload timer
	void	Process();
	// At startup, after UPnP: true while the connection should wait for the NAT discovery, which
	// this starts; at most NATD_CONNECT_WAIT, then CemuleDlg::EndStartupNetCheck is called.
	bool	DelayConnection();
	// eMule closes, before the client UDP socket goes: the FINs of every punched stream, at once
	void	Shutdown();

	// The discovery found a mapping of the client UDP port that can be punched to through a
	// relay: endpoint-independent, or random in a block of ports, or sequential.
	bool	IsPunchable() const;
	// Endpoint-independent: a source with an open UDP port can be punched to as well.
	bool	IsDirectPunchable() const;
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

	// The marker at the current position of a callback request, if there is one; else the
	// position stays.
	static bool ReadMarker(CSafeMemFile &data, uint64 &nNonce);
	// The request after the endpoint, at the current position; false without the user hash.
	// dwIP (network order) and nPort: the requester's endpoint, as the relay saw it.
	static bool ReadCallback(CSafeMemFile &data, uint32 dwIP, uint16 nPort, SNatCallback &cb);
	// Source side. A request arrived through byVia: punch towards the requester's endpoint, with
	// the token from its user hash and the nonce. False when the punch was not started.
	bool	StartIncoming(const SNatCallback &cb, uint64 nNonce, uint8 byVia);

	// The server. A LowID on our server can be punched to through it: the server
	// coordinates punches for us, and the ID is odd (the client announced the NAT callback).
	bool	ServerCanPunch(uint32 nID, uint32 dwServerIP, uint16 nServerPort) const;
	// Whether the login announces the NAT callback (SRVCAP_NATTRAVERSAL): not once the discovery
	// found that we cannot be punched to, so that no LowID asks us through the server in vain.
	// Without a result yet (a connection that did not wait for it), yes.
	bool	AnnounceServerPunch() const;
	// OP_NAT_CALLBACK_TCP from the server we are logged in to (bUdp: OP_NAT_CALLBACK_UDP).
	void	OnServerCallback(const BYTE *pData, uint32 nSize, bool bUdp = false);
	// A datagram from the server on the client UDP socket (the answer to the status request
	// that gives its UDP key, OP_NAT_CALLBACK_UDP): true when it was one, and is done with.
	bool	OnServerDatagram(BYTE *pData, int nLen, const SOCKADDR_IN &from);
	// A layer waiting for the target's endpoint through the server is gone
	void	ForgetLayer(CNatdSocketLayer *pLayer);

	// CNatdSocketLayer; Write() also from the upload throttler thread
	bool	Connect(CNatdSocketLayer *pLayer);
	int		Write(uint32 nSession, const void *pBuf, int nLen);
	int		Read(uint32 nSession, void *pBuf, int nLen);
	void	Detach(uint32 nSession);

private:
	// A punch session towards dwIP:nPort (network order IP): natd connects when bConnect, else
	// accepts. pLayer: the socket's, NULL for a socket made when the stream opens.
	// nServerPeer: through the server, the peer's ID there.
	bool	OpenSession(uint32 dwIP, uint16 nPort, const BYTE *pToken12, bool bConnect, CNatdSocketLayer *pLayer, uint8 byVia, uint32 nServerPeer = 0);
	void	ServerTimer();
	void	OnServerPeer(const SNatCallback &cb);
	// Our requests through the server, waiting for the peer's request back: byVia and nKey (the
	// target's ID on the server) name one. The timer sends them once more and times them out,
	// and sends once more the requests that wait for nothing (through the buddy, the requests
	// back); a wait is over (nError 0: no event); the peer's request back arrived (pToken12
	// NULL: the socket's), false when nothing waited for it.
	void	RelayTimer();
	bool	RetryThroughBuddy(CNatdSocketLayer *pLayer);
	void	DropWait(uint8 byVia, uint64 nKey, int nError);
	bool	Answered(uint8 byVia, uint64 nKey, const SNatCallback &cb, const BYTE *pToken12, bool bConnect);

	struct Impl;
	std::unique_ptr<Impl> m_pImpl;
	const bool m_bEnabled;
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
	uint8	GetVia() const							{ return m_byVia; }
	bool	IsConnecting() const					{ return GetLayerState() == connecting; }
	// Through a relay: the target's ID on the server, the source's buddy and the file, when the
	// first request went, the punches asked for
	uint32	GetServerPeer() const					{ return m_nServerPeer; }
	const uchar* GetRelayID() const					{ return m_abyRelayID; }
	uint32	GetRelayIP() const						{ return m_dwRelayIP; }
	uint16	GetRelayPort() const					{ return m_nRelayPort; }
	const uchar* GetFile() const					{ return m_abyFile; }
	DWORD	GetAskedAt() const						{ return m_dwAsked; }
	uint8	GetTries() const						{ return m_nTries; }
	// the punch timed out and a new request went: through the server waiting for the target's
	// endpoint again, by the request's key (nWait); through the buddy with the new token
	// (pToken12 NULL: the same)
	void	Retry(uint64 nWait, const BYTE *pToken12);

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
	void	Unhook();		// the session goes, and the wait for the relay's answer

	uint32	m_nSession;		// 0: none (not connected yet, or gone)
	uint64	m_nWait;		// the key of our request waiting for the target's endpoint, 0 when none
	uint32	m_nServerPeer;	// through the server: the target's ID there
	DWORD	m_dwAsked;		// when the first request to it went
	uint8	m_nTries;		// punches asked for, the first included
	uint32	m_dwRelayIP;	// through the buddy: the source's buddy, network order
	uint16	m_nRelayPort;
	uchar	m_abyRelayID[16];
	uchar	m_abyFile[16];
	uint32	m_dwIP;			// network order
	uint16	m_nPort;		// host order, the UDP port of the peer
	uint8	m_byVia;		// NATD_VIA_*, the channel of the request
	BYTE	m_abyToken[12];
};
