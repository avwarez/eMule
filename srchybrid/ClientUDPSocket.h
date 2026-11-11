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
#include "UploadBandwidthThrottler.h" // ZZ:UploadBandWithThrottler (UDP)
#include "EncryptedDatagramSocket.h"

class Packet;

#pragma pack(push, 1)
struct UDPPack
{
	Packet	*packet;
	uint32	dwIP;
	uint16	nPort;
	DWORD	dwTime;
	bool	bEncrypt;
	bool	bKad;
	uint32	nReceiverVerifyKey;
	uchar	pachTargetClientHashORKadID[16];
	//uint16 nPriority; We could add a priority system here to force some packets.
};
#pragma pack(pop)

class CClientUDPSocket : public CAsyncSocket, public CEncryptedDatagramSocket, public ThrottledControlSocket // ZZ:UploadBandWithThrottler (UDP)
{
public:
	CClientUDPSocket();
	virtual	~CClientUDPSocket();

	bool	Create();
	bool	Rebind();
	uint16	GetConnectedPort() const	{ return m_port; }
	bool	SendPacket(Packet *packet, uint32 dwIP, uint16 nPort, bool bEncrypt, const uchar *pachTargetClientHashORKadID, bool bKad, uint32 nReceiverVerifyKey);
	SocketSentBytes  SendControlData(uint32 maxNumberOfBytesToSend, uint32 /*minFragSize*/); // ZZ:UploadBandWithThrottler (UDP)
	// the eD2K server's UDP obfuscation, for the punch requests (89ng), which leave from this
	// socket so that the server sees the endpoint to punch to
	static int		ServerOverheadSize()	{ return EncryptOverheadSize(false); }
	static uint32	EncryptForServer(uchar *pbyBuf, uint32 nBufLen, uint32 dwBaseKey)	{ return EncryptSendServer(pbyBuf, nBufLen, dwBaseKey); }
	static int		DecryptFromServer(BYTE *pbyBufIn, int nBufLen, BYTE **ppbyBufOut, uint32 dwBaseKey, const SOCKADDR_IN &dbgIP)	{ return DecryptReceivedServer(pbyBufIn, nBufLen, ppbyBufOut, dwBaseKey, dbgIP); }

protected:
	bool	ProcessPacket(const BYTE *packet, UINT size, uint8 opcode, uint32 ip, uint16 port);

	virtual void	OnSend(int nErrorCode);
	virtual void	OnReceive(int nErrorCode);

private:
	int		SendTo(uchar *lpBuf, int nBufLen, uint32 dwIP, uint16 nPort);
	bool	IsBusy() const				{ return m_bWouldBlock; }

	CTypedPtrList<CPtrList, UDPPack*> controlpacket_queue;

	CCriticalSection sendLocker; // ZZ:UploadBandWithThrottler (UDP)

	uint16	m_port;
	bool	m_bWouldBlock;
};