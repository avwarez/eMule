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

// UDP hole punching between two LowIDs, with natd (the natd submodule): NAT discovery on the
// client UDP port (the one Kad uses), with public STUN servers only - no server of our own:
// natd's list, or the user's in stun.dat (config directory).
//
// The client is "punchable" when its NAT maps that port endpoint-independently (natd
// Predictability::Stable): the endpoint a third party sees is then the one every peer sees,
// so two punchable LowIDs can reach each other through the endpoints their buddies saw.
//
// The natd headers stay inside NatTraversal.cpp. Every method is called on the main thread.
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

	// The discovery found an endpoint-independent mapping of the client UDP port.
	bool	IsPunchable() const;

private:
	struct Impl;
	std::unique_ptr<Impl> m_pImpl;
};
