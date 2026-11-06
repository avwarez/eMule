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
#include <atomic>
#include "UPnPImpl.h"
#include "libplum\include\plum\plum.h"

// Port mapping through libplum, which tries PCP, then NAT-PMP, then UPnP-IGD by itself.
// Its own thread keeps the mappings alive once made - renewing the leases, checking them with
// the gateway every 5 minutes, and making again those a gateway restart or an address change
// lost - until DeletePorts() destroys them. CheckAndRefresh() has them checked at once.
// The result of a discovery is in when every port has either been mapped or has failed.
class CUPnPImplLibPlum : public CUPnPImpl
{
public:
	CUPnPImplLibPlum();
	virtual	~CUPnPImplLibPlum();

	virtual void StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort);
	virtual bool CheckAndRefresh();
	virtual void StopAsyncFind();
	virtual void DeletePorts();
	virtual bool IsReady();
	virtual int GetImplementationID()				{ return UPNP_IMPL_LIBPLUM; }

private:
	enum EMapping
	{
		MAP_TCP,
		MAP_UDP,
		MAP_WEB,
		MAP_COUNT
	};
	enum EMapState
	{
		MAPSTATE_NONE,		// no port to map
		MAPSTATE_PENDING,
		MAPSTATE_OK,
		MAPSTATE_FAILED
	};
	struct SMapping
	{
		int nId;			// libplum's id, -1 when libplum no longer has the mapping
		uint16 nPort;
		EMapState eState;
	};

	static void MappingCallback(int nId, plum_state_t eState, const plum_mapping_t *pMapping) noexcept;
	static void LogCallback(plum_log_level_t eLevel, const char *pszMessage) noexcept;
	void OnMapping(int nId, plum_state_t eState, const plum_mapping_t &mapping);
	void OnMappingLost(int nId);
	bool Init();
	void SetMapping(EMapping eMapping, uint16 nPort);
	void CreateMapping(EMapping eMapping);
	void CreateMappings();
	void DestroyMappings();
	void UpdateResult();

	CCriticalSection m_csMappings;	// never held while calling into libplum: its thread calls back holding its own lock
	SMapping m_aMappings[MAP_COUNT];
	std::atomic<bool> m_bDiscovering;
	std::atomic<bool> m_bRestart;	// libplum's thread has stopped, or may have: Init() starts it again
	bool m_bInitialized;
};
