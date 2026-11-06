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
#include "UPnPImplLibPlum.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static LPCTSTR const sTCP = _T("TCP");
static LPCTSTR const sUDP = _T("UDP");

// libplum spends up to the first on each protocol it tries (PCP and NAT-PMP, then UPnP-IGD)
// and up to the second on each port, so a discovery stays well within the 40 seconds eMule
// waits for it. The second also bounds how long a shutdown waits for the ports to be removed.
static const int PLUM_DISCOVER_TIMEOUT = 5000;	// ms
static const int PLUM_MAPPING_TIMEOUT = 5000;	// ms

static LPCTSTR MappingProtocolName(plum_mapping_protocol_t eProtocol)
{
	switch (eProtocol) {
	case PLUM_MAPPING_PROTOCOL_PCP:
		return _T("PCP");
	case PLUM_MAPPING_PROTOCOL_NATPMP:
		return _T("NAT-PMP");
	case PLUM_MAPPING_PROTOCOL_UPNP:
		return _T("UPnP-IGD");
	case PLUM_MAPPING_PROTOCOL_DIRECT:
		return _T("no mapping, the local address is public");
	case PLUM_MAPPING_PROTOCOL_UNKNOWN:
	default:
		return _T("unknown protocol");
	}
}

CUPnPImplLibPlum::CUPnPImplLibPlum()
	: m_aMappings()
	, m_bDiscovering()
	, m_bRestart()
	, m_bInitialized()
{
	for (int i = 0; i < MAP_COUNT; ++i)
		m_aMappings[i].nId = -1;
}

CUPnPImplLibPlum::~CUPnPImplLibPlum()
{
	// Stops libplum's thread. It first removes the mappings DeletePorts() destroyed; the ones
	// still alive are only forgotten, and the gateway drops them when their lease runs out.
	// What the thread reports while it stops is of no interest any more.
	{
		CSingleLock lock(&m_csMappings, TRUE);
		for (int i = 0; i < MAP_COUNT; ++i)
			SetMapping(static_cast<EMapping>(i), 0);
		SetMessageOnResult(NULL, 0);
	}
	if (m_bInitialized)
		plum_cleanup();
}

bool CUPnPImplLibPlum::Init()
{
	if (m_bInitialized && m_bRestart) {
		// libplum never starts its thread again by itself. Should it be running after all,
		// this waits for it to remove the mappings destroyed meanwhile.
		DebugLog(_T("libplum: restarting"));
		plum_cleanup();
		m_bInitialized = false;
	}
	if (!m_bInitialized) {
		plum_config_t config = {};
		config.log_level = PLUM_LOG_LEVEL_INFO;
		config.log_callback = LogCallback;
		config.discover_timeout = PLUM_DISCOVER_TIMEOUT;
		config.mapping_timeout = PLUM_MAPPING_TIMEOUT;
		int nResult = plum_init(&config);
		if (nResult != PLUM_ERR_SUCCESS) {
			DebugLogError(_T("libplum: initialisation failed (%d)"), nResult);
			return false;
		}
		m_bInitialized = true;
		m_bRestart = false;
	}
	return true;
}

bool CUPnPImplLibPlum::IsReady()
{
	return !m_bDiscovering;
}

void CUPnPImplLibPlum::StopAsyncFind()
{
	// Nothing to abort: what libplum has mapped stays, until DeletePorts() or the destructor.
	// A discovery given up on must not report later, though. It may have been made on a libplum
	// thread already stopped while there was no mapping to tell it by: the next one restarts it.
	CSingleLock lock(&m_csMappings, TRUE);
	if (m_bDiscovering)
		m_bRestart = true;
	m_bDiscovering = false;
	SetMessageOnResult(NULL, 0);
}

void CUPnPImplLibPlum::DeletePorts()
{
	DestroyMappings();
	CSingleLock lock(&m_csMappings, TRUE);
	m_nUDPPort = 0;
	m_nTCPPort = 0;
	m_nTCPWebPort = 0;
	m_nOldUDPPort = 0;
	m_nOldTCPPort = 0;
	m_nOldTCPWebPort = 0;
	m_bUPnPPortsForwarded = TRIS_FALSE;
	m_bDiscovering = false;
}

void CUPnPImplLibPlum::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort)
{
	DebugLog(_T("Using libplum based implementation (PCP, NAT-PMP, UPnP-IGD)"));
	DebugLog(_T("libplum (c) 2021-2026 Paul-Louis Ageneau - https://github.com/paullouisageneau/libplum"));
	// the old ports, if any, are removed before the new ones are mapped
	DestroyMappings();
	m_bCheckAndRefresh = false;
	if (!Init()) {
		m_bUPnPPortsForwarded = TRIS_FALSE;
		SendResultMessage();
		return;
	}
	{
		CSingleLock lock(&m_csMappings, TRUE);
		m_nUDPPort = nUDPPort;
		m_nTCPPort = nTCPPort;
		m_nTCPWebPort = nTCPWebPort;
		m_nOldUDPPort = 0;
		m_nOldTCPPort = 0;
		m_nOldTCPWebPort = 0;
		m_bUPnPPortsForwarded = TRIS_UNKNOWN;
		m_bDiscovering = true;
	}
	CreateMappings();
	CSingleLock lock(&m_csMappings, TRUE);
	UpdateResult();
}

bool CUPnPImplLibPlum::CheckAndRefresh()
{
	if (m_bDiscovering || m_nTCPPort == 0) {
		DebugLog(_T("Not refreshing libplum ports because no discovery was started, or one is still running"));
		return false;
	}

	DebugLog(_T("Checking and refreshing libplum ports"));
	bool bInit = true;
	if (m_bRestart) {
		// libplum's thread has stopped, and took the mappings with it: they are made anew
		DestroyMappings();
		bInit = Init();
		if (bInit)
			CreateMappings();
	} else {
		// the Web Interface port may have been switched on, off or moved (LateEnableWebServerPort)
		int nOldWebId = -1;
		bool bNewWeb = false;
		int aIds[MAP_COUNT];
		int nCount = 0;
		{
			CSingleLock lock(&m_csMappings, TRUE);
			if (m_aMappings[MAP_WEB].nPort != m_nTCPWebPort) {
				nOldWebId = m_aMappings[MAP_WEB].nId;
				SetMapping(MAP_WEB, m_nTCPWebPort);
				bNewWeb = (m_nTCPWebPort != 0);
			}
			for (int i = 0; i < MAP_COUNT; ++i)
				if (m_aMappings[i].nId >= 0)
					aIds[nCount++] = m_aMappings[i].nId;
		}
		if (nOldWebId >= 0)
			plum_destroy_mapping(nOldWebId);
		if (bNewWeb)
			CreateMapping(MAP_WEB);

		// libplum checks the mappings with the gateway every 5 minutes; this checks them now, and
		// makes again those a restarted gateway lost, without removing any that is still in place
		for (int i = 0; i < nCount; ++i)
			plum_refresh_mapping(aIds[i]);
	}

	// The answer is what libplum found last, and comes at once: eMule gives a refresh 10 seconds,
	// then takes it for a failed discovery and deletes the ports. What libplum finds now goes to the log.
	CSingleLock lock(&m_csMappings, TRUE);
	if (!bInit)
		m_bUPnPPortsForwarded = TRIS_FALSE;
	m_bCheckAndRefresh = true;
	SendResultMessage();
	return true;
}

void CUPnPImplLibPlum::SetMapping(EMapping eMapping, uint16 nPort)
{
	// m_csMappings must be held
	SMapping &mapping = m_aMappings[eMapping];
	mapping.nId = -1;
	mapping.nPort = nPort;
	mapping.eState = (nPort != 0) ? MAPSTATE_PENDING : MAPSTATE_NONE;
}

void CUPnPImplLibPlum::CreateMapping(EMapping eMapping)
{
	plum_mapping_t mapping = {};
	{
		CSingleLock lock(&m_csMappings, TRUE);
		if (m_aMappings[eMapping].eState != MAPSTATE_PENDING)
			return;
		mapping.internal_port = m_aMappings[eMapping].nPort;
	}
	mapping.protocol = (eMapping == MAP_UDP) ? PLUM_IP_PROTOCOL_UDP : PLUM_IP_PROTOCOL_TCP;
	mapping.external_port = mapping.internal_port;	// eMule announces its own ports: the public ones must be the same
	mapping.user_ptr = this;
	const int nId = plum_create_mapping(&mapping, MappingCallback);
	{
		CSingleLock lock(&m_csMappings, TRUE);
		SMapping &slot = m_aMappings[eMapping];
		if (nId < 0) {
			DebugLogError(_T("libplum: cannot map %s port %hu (%d)"), (eMapping == MAP_UDP) ? sUDP : sTCP, mapping.internal_port, nId);
			slot.eState = MAPSTATE_FAILED;
			UpdateResult();
			return;
		}
		if (slot.eState != MAPSTATE_PENDING)
			return;	// the callback already came, and set it
		slot.nId = nId;
	}
	// libplum's thread may have stopped before the id was known here
	if (plum_query_mapping(nId, NULL, NULL) != PLUM_ERR_SUCCESS)
		OnMappingLost(nId);
}

void CUPnPImplLibPlum::CreateMappings()
{
	{
		CSingleLock lock(&m_csMappings, TRUE);
		SetMapping(MAP_TCP, m_nTCPPort);
		SetMapping(MAP_UDP, m_nUDPPort);
		SetMapping(MAP_WEB, m_nTCPWebPort);
	}
	for (int i = 0; i < MAP_COUNT; ++i)
		CreateMapping(static_cast<EMapping>(i));
}

void CUPnPImplLibPlum::DestroyMappings()
{
	int aIds[MAP_COUNT];
	int nCount = 0;
	{
		CSingleLock lock(&m_csMappings, TRUE);
		for (int i = 0; i < MAP_COUNT; ++i) {
			if (m_aMappings[i].nId >= 0)
				aIds[nCount++] = m_aMappings[i].nId;
			SetMapping(static_cast<EMapping>(i), 0);
		}
	}
	// libplum's thread removes them from the gateway, before any mapping created after this
	for (int i = 0; i < nCount; ++i)
		plum_destroy_mapping(aIds[i]);
}

void CUPnPImplLibPlum::UpdateResult()
{
	// m_csMappings must be held
	for (int i = 0; i < MAP_COUNT; ++i)
		if (m_aMappings[i].eState == MAPSTATE_PENDING)
			return;

	// don't fail if only the Web Interface port fails for some reason
	const bool bSucceeded = m_aMappings[MAP_TCP].eState == MAPSTATE_OK
		&& (m_aMappings[MAP_UDP].eState == MAPSTATE_NONE || m_aMappings[MAP_UDP].eState == MAPSTATE_OK);
	const TRISTATE eForwarded = bSucceeded ? TRIS_TRUE : TRIS_FALSE;
	if (!m_bDiscovering) {
		if (eForwarded == m_bUPnPPortsForwarded)
			return;
		// libplum lost the mappings at a renewal, or made them again on a later attempt
		if (bSucceeded)
			DebugLog(_T("libplum: the ports are mapped again"));
		else
			DebugLogWarning(_T("libplum: the ports are no longer mapped"));
	}
	m_bDiscovering = false;
	m_bUPnPPortsForwarded = eForwarded;
	SendResultMessage();
}

void CUPnPImplLibPlum::MappingCallback(int nId, plum_state_t eState, const plum_mapping_t *pMapping) noexcept
{
	// Called on libplum's thread, with libplum's lock held. Nothing may be thrown back into C code.
	if ((eState != PLUM_STATE_SUCCESS && eState != PLUM_STATE_FAILURE && eState != PLUM_STATE_DESTROYED) || pMapping == NULL || pMapping->user_ptr == NULL)
		return;
	try {
		static_cast<CUPnPImplLibPlum*>(pMapping->user_ptr)->OnMapping(nId, eState, *pMapping);
	} catch (CException *ex) {
		ex->Delete();
	} catch (...) {
	}
}

void CUPnPImplLibPlum::OnMapping(int nId, plum_state_t eState, const plum_mapping_t &mapping)
{
	if (eState == PLUM_STATE_DESTROYED) {
		OnMappingLost(nId);
		return;
	}
	const bool bTCP = (mapping.protocol == PLUM_IP_PROTOCOL_TCP);
	LPCTSTR pszProt = bTCP ? sTCP : sUDP;
	bool bDrop = false;
	{
		CSingleLock lock(&m_csMappings, TRUE);
		SMapping *pSlot = NULL;
		for (int i = 0; i < MAP_COUNT && pSlot == NULL; ++i)
			if (m_aMappings[i].eState != MAPSTATE_NONE && m_aMappings[i].nPort == mapping.internal_port && (i == MAP_UDP) != bTCP)
				pSlot = &m_aMappings[i];
		if (pSlot == NULL)
			return;	// a mapping let go of meanwhile

		pSlot->nId = nId;
		if (eState != PLUM_STATE_SUCCESS) {
			// libplum keeps trying, and calls again if it succeeds later
			DebugLogWarning(_T("libplum: mapping %s port %hu failed"), pszProt, mapping.internal_port);
			pSlot->eState = MAPSTATE_FAILED;
		} else if (mapping.external_port != mapping.internal_port) {
			// UPnP-IGD picks another public port when ours is taken on the gateway
			DebugLogWarning(_T("libplum: the gateway mapped %s port %hu to public port %hu - considering as failed"), pszProt, mapping.internal_port, mapping.external_port);
			pSlot->nId = -1;
			pSlot->eState = MAPSTATE_FAILED;
			bDrop = true;
		} else {
			DebugLog(_T("libplum: mapped %s port %hu through %s, public address %hs"), pszProt, mapping.internal_port, MappingProtocolName(mapping.mapping_protocol), mapping.external_host);
			pSlot->eState = MAPSTATE_OK;
		}
		UpdateResult();
	}
	if (bDrop)
		plum_destroy_mapping(nId);
}

void CUPnPImplLibPlum::OnMappingLost(int nId)
{
	// Every mapping destroyed here has let go of its id first. One still known went with libplum's
	// thread, which stops for good when it finds no default route: no network yet, or for a moment.
	CSingleLock lock(&m_csMappings, TRUE);
	for (int i = 0; i < MAP_COUNT; ++i) {
		SMapping &slot = m_aMappings[i];
		if (slot.nId == nId && slot.eState != MAPSTATE_NONE) {
			if (!m_bRestart.exchange(true))
				DebugLogWarning(_T("libplum: its thread has stopped, and starts again at the next discovery or refresh"));
			slot.nId = -1;
			slot.eState = MAPSTATE_FAILED;
			UpdateResult();
			return;
		}
	}
}

void CUPnPImplLibPlum::LogCallback(plum_log_level_t eLevel, const char *pszMessage) noexcept
{
	try {
		if (eLevel >= PLUM_LOG_LEVEL_ERROR)
			DebugLogError(_T("libplum: %hs"), pszMessage);
		else if (eLevel == PLUM_LOG_LEVEL_WARN)
			DebugLogWarning(_T("libplum: %hs"), pszMessage);
		else
			DebugLog(_T("libplum: %hs"), pszMessage);
	} catch (CException *ex) {
		ex->Delete();
	} catch (...) {
	}
}
