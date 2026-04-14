//this file is part of eMule
//Copyright (C)2002-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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
#include "emule.h"
#include "ClientCredits.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "SafeFile.h"
#include "Opcodes.h"
#include "ServerConnect.h"
#include "emuledlg.h"
#include "Log.h"
#include <bcrypt.h>
#include <vector>
#include <stdexcept>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/entropy.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define CLIENTS_MET_FILENAME	_T("clients.met")

CClientCredits::CClientCredits(const CreditStruct &in_credits)
	: m_Credits(in_credits)
{
	InitalizeIdent();
	ClearWaitStartTime();
	m_dwWaitTimeIP = 0;
}

CClientCredits::CClientCredits(const uchar *key)
	: m_Credits()
{
	md4cpy(&m_Credits.abyKey, key);
	InitalizeIdent();
	m_dwSecureWaitTime = m_dwUnSecureWaitTime = ::GetTickCount();
	m_dwWaitTimeIP = 0;
}

void CClientCredits::AddDownloaded(uint32 bytes, uint32 dwForIP)
{
	switch (GetCurrentIdentState(dwForIP)) {
	case IS_IDFAILED:
	case IS_IDBADGUY:
	case IS_IDNEEDED:
		if (theApp.clientcredits->CryptoAvailable())
			return;
	}

	uint64 current = GetDownloadedTotal() + bytes;
	//recode
	m_Credits.nDownloadedLo = LODWORD(current);
	m_Credits.nDownloadedHi = HIDWORD(current);
}

void CClientCredits::AddUploaded(uint32 bytes, uint32 dwForIP)
{
	switch (GetCurrentIdentState(dwForIP)) {
	case IS_IDFAILED:
	case IS_IDBADGUY:
	case IS_IDNEEDED:
		if (theApp.clientcredits->CryptoAvailable())
			return;
	}

	uint64 current = GetUploadedTotal() + bytes;
	//recode
	m_Credits.nUploadedLo = LODWORD(current);
	m_Credits.nUploadedHi = HIDWORD(current);
}

uint64 CClientCredits::GetUploadedTotal() const
{
	return ((uint64)m_Credits.nUploadedHi << 32) | m_Credits.nUploadedLo;
}

uint64 CClientCredits::GetDownloadedTotal() const
{
	return ((uint64)m_Credits.nDownloadedHi << 32) | m_Credits.nDownloadedLo;
}

float CClientCredits::GetScoreRatio(uint32 dwForIP) const
{
	// check the client ident status
	switch (GetCurrentIdentState(dwForIP)) {
	case IS_IDFAILED:
	case IS_IDBADGUY:
	case IS_IDNEEDED:
		if (theApp.clientcredits->CryptoAvailable())
			// bad guy - no credits for you
			return 1.0f;
	}

	if (GetDownloadedTotal() < 1048576)
		return 1.0f;
	float result;
	if (GetUploadedTotal())
		result = (GetDownloadedTotal() * 2) / (float)GetUploadedTotal();
	else
		result = 10.0f;

	// exponential calculation of the max multiplicator based on uploaded data (9.2MB = 3.34, 100MB = 10.0)
	float result2 = sqrt(GetDownloadedTotal() / 1048576.0f + 2.0f);

	// linear calculation of the max multiplicator based on uploaded data for the first chunk (1MB = 1.01, 9.2MB = 3.34)
	float result3;
	if (GetDownloadedTotal() < 9646899)
		result3 = (GetDownloadedTotal() - 1048576) / 8598323.0f * 2.34f + 1.0f;
	else
		result3 = 10.0f;

	// take the smallest result
	result = min(result, min(result2, result3));

	if (result < 1.0f)
		return 1.0f;
	return min(result, 10.0f);
}


CClientCreditsList::CClientCreditsList()
{
	m_nLastSaved = ::GetTickCount();
	LoadList();

	InitalizeCrypting();
}

CClientCreditsList::~CClientCreditsList()
{
	SaveList();
	CCKey tmpkey;
	for (POSITION pos = m_mapClients.GetStartPosition(); pos != NULL;) {
		CClientCredits *cur_credit;
		m_mapClients.GetNextAssoc(pos, tmpkey, cur_credit);
		delete cur_credit;
	}
	delete m_pSignkey;
}

void CClientCreditsList::LoadList()
{
	const CString &sConfDir(thePrefs.GetMuleDirectory(EMULE_CONFIGDIR));
	const CString &strFileName(sConfDir + CLIENTS_MET_FILENAME);
	const int iOpenFlags = CFile::modeRead | CFile::osSequentialScan | CFile::typeBinary | CFile::shareDenyWrite;
	CSafeBufferedFile file;
	if (!CFileOpen(file, strFileName, iOpenFlags, GetResString(IDS_ERR_LOADCREDITFILE)))
		return;

	::setvbuf(file.m_pStream, NULL, _IOFBF, 16384);
	try {
		uint8 version = file.ReadUInt8();
		if (version != CREDITFILE_VERSION && version != CREDITFILE_VERSION_29) {
			LogWarning(GetResString(IDS_ERR_CREDITFILEOLD));
			file.Close();
			return;
		}

		// everything is OK, lets see if the backup exist...
		const CString &strBakFileName(sConfDir + CLIENTS_MET_FILENAME _T(".bak"));

		BOOL bCreateBackup = TRUE;

		HANDLE hBakFile = ::CreateFile(strBakFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hBakFile != INVALID_HANDLE_VALUE) {
			// OK, the backup exist, get the size
			DWORD dwBakFileSize = ::GetFileSize(hBakFile, NULL); //debug
			if (dwBakFileSize > (DWORD)file.GetLength()) {
				// the size of the backup was larger then the orig. file, something is wrong here, don't overwrite old backup.
				bCreateBackup = FALSE;
			}
			//else: backup is smaller or the same size as orig. file, proceed with copying of file
			::CloseHandle(hBakFile);
		}
		//else: the backup doesn't exist, create it

		if (bCreateBackup) {
			file.Close(); // close the file before copying

			if (!::CopyFile(strFileName, strBakFileName, FALSE))
				LogError(GetResString(IDS_ERR_MAKEBAKCREDITFILE));

			// reopen file
			if (!CFileOpen(file, strFileName, iOpenFlags, GetResString(IDS_ERR_LOADCREDITFILE)))
				return;

			::setvbuf(file.m_pStream, NULL, _IOFBF, 16384);
			file.Seek(1, CFile::begin); //set file pointer behind file version byte
		}

		uint32 count = file.ReadUInt32();
		m_mapClients.InitHashTable(count + 5000); // TODO: should be prime number... and 20% larger

		const time_t dwExpired = time(NULL) - DAY2S(150); // today - 150 days
		uint32 cDeleted = 0;
		for (uint32 i = 0; i < count; ++i) {
			CreditStruct newcstruct{};
			file.Read(&newcstruct, (version == CREDITFILE_VERSION_29) ? sizeof(CreditStruct_29a) : sizeof(CreditStruct));

			if (newcstruct.nLastSeen < (uint32)dwExpired)
				++cDeleted;
			else {
				CClientCredits *newcredits = new CClientCredits(newcstruct);
				m_mapClients[CCKey(newcredits->GetKey())] = newcredits;
			}
		}
		file.Close();

		if (cDeleted > 0)
			AddLogLine(false, GetResString(IDS_CREDITFILELOADED) + GetResString(IDS_CREDITSEXPIRED), count - cDeleted, cDeleted);
		else
			AddLogLine(false, GetResString(IDS_CREDITFILELOADED), count);
	} catch (CFileException *ex) {
		if (ex->m_cause == CFileException::endOfFile)
			LogError(LOG_STATUSBAR, GetResString(IDS_CREDITFILECORRUPT));
		else
			LogError(LOG_STATUSBAR, GetResString(IDS_ERR_CREDITFILEREAD), (LPCTSTR)CExceptionStr(*ex));
		ex->Delete();
	}
}

void CClientCreditsList::SaveList()
{
	if (thePrefs.GetLogFileSaving())
		AddDebugLogLine(false, _T("Saving clients credit list file \"%s\""), CLIENTS_MET_FILENAME);
	m_nLastSaved = ::GetTickCount();

	CFile file;// no buffering needed here since we swap out the entire array
	if (!CFileOpen(file
		, thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + CLIENTS_MET_FILENAME
		, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary | CFile::shareDenyWrite
		, GetResString(IDS_ERR_FAILED_CREDITSAVE)))
	{
		return;
	}
	byte *pBuffer = new byte[m_mapClients.GetCount() * sizeof(CreditStruct)]; //not CreditStruct[] because of alignment
	uint32 count = 0;
	for (const CClientCreditsMap::CPair *pair = m_mapClients.PGetFirstAssoc(); pair != NULL; pair = m_mapClients.PGetNextAssoc(pair)) {
		const CClientCredits *cur_credit = pair->value;
		if (cur_credit->GetUploadedTotal() || cur_credit->GetDownloadedTotal())
			*reinterpret_cast<CreditStruct*>(&pBuffer[sizeof(CreditStruct) * count++]) = cur_credit->m_Credits;
	}

	try {
		uint8 version = CREDITFILE_VERSION;
		file.Write(&version, 1);
		file.Write(&count, 4);
		file.Write(pBuffer, (UINT)(count * sizeof(CreditStruct)));
		file.Close();
	} catch (CFileException *ex) {
		LogError(LOG_STATUSBAR, _T("%s%s"), (LPCTSTR)GetResString(IDS_ERR_FAILED_CREDITSAVE), (LPCTSTR)CExceptionStrDash(*ex));
		ex->Delete();
	}

	delete[] pBuffer;
}

CClientCredits* CClientCreditsList::GetCredit(const uchar *key)
{
	CCKey tkey(key);
	CClientCredits *result;
	if (!m_mapClients.Lookup(tkey, result)) {
		result = new CClientCredits(key);
		m_mapClients[CCKey(result->GetKey())] = result;
	}
	result->SetLastSeen();
	return result;
}

void CClientCreditsList::Process()
{
	if (::GetTickCount() >= m_nLastSaved + MIN2MS(13))
		SaveList();
}

void CClientCredits::InitalizeIdent()
{
	if (m_Credits.nKeySize == 0) {
		memset(m_abyPublicKey, 0, sizeof m_abyPublicKey); // for debugging
		m_nPublicKeyLen = 0;
		IdentState = IS_NOTAVAILABLE;
	} else {
		m_nPublicKeyLen = m_Credits.nKeySize;
		memcpy(m_abyPublicKey, m_Credits.abySecureIdent, m_nPublicKeyLen);
		IdentState = IS_IDNEEDED;
	}
	m_dwCryptRndChallengeFor = 0;
	m_dwCryptRndChallengeFrom = 0;
	m_dwIdentIP = 0;
}

void CClientCredits::Verified(uint32 dwForIP)
{
	m_dwIdentIP = dwForIP;
	// client was verified, copy the key to store him if not done already
	if (m_Credits.nKeySize == 0) {
		m_Credits.nKeySize = m_nPublicKeyLen;
		memcpy(m_Credits.abySecureIdent, m_abyPublicKey, m_nPublicKeyLen);
		if (GetDownloadedTotal() > 0) {
			// for security reason, we have to delete all prior credits here
			m_Credits.nDownloadedHi = 0;
			m_Credits.nDownloadedLo = 1;
			m_Credits.nUploadedHi = 0;
			m_Credits.nUploadedLo = 1; // in order to save this client, set 1 byte
			if (thePrefs.GetVerbose())
				DEBUG_ONLY(AddDebugLogLine(false, _T("Credits deleted due to new SecureIdent")));
		}
	}
	IdentState = IS_IDENTIFIED;
}

bool CClientCredits::SetSecureIdent(const uchar *pachIdent, uint8 nIdentLen)  // verified Public key cannot change, use only if there is no public key yet
{
	if (MAXPUBKEYSIZE < nIdentLen || m_Credits.nKeySize != 0)
		return false;
	memcpy(m_abyPublicKey, pachIdent, nIdentLen);
	m_nPublicKeyLen = nIdentLen;
	IdentState = IS_IDNEEDED;
	return true;
}

EIdentState	CClientCredits::GetCurrentIdentState(uint32 dwForIP) const
{
	if (IdentState != IS_IDENTIFIED)
		return IdentState;
	if (dwForIP == m_dwIdentIP)
		return IS_IDENTIFIED;
	return IS_IDBADGUY;
	// mod note: clients which just reconnected after an IP change and have to ident yet will also have this state for 1-2 seconds
	//		 so don't try to spam such clients with "bad guy" messages (besides: spam messages are always bad)
}

// --- RSA helpers (PKCS#1 RSAPublicKey DER format, wire-compatible with CryptoPP) ---

static int emule_rng(void * /*ctx*/, unsigned char *buf, size_t len)
{
	return BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
		? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}

// Write RSA public key as PKCS#1 RSAPublicKey DER (SEQUENCE { N INTEGER, E INTEGER })
// Returns number of bytes written into buf (starting at buf[0]), or negative on error.
static int rsa_write_pubkey_pkcs1(unsigned char *buf, size_t buflen, mbedtls_pk_context *pk)
{
	unsigned char *c = buf + buflen;
	size_t len = 0;
	mbedtls_mpi N, E;
	mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
	int ret = mbedtls_rsa_export(mbedtls_pk_rsa(*pk), &N, NULL, NULL, NULL, &E);
	if (ret == 0) {
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &E));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&c, buf, &N));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
		MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
		memmove(buf, c, len);
		ret = (int)len;
	}
	mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
	return ret;
}

// Parse RSA public key from PKCS#1 RSAPublicKey DER (SEQUENCE { N INTEGER, E INTEGER })
static int rsa_read_pubkey_pkcs1(mbedtls_pk_context *pk, const unsigned char *der, size_t len)
{
	unsigned char *p = const_cast<unsigned char*>(der);
	const unsigned char *end = der + len;
	size_t seq_len;
	mbedtls_mpi N, E;
	mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);

	int ret = mbedtls_asn1_get_tag(&p, end, &seq_len,
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret == 0) ret = mbedtls_asn1_get_mpi(&p, end, &N);
	if (ret == 0) ret = mbedtls_asn1_get_mpi(&p, end, &E);
	if (ret == 0) ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (ret == 0) ret = mbedtls_rsa_import(mbedtls_pk_rsa(*pk), &N, NULL, NULL, NULL, &E);
	if (ret == 0) ret = mbedtls_rsa_complete(mbedtls_pk_rsa(*pk));

	mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
	return ret;
}

// Sign message with RSASSA-PKCS1v15-SHA1. Returns signature length or 0 on error.
static size_t rsa_sign_pkcs1v15_sha1(mbedtls_pk_context *pk,
	const unsigned char *msg, size_t msglen,
	unsigned char *sig, size_t sigbuf)
{
	unsigned char hash[20];
	if (mbedtls_sha1(msg, msglen, hash) != 0) return 0;
	size_t siglen = 0;
	if (mbedtls_pk_sign(pk, MBEDTLS_MD_SHA1, hash, sizeof hash,
		sig, sigbuf, &siglen, emule_rng, NULL) != 0) return 0;
	return siglen;
}

// Verify signature with RSASSA-PKCS1v15-SHA1. Returns true if valid.
static bool rsa_verify_pkcs1v15_sha1(mbedtls_pk_context *pk,
	const unsigned char *msg, size_t msglen,
	const unsigned char *sig, size_t siglen)
{
	unsigned char hash[20];
	if (mbedtls_sha1(msg, msglen, hash) != 0) return false;
	return mbedtls_pk_verify(pk, MBEDTLS_MD_SHA1, hash, sizeof hash, sig, siglen) == 0;
}

void CClientCreditsList::InitalizeCrypting()
{
	m_nMyPublicKeyLen = 0;
	memset(m_abyMyPublicKey, 0, sizeof m_abyMyPublicKey);
	m_pSignkey = NULL;
	if (!thePrefs.IsSecureIdentEnabled())
		return;

	// check if keyfile exists and is non-empty
	bool bCreateNewKey = false;
	const CString &cryptkeypath(thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("cryptkey.dat"));
	HANDLE hKeyFile = ::CreateFile(cryptkeypath,
		GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hKeyFile != INVALID_HANDLE_VALUE) {
		if (::GetFileSize(hKeyFile, NULL) == 0)
			bCreateNewKey = true;
		::CloseHandle(hKeyFile);
	} else
		bCreateNewKey = true;
	if (bCreateNewKey)
		CreateKeyPair();

	// load private key: read file → base64 decode → DER parse
	try {
		// read file
		CStdioFile f;
		if (!f.Open(cryptkeypath, CFile::modeRead | CFile::shareDenyWrite | CFile::typeText))
			throw std::runtime_error("cannot open key file");
		CString sB64; CString sLine;
		while (f.ReadString(sLine)) sB64 += sLine;
		f.Close();
		CStringA sB64A(sB64);

		// base64 decode
		size_t derLen = 0;
		mbedtls_base64_decode(NULL, 0, &derLen, (const unsigned char*)(LPCSTR)sB64A, sB64A.GetLength());
		std::vector<unsigned char> der(derLen);
		if (mbedtls_base64_decode(der.data(), derLen, &derLen,
			(const unsigned char*)(LPCSTR)sB64A, sB64A.GetLength()) != 0)
			throw std::runtime_error("base64 decode failed");

		// parse PKCS#1 RSAPrivateKey DER
		auto *pk = new mbedtls_pk_context;
		mbedtls_pk_init(pk);
		if (mbedtls_pk_parse_key(pk, der.data(), derLen, NULL, 0, emule_rng, NULL) != 0) {
			mbedtls_pk_free(pk); delete pk;
			throw std::runtime_error("key parse failed");
		}
		m_pSignkey = pk;

		// extract and store public key in PKCS#1 RSAPublicKey DER format
		int n = rsa_write_pubkey_pkcs1(m_abyMyPublicKey, sizeof m_abyMyPublicKey, m_pSignkey);
		if (n <= 0) {
			mbedtls_pk_free(pk); delete pk;
			m_pSignkey = NULL;
			throw std::runtime_error("pubkey export failed");
		}
		m_nMyPublicKeyLen = (uint8)n;
	} catch (...) {
		delete m_pSignkey;
		m_pSignkey = NULL;
		LogError(LOG_STATUSBAR, GetResString(IDS_CRYPT_INITFAILED));
		ASSERT(0);
	}
	ASSERT(Debug_CheckCrypting());
}

bool CClientCreditsList::CreateKeyPair()
{
	try {
		// Generate RSA key pair
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);
		int ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
		if (ret == 0)
			ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), emule_rng, NULL, RSAKEYSIZE, 65537);
		if (ret != 0) {
			mbedtls_pk_free(&pk);
			throw std::runtime_error("key generation failed");
		}

		// Write PKCS#1 RSAPrivateKey DER (mbedtls writes from end of buffer)
		unsigned char derBuf[1024];
		int derLen = mbedtls_pk_write_key_der(&pk, derBuf, sizeof derBuf);
		mbedtls_pk_free(&pk);
		if (derLen <= 0)
			throw std::runtime_error("key DER export failed");
		const unsigned char *derStart = derBuf + sizeof(derBuf) - derLen;

		// Base64 encode
		size_t b64Len = 0;
		mbedtls_base64_encode(NULL, 0, &b64Len, derStart, derLen);
		std::vector<unsigned char> b64(b64Len + 1);
		mbedtls_base64_encode(b64.data(), b64Len, &b64Len, derStart, derLen);

		// Write to file
		const CString keypath(thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("cryptkey.dat"));
		CStdioFile f;
		if (!f.Open(keypath, CFile::modeCreate | CFile::modeWrite | CFile::shareDenyWrite | CFile::typeText))
			throw std::runtime_error("cannot write key file");
		f.WriteString(CString((LPCSTR)b64.data(), (int)b64Len));
		f.Close();

		if (thePrefs.GetLogSecureIdent())
			AddDebugLogLine(false, _T("Created new RSA keypair"));
		return true;
	} catch (...) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("Failed to create new RSA keypair"));
		ASSERT(0);
	}
	return false;
}

uint8 CClientCreditsList::CreateSignature(CClientCredits *pTarget, uchar *pachOutput, uint8 nMaxSize
	, uint32 ChallengeIP, uint8 byChaIPKind, mbedtls_pk_context *sigkey) const
{
	ASSERT(pTarget != NULL && pachOutput != NULL);
	if (sigkey == NULL)
		sigkey = m_pSignkey;
	if (!CryptoAvailable())
		return 0;

	byte abyBuffer[MAXPUBKEYSIZE + 9];
	size_t keylen = pTarget->GetSecIDKeyLen();
	memcpy(abyBuffer, pTarget->GetSecureIdent(), keylen);
	uint32 challenge = pTarget->m_dwCryptRndChallengeFrom;
	ASSERT(challenge);
	PokeUInt32(&abyBuffer[keylen], challenge);
	size_t ChIpLen;
	if (byChaIPKind == 0)
		ChIpLen = 0;
	else {
		ChIpLen = 5;
		PokeUInt32(&abyBuffer[keylen + 4], ChallengeIP);
		abyBuffer[keylen + 4 + 4] = byChaIPKind;
	}
	unsigned char sig[256];
	size_t siglen = rsa_sign_pkcs1v15_sha1(sigkey, abyBuffer, keylen + 4 + ChIpLen, sig, sizeof sig);
	if (siglen == 0 || siglen > nMaxSize)
		return 0;
	memcpy(pachOutput, sig, siglen);
	return (uint8)siglen;
}

bool CClientCreditsList::VerifyIdent(CClientCredits *pTarget, const uchar *pachSignature, uint8 nInputSize,
	uint32 dwForIP, uint8 byChaIPKind)
{
	ASSERT(pTarget);
	ASSERT(pachSignature);
	if (!CryptoAvailable()) {
		pTarget->IdentState = IS_NOTAVAILABLE;
		return false;
	}
	bool bResult = false;
	try {
		mbedtls_pk_context pubkey;
		mbedtls_pk_init(&pubkey);
		int ret = rsa_read_pubkey_pkcs1(&pubkey,
			(const unsigned char*)pTarget->GetSecureIdent(), pTarget->GetSecIDKeyLen());
		if (ret != 0) {
			mbedtls_pk_free(&pubkey);
			throw std::runtime_error("pubkey parse failed");
		}

		// 4 additional bytes random data send from this client +5 bytes v2
		byte abyBuffer[MAXPUBKEYSIZE + 9];
		memcpy(abyBuffer, m_abyMyPublicKey, m_nMyPublicKeyLen);
		uint32 challenge = pTarget->m_dwCryptRndChallengeFor;
		ASSERT(challenge);
		PokeUInt32(&abyBuffer[m_nMyPublicKeyLen], challenge);

		size_t nChIpSize;
		if (byChaIPKind == 0)
			nChIpSize = 0;
		else {
			nChIpSize = 5;
			uint32 ChallengeIP = 0;
			switch (byChaIPKind) {
			case CRYPT_CIP_LOCALCLIENT:
				ChallengeIP = dwForIP;
				break;
			case CRYPT_CIP_REMOTECLIENT:
				if (theApp.serverconnect->GetClientID() == 0 || theApp.serverconnect->IsLowID()) {
					if (thePrefs.GetLogSecureIdent())
						AddDebugLogLine(false, _T("Warning: Maybe SecureHash Ident fails because LocalIP is unknown"));
					ChallengeIP = theApp.serverconnect->GetLocalIP();
				} else
					ChallengeIP = theApp.serverconnect->GetClientID();
				break;
			case CRYPT_CIP_NONECLIENT:
				ChallengeIP = 0;
			}
			PokeUInt32(&abyBuffer[m_nMyPublicKeyLen + 4], ChallengeIP);
			abyBuffer[m_nMyPublicKeyLen + 4 + 4] = byChaIPKind;
		}

		bResult = rsa_verify_pkcs1v15_sha1(&pubkey,
			abyBuffer, m_nMyPublicKeyLen + 4 + nChIpSize,
			(const unsigned char*)pachSignature, nInputSize);
		mbedtls_pk_free(&pubkey);
	} catch (...) {
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("Error: Unknown exception in %hs"), __FUNCTION__);
		bResult = false;
	}
	if (!bResult) {
		if (pTarget->IdentState == IS_IDNEEDED)
			pTarget->IdentState = IS_IDFAILED;
	} else
		pTarget->Verified(dwForIP);

	return bResult;
}

bool CClientCreditsList::CryptoAvailable() const
{
	return m_nMyPublicKeyLen > 0 && m_pSignkey != NULL && thePrefs.IsSecureIdentEnabled();
}

#ifdef _DEBUG
bool CClientCreditsList::Debug_CheckCrypting()
{
	// Generate a temporary RSA keypair for self-test
	mbedtls_pk_context privpk;
	mbedtls_pk_init(&privpk);
	if (mbedtls_pk_setup(&privpk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0 ||
		mbedtls_rsa_gen_key(mbedtls_pk_rsa(privpk), emule_rng, NULL, RSAKEYSIZE, 65537) != 0) {
		mbedtls_pk_free(&privpk);
		return false;
	}

	byte abyPublicKey[80];
	int pubLen = rsa_write_pubkey_pkcs1(abyPublicKey, sizeof abyPublicKey, &privpk);
	if (pubLen <= 0) { mbedtls_pk_free(&privpk); return false; }
	uint8 PublicKeyLen = (uint8)pubLen;

	uint32 challenge = GetRandomUInt32();
	CreditStruct emptystruct{};
	CClientCredits newcredits(emptystruct);
	newcredits.SetSecureIdent(m_abyMyPublicKey, m_nMyPublicKeyLen);
	newcredits.m_dwCryptRndChallengeFrom = challenge;
	uchar pachSignature[200] = {};
	uint8 sigsize = CreateSignature(&newcredits, pachSignature, sizeof pachSignature, 0, 0, &privpk);

	CClientCredits newcredits2(emptystruct);
	newcredits2.m_dwCryptRndChallengeFor = challenge;
	newcredits2.SetSecureIdent(abyPublicKey, PublicKeyLen);

	bool bResult = VerifyIdent(&newcredits2, pachSignature, sigsize, 0, 0);
	mbedtls_pk_free(&privpk);
	return bResult;
}
#endif

DWORD CClientCredits::GetSecureWaitStartTime(uint32 dwForIP)
{
	if (m_dwUnSecureWaitTime == 0 || m_dwSecureWaitTime == 0)
		SetSecWaitStartTime(dwForIP);

	if (m_Credits.nKeySize != 0) {	// this client is a SecureHash Client
		if (GetCurrentIdentState(dwForIP) == IS_IDENTIFIED) // good boy
			return m_dwSecureWaitTime;

		// not so good boy
		if (dwForIP == m_dwWaitTimeIP)
			return m_dwUnSecureWaitTime;

		// bad boy
		// this can also happen if the client has not identified himself yet, but will do later - so maybe he is not a bad boy :) .
		/*CString buffer2, buffer;
		for (int i = 0; i < 16; ++i) {
			buffer2.Format("%02X", m_Credits.abyKey[i]);
			buffer += buffer2;
		}
		if (thePrefs.GetLogSecureIdent())
			AddDebugLogLine(false, "Warning: WaitTime reset due to Invalid Ident for Userhash %s", buffer);*/

		m_dwUnSecureWaitTime = ::GetTickCount();
		m_dwWaitTimeIP = dwForIP;
	}
	// not a SecureHash Client - handle it like before for now (no security checks)
	return m_dwUnSecureWaitTime;
}

void CClientCredits::SetSecWaitStartTime(uint32 dwForIP)
{
	m_dwUnSecureWaitTime = ::GetTickCount() - 1;
	m_dwSecureWaitTime = m_dwUnSecureWaitTime;
	m_dwWaitTimeIP = dwForIP;
}

void CClientCredits::ClearWaitStartTime()
{
	m_dwUnSecureWaitTime = 0;
	m_dwSecureWaitTime = 0;
}