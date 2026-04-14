//this file is part of eMule
//Copyright (C)2002-2024 Merkur ( devs@emule-project.net / https://www.emule-project.net )
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
#include "StdAfx.h"
#include "collection.h"
#include "KnownFile.h"
#include "CollectionFile.h"
#include "SafeFile.h"
#include "Packets.h"
#include "Preferences.h"
#include "SharedFilelist.h"
#include "emule.h"
#include "Log.h"
#include "md5sum.h"
#include "mbedtls/sha1.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/entropy.h"
#include <bcrypt.h>
#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define COLLECTION_FILE_VERSION1_INITIAL		0x01
#define COLLECTION_FILE_VERSION2_LARGEFILES		0x02

CCollection::CCollection()
	: m_bTextFormat()
	, m_nKeySize()
	, m_pabyCollectionAuthorKey()
{
	m_CollectionFilesMap.InitHashTable(1031);
	m_sCollectionName.Format(_T("New Collection-%u"), ::GetTickCount());
}

CCollection::CCollection(const CCollection *pCollection)
	: m_sCollectionName(pCollection->m_sCollectionName)
	, m_bTextFormat(pCollection->m_bTextFormat)
{
	if (pCollection->m_pabyCollectionAuthorKey != NULL) {
		m_nKeySize = pCollection->m_nKeySize;
		m_pabyCollectionAuthorKey = new BYTE[m_nKeySize];
		memcpy(m_pabyCollectionAuthorKey, pCollection->m_pabyCollectionAuthorKey, m_nKeySize);
		m_sCollectionAuthorName = pCollection->m_sCollectionAuthorName;
	} else {
		m_nKeySize = 0;
		m_pabyCollectionAuthorKey = NULL;
	}

	m_CollectionFilesMap.InitHashTable(1031);
	for (const CCollectionFilesMap::CPair *pair = pCollection->m_CollectionFilesMap.PGetFirstAssoc(); pair != NULL; pair = pCollection->m_CollectionFilesMap.PGetNextAssoc(pair))
		AddFileToCollection(pair->value, true);
}

CCollection::~CCollection()
{
	delete[] m_pabyCollectionAuthorKey;
	CSKey key;
	for (POSITION pos = m_CollectionFilesMap.GetStartPosition(); pos != NULL;) {
		CCollectionFile *pCollectionFile;
		m_CollectionFilesMap.GetNextAssoc(pos, key, pCollectionFile);
		delete pCollectionFile;
	}
}

CCollectionFile* CCollection::AddFileToCollection(CAbstractFile *pAbstractFile, bool bCreateClone)
{
	CSKey key(pAbstractFile->GetFileHash());
	CCollectionFile *pCollectionFile;
	if (m_CollectionFilesMap.Lookup(key, pCollectionFile)) {
		ASSERT(0);
		return pCollectionFile;
	}

	if (bCreateClone)
		pCollectionFile = new CCollectionFile(pAbstractFile);
	else if (pAbstractFile->IsKindOf(RUNTIME_CLASS(CCollectionFile)))
		pCollectionFile = static_cast<CCollectionFile*>(pAbstractFile);
	else
		pCollectionFile = NULL;

	if (pCollectionFile)
		m_CollectionFilesMap[key] = pCollectionFile;

	return pCollectionFile;
}

void CCollection::RemoveFileFromCollection(CAbstractFile *pAbstractFile)
{
	CSKey key(pAbstractFile->GetFileHash());
	CCollectionFile *pCollectionFile;
	if (m_CollectionFilesMap.Lookup(key, pCollectionFile)) {
		m_CollectionFilesMap.RemoveKey(key);
		delete pCollectionFile;
	} else
		ASSERT(0);
}

void CCollection::SetCollectionAuthorKey(const byte *abyCollectionAuthorKey, uint32 nSize)
{
	delete[] m_pabyCollectionAuthorKey;
	m_pabyCollectionAuthorKey = NULL;
	m_nKeySize = 0;
	if (abyCollectionAuthorKey != NULL) {
		m_pabyCollectionAuthorKey = new BYTE[nSize];
		memcpy(m_pabyCollectionAuthorKey, abyCollectionAuthorKey, nSize);
		m_nKeySize = nSize;
	}
}

bool CCollection::InitCollectionFromFile(const CString &sFilePath, const CString &sFileName)
{
	CSafeFile data;
	if (!data.Open(sFilePath, CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary))
		return false;
	bool bCollectionLoaded = false;
	try {
		uint32 nVersion = data.ReadUInt32();
		if (nVersion == COLLECTION_FILE_VERSION1_INITIAL || nVersion == COLLECTION_FILE_VERSION2_LARGEFILES) {
			for (uint32 headerTagCount = data.ReadUInt32(); headerTagCount > 0; --headerTagCount) {
				CTag tag(data, true);
				switch (tag.GetNameID()) {
				case FT_FILENAME:
					if (tag.IsStr())
						m_sCollectionName = tag.GetStr();
					break;
				case FT_COLLECTIONAUTHOR:
					if (tag.IsStr())
						m_sCollectionAuthorName = tag.GetStr();
					break;
				case FT_COLLECTIONAUTHORKEY:
					if (tag.IsBlob())
						SetCollectionAuthorKey(tag.GetBlob(), tag.GetBlobSize());
				}
			}
			for (uint32 fileCount = data.ReadUInt32(); fileCount > 0; --fileCount)
				try {
					CCollectionFile *pCollectionFile = new CCollectionFile(data);
					AddFileToCollection(pCollectionFile, false);
				} catch (...) {
					ASSERT(0);
				}

			bCollectionLoaded = true;
		}
		if (m_pabyCollectionAuthorKey != NULL) {
			bool bResult = false;
			if (data.GetLength() > data.GetPosition()) {
				uint32 nPos = (uint32)data.GetPosition();
				data.SeekToBegin();
				std::vector<BYTE> message(nPos);
				VERIFY(data.Read(message.data(), nPos) == nPos);

				UINT nSignLen = (UINT)(data.GetLength() - data.GetPosition());
				std::vector<BYTE> signature(nSignLen);
				VERIFY(data.Read(signature.data(), nSignLen) == nSignLen);

				// Parse PKCS#1 RSAPublicKey DER
				unsigned char *p = m_pabyCollectionAuthorKey;
				const unsigned char *end = p + m_nKeySize;
				size_t seq_len; mbedtls_mpi N, E;
				mbedtls_mpi_init(&N); mbedtls_mpi_init(&E);
				if (mbedtls_asn1_get_tag(&p, end, &seq_len,
					MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0 &&
					mbedtls_asn1_get_mpi(&p, end, &N) == 0 &&
					mbedtls_asn1_get_mpi(&p, end, &E) == 0) {
					mbedtls_pk_context pubkey;
					mbedtls_pk_init(&pubkey);
					if (mbedtls_pk_setup(&pubkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
						mbedtls_rsa_import(mbedtls_pk_rsa(pubkey), &N, NULL, NULL, NULL, &E) == 0 &&
						mbedtls_rsa_complete(mbedtls_pk_rsa(pubkey)) == 0) {
						unsigned char hash[20];
						if (mbedtls_sha1(message.data(), nPos, hash) == 0) {
							bResult = mbedtls_pk_verify(&pubkey, MBEDTLS_MD_SHA1,
								hash, sizeof hash, signature.data(), nSignLen) == 0;
						}
					}
					mbedtls_pk_free(&pubkey);
				}
				mbedtls_mpi_free(&N); mbedtls_mpi_free(&E);
			}
			if (!bResult) {
				DebugLogWarning(_T("Collection %s: Verification of public key failed!"), (LPCTSTR)m_sCollectionName);
				delete[] m_pabyCollectionAuthorKey;
				m_pabyCollectionAuthorKey = NULL;
				m_nKeySize = 0;
				m_sCollectionAuthorName.Empty();
			} else
				DebugLog(_T("Collection %s: Public key verified"), (LPCTSTR)m_sCollectionName);

		} else
			m_sCollectionAuthorName.Empty();
		data.Close();
	} catch (CFileException *ex) {
		ex->Delete();
		return false;
	} catch (...) {
		ASSERT(0);
		return false;
	}

	if (!bCollectionLoaded) {
		CStdioFile data1;
		if (data1.Open(sFilePath, CFile::modeRead | CFile::shareDenyWrite | CFile::typeText)) {
			try {
				CString sLink;
				while (data1.ReadString(sLink)) {
					//Ignore all lines that start with #.
					//These lines can be used for future features.
					if (sLink.Find(_T('#')) != 0) {
						try {
							CCollectionFile *pCollectionFile = new CCollectionFile();
							if (pCollectionFile->InitFromLink(sLink))
								AddFileToCollection(pCollectionFile, false);
							else
								delete pCollectionFile;
						} catch (...) {
							ASSERT(0);
							return false;
						}
					}
				}
				data1.Close();
				//No collection name tag; use file name without extension
				int iLen = sFileName.GetLength();
				if (HasCollectionExtention(sFileName))
					iLen -= _countof(COLLECTION_FILEEXTENSION) - 1;
				m_sCollectionName = sFileName.Left(iLen);
				m_bTextFormat = true;
				return true;
			} catch (CFileException *ex) {
				ex->Delete();
			} catch (...) {
				ASSERT(0);
			}
		}
	}
	return bCollectionLoaded;
}

void CCollection::WriteToFileAddShared(mbedtls_pk_context *pSignKey)
{

	CString sFilePath(thePrefs.GetMuleDirectory(EMULE_INCOMINGDIR));
	sFilePath.AppendFormat(_T("%s%s"), (LPCTSTR)m_sCollectionName, COLLECTION_FILEEXTENSION);

	if (m_bTextFormat) {
		CStdioFile data;
		if (data.Open(sFilePath, CFile::modeCreate | CFile::modeWrite | CFile::shareDenyWrite | CFile::typeText)) {
			try {
				for (const CCollectionFilesMap::CPair *pair = m_CollectionFilesMap.PGetFirstAssoc(); pair != NULL; pair = m_CollectionFilesMap.PGetNextAssoc(pair))
					if (pair->value)
						data.WriteString(pair->value->GetED2kLink() + _T('\n'));

				data.Close();
			} catch (CFileException *ex) {
				ex->Delete();
				return;
			} catch (...) {
				ASSERT(0);
				return;
			}
		}
	} else {
		CSafeFile data;
		if (data.Open(sFilePath, CFile::modeCreate | CFile::modeReadWrite | CFile::shareDenyWrite | CFile::typeBinary)) {
			try {
				//Version
				// check first if we have any large files in the map - write use lowest version possible
				uint32 dwVersion = COLLECTION_FILE_VERSION1_INITIAL;
				for (const CCollectionFilesMap::CPair *pair = m_CollectionFilesMap.PGetFirstAssoc(); pair != NULL; pair = m_CollectionFilesMap.PGetNextAssoc(pair))
					if (pair->value->IsLargeFile()) {
						dwVersion = COLLECTION_FILE_VERSION2_LARGEFILES;
						break;
					}

				data.WriteUInt32(dwVersion);
				//NumberHeaderTags
				data.WriteUInt32(m_pabyCollectionAuthorKey ? 3 : 1);

				CTag collectionName(FT_FILENAME, m_sCollectionName);
				collectionName.WriteTagToFile(data, UTF8strRaw);

				if (m_pabyCollectionAuthorKey != NULL) {
					CTag collectionAuthor(FT_COLLECTIONAUTHOR, m_sCollectionAuthorName);
					collectionAuthor.WriteTagToFile(data, UTF8strRaw);

					CTag collectionAuthorKey(FT_COLLECTIONAUTHORKEY, m_nKeySize, m_pabyCollectionAuthorKey);
					collectionAuthorKey.WriteTagToFile(data, UTF8strRaw);
				}

				//Total Files
				data.WriteUInt32((uint32)m_CollectionFilesMap.GetCount());

				for (const CCollectionFilesMap::CPair *pair = m_CollectionFilesMap.PGetFirstAssoc(); pair != NULL; pair = m_CollectionFilesMap.PGetNextAssoc(pair))
					pair->value->WriteCollectionInfo(data);

				if (pSignKey != NULL) {
					uint32 nPos = (uint32)data.GetPosition();
					data.SeekToBegin();
					std::vector<BYTE> buffer(nPos);
					VERIFY(data.Read(buffer.data(), nPos) == nPos);

					unsigned char hash[20];
					unsigned char sig[256];
					size_t sigLen = 0;
					if (mbedtls_sha1(buffer.data(), nPos, hash) == 0) {
						auto rng_fn = [](void*, unsigned char *b, size_t l) -> int {
							return BCryptGenRandom(NULL, b, (ULONG)l, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
								? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
						};
						mbedtls_pk_sign(pSignKey, MBEDTLS_MD_SHA1, hash, sizeof hash,
							sig, sizeof sig, &sigLen, rng_fn, NULL);
					}
					if (sigLen > 0)
						data.Write(sig, (UINT)sigLen);
				}
				data.Close();
			} catch (CFileException *ex) {
				ex->Delete();
				return;
			} catch (...) {
				ASSERT(0);
				return;
			}
		}
	}

	theApp.sharedfiles->AddFileFromNewlyCreatedCollection(sFilePath);
}

bool CCollection::HasCollectionExtention(const CString &sFileName)
{
	return ExtensionIs(sFileName, COLLECTION_FILEEXTENSION);
}

CString CCollection::GetCollectionAuthorKeyString()
{
	return m_pabyCollectionAuthorKey ? EncodeBase16(m_pabyCollectionAuthorKey, m_nKeySize) : CString();
}

CString CCollection::GetAuthorKeyHashString() const
{
	if (m_pabyCollectionAuthorKey == NULL)
		return CString();
	MD5Sum md5(m_pabyCollectionAuthorKey, m_nKeySize);
	return md5.GetHashString().MakeUpper();
}