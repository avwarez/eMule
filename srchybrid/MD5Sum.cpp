#include "stdafx.h"
#include "MD5Sum.h"
#include "otherfunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

MD5Sum::MD5Sum()
	: m_hash()
{
}

MD5Sum::MD5Sum(const CString &sSource)
{
	Calculate(sSource);
}

MD5Sum::MD5Sum(const byte *pachSource, size_t nLength)
{
	Calculate(pachSource, nLength);
}

void MD5Sum::Calculate(const CString &sSource)
{
	Calculate((byte*)(LPCTSTR)sSource, sSource.GetLength() * sizeof(TCHAR));
}

void MD5Sum::Calculate(const byte *pachSource, size_t nLength)
{
	mbedtls_md5_context ctx;
	mbedtls_md5_init(&ctx);
	mbedtls_md5_starts(&ctx);
	mbedtls_md5_update(&ctx, pachSource, nLength);
	mbedtls_md5_finish(&ctx, m_hash.b);
	mbedtls_md5_free(&ctx);
}

CString MD5Sum::GetHashString() const
{
	return md4str(m_hash.b);
}