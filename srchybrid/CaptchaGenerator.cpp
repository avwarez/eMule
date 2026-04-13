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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#include "StdAfx.h"
#include "CaptchaGenerator.h"
#include "OtherFunctions.h"
#include <atlimage.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define LETTERSIZE  32
#define CROWDEDSIZE 18

// fairly simple captcha generator, might be improved if spammers think it's really worth it to solve captchas in eMule

static TCHAR const schCaptchaContent[] = _T("ABCDEFGHIJKLMNPQRSTUVWXYZ123456789");

CCaptchaGenerator::CCaptchaGenerator(uint32 nLetterCount)
	: m_pimgCaptcha()
	, m_gdipToken()
{
	Gdiplus::GdiplusStartupInput gdipInput;
	Gdiplus::GdiplusStartup(&m_gdipToken, &gdipInput, NULL);
	ReGenerateCaptcha(nLetterCount);
}

CCaptchaGenerator::~CCaptchaGenerator()
{
	Clear();
	Gdiplus::GdiplusShutdown(m_gdipToken);
}

void CCaptchaGenerator::ReGenerateCaptcha(uint32 nLetterCount)
{
	Clear();
	if (!m_gdipToken) return;

	// Result image: white background (width validated by ProcessCaptchaRequest: 11..149)
	UINT resultW = nLetterCount > 1 ? (LETTERSIZE + nLetterCount * CROWDEDSIZE) : LETTERSIZE;
	UINT resultH = 48;
	auto *pimgResult = new Gdiplus::Bitmap(resultW, resultH, PixelFormat32bppARGB);
	{ Gdiplus::Graphics g(pimgResult); g.Clear(Gdiplus::Color(255, 255, 255, 255)); }

	TCHAR strLetter[2] = {};
	for (uint32 i = 0; i < nLetterCount; ++i) {
		strLetter[0] = schCaptchaContent[rand() % (_countof(schCaptchaContent) - 1)];
		m_strCaptchaText += strLetter[0];

		// Draw letter on a blank LETTERSIZE x LETTERSIZE white bitmap
		Gdiplus::Bitmap imgLetter(LETTERSIZE, LETTERSIZE, PixelFormat32bppARGB);
		{
			Gdiplus::Graphics g(&imgLetter);
			g.Clear(Gdiplus::Color(255, 255, 255, 255));
			g.SetTextRenderingHint(Gdiplus::TextRenderingHintSingleBitPerPixelGridFit);
			int iFontSize = rand() % 10;
			int iTextOffsetX = 3 + rand() % 11;
			Gdiplus::Font font(L"Arial", (Gdiplus::REAL)(40 - iFontSize), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
			Gdiplus::SolidBrush brush(Gdiplus::Color(255, 0, 0, 0));
			Gdiplus::StringFormat fmt;
			g.DrawString(strLetter, 1, &font, Gdiplus::PointF((Gdiplus::REAL)iTextOffsetX, 0.0f), &fmt, &brush);
		}

		// Rotate letter with bilinear filtering; white is the background color
		float fRotate = 35.0f - (float)(rand() % 71);
		Gdiplus::Bitmap imgRotated(LETTERSIZE, LETTERSIZE, PixelFormat32bppARGB);
		{
			Gdiplus::Graphics g(&imgRotated);
			g.Clear(Gdiplus::Color(255, 255, 255, 255));
			g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBilinear);
			float cx = LETTERSIZE / 2.0f, cy = LETTERSIZE / 2.0f;
			g.TranslateTransform(cx, cy);
			g.RotateTransform(fRotate);
			g.TranslateTransform(-cx, -cy);
			g.DrawImage(&imgLetter, 0, 0, LETTERSIZE, LETTERSIZE);
		}

		// Merge rotated letter into result (preserve existing black pixels)
		UINT nOffset = i * CROWDEDSIZE;
		for (UINT j = 0; j < resultH && j < (UINT)LETTERSIZE; ++j) {
			for (UINT k = 0; k < (UINT)LETTERSIZE && nOffset + k < resultW; ++k) {
				Gdiplus::Color cResult, cLetter;
				pimgResult->GetPixel(nOffset + k, j, &cResult);
				imgRotated.GetPixel(k, j, &cLetter);
				// If result is still white and letter pixel is black, stamp it
				if (cResult.GetR() > 200 && cLetter.GetR() < 128)
					pimgResult->SetPixel(nOffset + k, j, Gdiplus::Color(255, 0, 0, 0));
			}
		}
	}

	// Jitter: displace each output pixel by a random ±1 offset from the source
	Gdiplus::Bitmap *pJittered = new Gdiplus::Bitmap(resultW, resultH, PixelFormat32bppARGB);
	{ Gdiplus::Graphics g(pJittered); g.Clear(Gdiplus::Color(255, 255, 255, 255)); }
	for (UINT y = 0; y < resultH; ++y) {
		for (UINT x = 0; x < resultW; ++x) {
			int sx = (int)x + (rand() % 3) - 1;
			int sy = (int)y + (rand() % 3) - 1;
			sx = max(0, min((int)resultW - 1, sx));
			sy = max(0, min((int)resultH - 1, sy));
			Gdiplus::Color c;
			pimgResult->GetPixel(sx, sy, &c);
			pJittered->SetPixel(x, y, c);
		}
	}
	delete pimgResult;
	m_pimgCaptcha = pJittered;
}

void CCaptchaGenerator::Clear()
{
	delete m_pimgCaptcha;
	m_pimgCaptcha = nullptr;
	m_strCaptchaText.Empty();
}

bool CCaptchaGenerator::WriteCaptchaImage(CFileDataIO &file)
{
	if (!m_pimgCaptcha) return false;

	UINT w = m_pimgCaptcha->GetWidth();
	UINT h = m_pimgCaptcha->GetHeight();
	int rowStride = (((int)w + 31) / 32) * 4; // 1bpp row, DWORD-aligned
	int pixelBytes = rowStride * (int)h;
	int headerBytes = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + 2 * sizeof(RGBQUAD);
	int totalBytes  = headerBytes + pixelBytes;

	BYTE *pBuf = (BYTE *)malloc(totalBytes);
	if (!pBuf) return false;
	memset(pBuf, 0, totalBytes);

	// BITMAPFILEHEADER
	auto *bfh = reinterpret_cast<BITMAPFILEHEADER *>(pBuf);
	bfh->bfType    = 0x4D42; // 'BM'
	bfh->bfSize    = totalBytes;
	bfh->bfOffBits = headerBytes;

	// BITMAPINFOHEADER
	auto *bih = reinterpret_cast<BITMAPINFOHEADER *>(pBuf + sizeof(BITMAPFILEHEADER));
	bih->biSize        = sizeof(BITMAPINFOHEADER);
	bih->biWidth       = (LONG)w;
	bih->biHeight      = (LONG)h; // positive = bottom-up
	bih->biPlanes      = 1;
	bih->biBitCount    = 1;
	bih->biCompression = BI_RGB;
	bih->biSizeImage   = pixelBytes;

	// 2-color palette: index 0 = white (background), index 1 = black (foreground)
	auto *pal = reinterpret_cast<RGBQUAD *>(pBuf + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER));
	pal[0] = {255, 255, 255, 0}; // white
	pal[1] = {  0,   0,   0, 0}; // black

	// Pixel data: bottom-up scanlines, MSB = leftmost pixel
	BYTE *pixData = pBuf + headerBytes;
	for (UINT y = 0; y < h; ++y) {
		BYTE *row = pixData + (h - 1 - y) * rowStride; // bottom-up
		for (UINT x = 0; x < w; ++x) {
			Gdiplus::Color c;
			m_pimgCaptcha->GetPixel(x, y, &c);
			if (c.GetR() < 128) // black pixel → palette index 1
				row[x / 8] |= (0x80u >> (x % 8));
		}
	}

	file.Write(pBuf, totalBytes);
	ASSERT(totalBytes > 100 && totalBytes < 1000);
	free(pBuf);
	return true;
}