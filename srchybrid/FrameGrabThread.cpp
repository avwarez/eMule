//this file is part of eMule
//Copyright (C)2003-2024 Merkur ( devs@emule-project.net / https://www.emule-project.net )
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
#include <atlimage.h>
#include <vector>
#include "quantize.h"
#include "FrameGrabThread.h"
#include "OtherFunctions.h"
#ifndef HAVE_QEDIT_H
// This is a remote feature and not optional, in order to keep to working properly for other clients who want to use it
// Check emule_site_config.h to fix it
#error Missing 'qedit.h', look at "emule_site_config.h" for further information.
#endif

// DirectShow MediaDet
#include <strmif.h>
#define _DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
		EXTERN_C const GUID DECLSPEC_SELECTANY name \
				= { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
_DEFINE_GUID(MEDIATYPE_Video, 0x73646976, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
_DEFINE_GUID(MEDIATYPE_Audio, 0x73647561, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
_DEFINE_GUID(FORMAT_VideoInfo, 0x05589f80, 0xc356, 0x11ce, 0xbf, 0x01, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a);
_DEFINE_GUID(FORMAT_WaveFormatEx, 0x05589f81, 0xc356, 0x11ce, 0xbf, 0x01, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a);
//#define MMNODRV		// mmsystem: Installable driver support
#define MMNOSOUND		// mmsystem: Sound support
//#define MMNOWAVE		// mmsystem: Waveform support
#define MMNOMIDI		// mmsystem: MIDI support
#define MMNOAUX			// mmsystem: Auxiliary audio support
#define MMNOMIXER		// mmsystem: Mixer support
#define MMNOTIMER		// mmsystem: Timer support
#define MMNOJOY			// mmsystem: Joystick support
#define MMNOMCI			// mmsystem: MCI support
//#define MMNOMMIO		// mmsystem: Multimedia file I/O support
#define MMNOMMSYSTEM	// mmsystem: General MMSYSTEM functions
// NOTE: If you get a compile error due to missing 'qedit.h', look at "emule_site_config.h" for further information.
#include <qedit.h>
typedef struct tagVIDEOINFOHEADER
{
	RECT            rcSource;          // The bit we really want to use
	RECT            rcTarget;          // Where the video should go
	DWORD           dwBitRate;         // Approximate bit data rate
	DWORD           dwBitErrorRate;    // Bit error rate for this stream
	REFERENCE_TIME  AvgTimePerFrame;   // Average time per frame (100ns units)
	BITMAPINFOHEADER bmiHeader;
} VIDEOINFOHEADER;
#include "emuledlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


IMPLEMENT_DYNCREATE(CFrameGrabThread, CWinThread)

BEGIN_MESSAGE_MAP(CFrameGrabThread, CWinThread)
END_MESSAGE_MAP()

CFrameGrabThread::CFrameGrabThread()
	: imgResults()
	, pOwner()
	, pSender()
	, dStartTime()
	, nMaxWidth()
	, nFramesToGrab()
	, bReduceColor()
{
}

BOOL CFrameGrabThread::InitInstance()
{
	DbgSetThreadName("FrameGrabThread");
	InitThreadLocale();
	return TRUE;
}

BOOL CFrameGrabThread::Run()
{
	imgResults = new HBITMAP[nFramesToGrab]{};
	FrameGrabResult_Struct *result = new FrameGrabResult_Struct;
	(void)CoInitialize(NULL);
	result->nImagesGrabbed = (uint8)GrabFrames();
	CoUninitialize();
	result->imgResults = imgResults;
	result->pSender = pSender;
	if (!theApp.emuledlg->PostMessage(TM_FRAMEGRABFINISHED, (WPARAM)pOwner, (LPARAM)result)) {
		for (int i = (int)result->nImagesGrabbed; --i >= 0;)
			::DeleteObject(result->imgResults[i]);
		delete[] result->imgResults;
		delete result;
	}
	return 0;
}

UINT CFrameGrabThread::GrabFrames()
{
#define TIMEBETWEENFRAMES	50.0 // could be a param later, if needed
	try {
		HRESULT hr;
		CComPtr<IMediaDet> pDet;
		hr = pDet.CoCreateInstance(__uuidof(MediaDet));
		if (!SUCCEEDED(hr))
			return 0;

		// Convert the file name to a BSTR.
		CComBSTR bstrFilename(strFileName);
		pDet->put_Filename(bstrFilename);

		long lStreams;
		bool bFound = false;
		pDet->get_OutputStreams(&lStreams);
		for (long i = 0; i < lStreams; ++i) {
			GUID major_type;
			pDet->put_CurrentStream(i);
			pDet->get_StreamType(&major_type);
			if (major_type == MEDIATYPE_Video) {
				bFound = true;
				break;
			}
		}

		if (!bFound)
			return 0;

		double dLength = 0;
		pDet->get_StreamLength(&dLength);
		if (dStartTime > dLength)
			dStartTime = 0;

		long width = 0, height = 0;
		AM_MEDIA_TYPE mt;
		hr = pDet->get_StreamMediaType(&mt);
		if (mt.formattype != FORMAT_VideoInfo)
			return 0; // Should not happen, in theory.

		VIDEOINFOHEADER *pVih = (VIDEOINFOHEADER*)(mt.pbFormat);
		width = pVih->bmiHeader.biWidth;
		height = pVih->bmiHeader.biHeight;

		// We want the absolute height, don't care about orientation.
		if (height < 0)
			height = -height;

		/*FreeMediaType(mt); = */
		if (mt.cbFormat != 0) {
			::CoTaskMemFree((PVOID)mt.pbFormat);
			mt.cbFormat = 0;
			mt.pbFormat = NULL;
		}
		if (mt.pUnk != NULL) {
			mt.pUnk->Release();
			mt.pUnk = NULL;
		}
		/**/

		uint32 nFramesGrabbed;
		for (nFramesGrabbed = 0; nFramesGrabbed < nFramesToGrab; ++nFramesGrabbed) {
			long size;
			hr = pDet->GetBitmapBits(dStartTime + (nFramesGrabbed * TIMEBETWEENFRAMES), &size, NULL, width, height);
			if (SUCCEEDED(hr)) {
				// we could also directly create a Bitmap in memory, however this caused problems/failed with *some* movie files
				// when I tried it for the MMPreview, while this method works always - so I'll continue to use this one
				uint32_t nFullBufferLen = static_cast<uint32_t>(sizeof(BITMAPFILEHEADER) + size);
				char *buffer = new char[nFullBufferLen];

				BITMAPFILEHEADER *pHdr = reinterpret_cast<BITMAPFILEHEADER*>(buffer);
				memset(buffer, 0, sizeof(BITMAPFILEHEADER));
				pHdr->bfType = 'MB';
				pHdr->bfSize = nFullBufferLen;
				pHdr->bfOffBits = sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER);

				try {
					hr = pDet->GetBitmapBits(dStartTime + nFramesGrabbed * TIMEBETWEENFRAMES, NULL, &buffer[sizeof(BITMAPFILEHEADER)], width, height);
				} catch (...) {
					ASSERT(0);
					hr = E_FAIL;
				}

				if (FAILED(hr)) {
					delete[] buffer;
					break;
				}

				// decode BMP from memory using GDI+
				ULONG_PTR gdipToken = 0;
				Gdiplus::GdiplusStartupInput gdipInput;
				if (Gdiplus::GdiplusStartup(&gdipToken, &gdipInput, NULL) != Gdiplus::Ok) {
					delete[] buffer;
					break;
				}

				Gdiplus::Bitmap *imgResult = nullptr;
				{
					IStream *pStream = nullptr;
					if (SUCCEEDED(CreateStreamOnHGlobal(NULL, TRUE, &pStream))) {
						ULONG written = 0;
						pStream->Write(buffer, nFullBufferLen, &written);
						LARGE_INTEGER li = {};
						pStream->Seek(li, STREAM_SEEK_SET, nullptr);
						imgResult = Gdiplus::Bitmap::FromStream(pStream);
						pStream->Release();
					}
				}
				delete[] buffer;

				if (!imgResult || imgResult->GetLastStatus() != Gdiplus::Ok) {
					delete imgResult;
					Gdiplus::GdiplusShutdown(gdipToken);
					break;
				}

				// resize if needed
				if (nMaxWidth > 0 && (int)imgResult->GetWidth() > nMaxWidth) {
					float scale = (float)nMaxWidth / (float)imgResult->GetWidth();
					int nNewH = (int)(imgResult->GetHeight() * scale);
					Gdiplus::Bitmap *resized = new Gdiplus::Bitmap(nMaxWidth, nNewH, PixelFormat24bppRGB);
					Gdiplus::Graphics g(resized);
					g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBilinear);
					g.DrawImage(imgResult, 0, 0, nMaxWidth, nNewH);
					delete imgResult;
					imgResult = resized;
				}

				// decrease bpp if needed (quantize to 8bpp palette)
				if (bReduceColor) {
					UINT w = imgResult->GetWidth(), h = imgResult->GetHeight();
					int rowBytes = ((w * 3 + 3) / 4) * 4; // DWORD-aligned 24bpp row

					// Build a DIB buffer for CQuantizer (BITMAPINFOHEADER + bottom-up 24bpp pixels)
					std::vector<BYTE> dib24(sizeof(BITMAPINFOHEADER) + rowBytes * h, 0);
					auto *bih24 = reinterpret_cast<BITMAPINFOHEADER*>(dib24.data());
					bih24->biSize = sizeof(BITMAPINFOHEADER);
					bih24->biWidth = (LONG)w; bih24->biHeight = (LONG)h;
					bih24->biPlanes = 1; bih24->biBitCount = 24; bih24->biCompression = BI_RGB;

					Gdiplus::BitmapData srcData;
					Gdiplus::Rect rect(0, 0, w, h);
					if (imgResult->LockBits(&rect, Gdiplus::ImageLockModeRead, PixelFormat24bppRGB, &srcData) == Gdiplus::Ok) {
						BYTE *pixBase = dib24.data() + sizeof(BITMAPINFOHEADER);
						for (UINT y = 0; y < h; ++y) {
							// flip to bottom-up for CQuantizer
							BYTE *src = (BYTE*)srcData.Scan0 + (int)y * srcData.Stride;
							memcpy(pixBase + (h - 1 - y) * rowBytes, src, w * 3);
						}
						imgResult->UnlockBits(&srcData);
					}

					RGBQUAD pal[256] = {};
					CQuantizer q(256, 8);
					q.ProcessImage(dib24.data());
					q.SetColorTable(pal);
					UINT nColors = q.GetColorCount();

					// Build 8bpp indexed GDI+ Bitmap
					Gdiplus::Bitmap *indexed = new Gdiplus::Bitmap(w, h, PixelFormat8bppIndexed);
					size_t palSize = sizeof(Gdiplus::ColorPalette) + (nColors > 0 ? nColors - 1 : 0) * sizeof(Gdiplus::ARGB);
					auto *gdipPal = (Gdiplus::ColorPalette*)malloc(palSize);
					if (gdipPal) {
						gdipPal->Flags = 0; gdipPal->Count = nColors;
						for (UINT k = 0; k < nColors; ++k)
							gdipPal->Entries[k] = Gdiplus::Color::MakeARGB(255, pal[k].rgbRed, pal[k].rgbGreen, pal[k].rgbBlue);
						indexed->SetPalette(gdipPal);
						free(gdipPal);
					}

					// Map each pixel to nearest palette entry
					Gdiplus::BitmapData idxData;
					if (indexed->LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat8bppIndexed, &idxData) == Gdiplus::Ok) {
						if (imgResult->LockBits(&rect, Gdiplus::ImageLockModeRead, PixelFormat24bppRGB, &srcData) == Gdiplus::Ok) {
							for (UINT y = 0; y < h; ++y) {
								BYTE *src = (BYTE*)srcData.Scan0 + (int)y * srcData.Stride;
								BYTE *dst = (BYTE*)idxData.Scan0 + (int)y * idxData.Stride;
								for (UINT x = 0; x < w; ++x, src += 3) {
									BYTE b = src[0], g2 = src[1], r = src[2]; // GDI+ 24bpp = BGR
									BYTE best = 0; int bestDist = INT_MAX;
									for (UINT k = 0; k < nColors; ++k) {
										int dr = r - pal[k].rgbRed, dg = g2 - pal[k].rgbGreen, db = b - pal[k].rgbBlue;
										int dist = dr*dr + dg*dg + db*db;
										if (dist < bestDist) { bestDist = dist; best = (BYTE)k; }
									}
									dst[x] = best;
								}
							}
							imgResult->UnlockBits(&srcData);
						}
						indexed->UnlockBits(&idxData);
					}
					delete imgResult;
					imgResult = indexed;
				}

				// Convert GDI+ Bitmap to HBITMAP (white background for any transparent areas)
				HBITMAP hbmp = NULL;
				imgResult->GetHBITMAP(Gdiplus::Color(255, 255, 255), &hbmp);
				delete imgResult;
				Gdiplus::GdiplusShutdown(gdipToken);

				if (!hbmp)
					break;

				// done
				imgResults[nFramesGrabbed] = hbmp;
			}
		}
		return nFramesGrabbed;
	} catch (...) {
		ASSERT(0);
	}
	return 0;
}

void CFrameGrabThread::SetValues(const CKnownFile *in_pOwner, const CString &in_strFileName, uint8 in_nFramesToGrab, double in_dStartTime, bool in_bReduceColor, uint16 in_nMaxWidth, void *in_pSender)
{
	strFileName = in_strFileName;
	nFramesToGrab = in_nFramesToGrab;
	dStartTime = in_dStartTime;
	bReduceColor = in_bReduceColor;
	nMaxWidth = in_nMaxWidth;
	pOwner = in_pOwner;
	pSender = in_pSender;
}