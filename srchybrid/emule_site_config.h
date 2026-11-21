#pragma once

#if !defined(UNICODE) || !defined(_UNICODE)
#error This application requires Unicode character set
#endif
// This file provides a way for local compiler site configurations (e.g. installed SDKs).

// By default, assume that we have all the SDKs which we need and enable all optional features.
#define	HAVE_SAPI_H
#define HAVE_QEDIT_H
#define HAVE_WMSDK_H

#if _MSC_VER<1937 //before VS2022 17.7
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

// Windows 10 is the minimum. sdkddkver.h derives WINVER, _WIN32_IE and NTDDI_VERSION
// from this, and would pick the same value on its own if it were left undefined.
#define _WIN32_WINNT 0x0A00
#include <sdkddkver.h>
