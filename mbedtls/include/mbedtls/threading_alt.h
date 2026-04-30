//this file is part of eMule
//Copyright (C)2017-2023 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
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
#ifdef _MSC_VER
#include <winsock2.h>

typedef struct
{
	CRITICAL_SECTION cs;
	char is_valid;
} mbedtls_threading_mutex_t;

/* Required by mbedtls test framework (threading_helpers.h/.c) when
 * MBEDTLS_THREADING_ALT is defined. eMule does not use mbedtls test threads,
 * but the framework files are compiled into the library, so this stub
 * satisfies the type requirement. */
typedef struct mbedtls_test_thread_t
{
	unsigned dummy;
} mbedtls_test_thread_t;

#endif