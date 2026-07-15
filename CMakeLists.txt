cmake_minimum_required(VERSION 3.20)
project(eMule VERSION 0.72 LANGUAGES CXX RC)

# ---------------------------------------------------------------------------
# This build targets the original MFC/Windows application, as built today by
# srchybrid/emule.vcxproj (MSVC + static MFC/ATL). It is Windows-only.
#
# Third-party dependencies are expected as sibling directories of this repo
# (eMule/../<lib>), exactly as emule.vcxproj expects them - see
# srchybrid/CMakeLists.txt DEPENDENCY_LIBS for the precise paths/lib names.
# None of them are vendored in this checkout; configure will warn about
# whichever are missing (see check_thirdparty_dependencies()), and the link
# step will fail with a clear "file not found" for any that are still
# missing at build time.
# ---------------------------------------------------------------------------

if(NOT WIN32)
    message(FATAL_ERROR "eMule (this target) is an MFC/Windows application and can only be built on Windows with MSVC.")
endif()

set(THIRDPARTY_ROOT "${CMAKE_SOURCE_DIR}/.." CACHE PATH
    "Root directory containing sibling checkouts of cryptopp, id3lib, miniupnpc, resizablelib, zlib")

# ---------------------------------------------------------------------------
# mbedtls - vanilla git submodule (mbedtls/, with nested tf-psa-crypto/ and
# framework/ submodules), pinned to v4.0.0. Never edited in place; see
# mbedtls_overrides/README.md for how eMule's two required customizations
# (threading_alt.h and enabling MBEDTLS_THREADING_ALT) are supplied from
# outside the submodule instead, using mechanisms mbedtls itself documents
# for exactly this purpose.
# ---------------------------------------------------------------------------
set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_SOURCE_DIR}/mbedtls_overrides/mbedtls/emule_mbedtls_user_config.h"
    CACHE FILEPATH "" FORCE)
# mbedTLS 4.0 cross-checks the legacy config against the PSA crypto config
# and errors ("MBEDTLS_THREADING_ALT must be configured in psa/crypto_config.h")
# if a threading option is set on only one side - confirmed by an actual
# build attempt with only MBEDTLS_USER_CONFIG_FILE set above.
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "${CMAKE_SOURCE_DIR}/mbedtls_overrides/mbedtls/emule_psa_crypto_user_config.h"
    CACHE FILEPATH "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Don't build mbedtls's own example programs" FORCE)

# GEN_FILES defaults OFF on Windows (mbedtls's CMakeLists.txt assumes a
# release tarball there, which ships its generated sources pre-built). A git
# submodule checkout has none of them, so this must be forced ON - confirmed
# necessary by an actual configure attempt (failed on missing
# psa_crypto_driver_wrappers_no_static.c / error.c / ssl_debug_helpers_generated.c
# without it). Requires Python 3 on PATH.
set(GEN_FILES ON CACHE BOOL "Generate mbedtls's auto-generated sources (required for a submodule checkout)" FORCE)

# Directory-scoped (not target_include_directories): threading.c, compiled
# deep inside tf-psa-crypto's own CMake targets, needs to see this override
# directory too - include_directories() here is inherited by everything
# add_subdirectory()'d below, without having to chase mbedtls's internal
# target names across versions.
include_directories("${CMAKE_SOURCE_DIR}/mbedtls_overrides/mbedtls")

# ---------------------------------------------------------------------------
# Crypto++ - vanilla git submodule (cryptopp/, weidai11/cryptopp pinned to
# CRYPTOPP_8_9_0), built via our own cryptopp_build/CMakeLists.txt since the
# upstream repo ships no CMake support of its own (see that file for why).
# ---------------------------------------------------------------------------
add_subdirectory(cryptopp_build)

add_subdirectory(mbedtls)
add_subdirectory(srchybrid)
