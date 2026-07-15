cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Crypto++ (weidai11/cryptopp @ CRYPTOPP_8_9_0, vanilla submodule at
# eMule/cryptopp) has no CMakeLists.txt of its own - only cryptlib.vcxproj
# (MSVC) and GNUmakefile. Rather than pull in a third-party CMake wrapper,
# this file is our own, transcribed directly from cryptlib.vcxproj's
# Debug/Release (static lib) configuration - the DLL-Import configs and
# cryptest/cryptdll projects are not needed here and were skipped. As with
# mbedtls, the submodule itself is never edited.
# ---------------------------------------------------------------------------
set(CRYPTOPP_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../cryptopp")

# Source list - read directly from cryptlib.vcxproj so this can never drift.
# Order matters for the first 3 (cryptlib.cpp, cpu.cpp, integer.cpp - see the
# vcxproj's own "The order of the first three matters" comment), so they're
# read as an ordered slice rather than alphabetically re-sorted.
file(STRINGS "${CRYPTOPP_SRC_DIR}/cryptlib.vcxproj" _clcompile_lines
     REGEX "<ClCompile Include=\"[^\"]+\\.cpp\"")

set(CRYPTOPP_SOURCES "")
foreach(_line IN LISTS _clcompile_lines)
    string(REGEX REPLACE ".*<ClCompile Include=\"([^\"]+)\".*" "\\1" _src "${_line}")
    list(APPEND CRYPTOPP_SOURCES "${_src}")
endforeach()

# eccrypto.cpp/eprecomp.cpp: <ExcludedFromBuild>true</ExcludedFromBuild>
# unconditionally in the vcxproj (superseded by ecp.cpp/ec2n.cpp - kept out
# of the build there too). pch.cpp: only `#include "pch.h"`, a stub whose
# sole purpose is to be the MSBuild-recognized PCH-creation translation
# unit; target_precompile_headers() below creates CMake's own PCH object
# instead, so this stub is compiled by neither.
list(REMOVE_ITEM CRYPTOPP_SOURCES eccrypto.cpp eprecomp.cpp pch.cpp)

list(TRANSFORM CRYPTOPP_SOURCES PREPEND "${CRYPTOPP_SRC_DIR}/")

list(LENGTH CRYPTOPP_SOURCES _n_sources)
message(STATUS "cryptopp: ${_n_sources} source files read from cryptlib.vcxproj")

# ---------------------------------------------------------------------------
# MASM sources (rdrand/rdseed hardware RNG support, low-level x64 helpers).
# cryptlib.vcxproj only defines Win32/x64 configurations - no ARM64 - so
# these are skipped there, consistent with upstream never having shipped an
# ARM64 config for them.
# ---------------------------------------------------------------------------
set(CRYPTOPP_ASM_SOURCES "")
if(CMAKE_VS_PLATFORM_NAME)
    set(_cryptopp_platform "${CMAKE_VS_PLATFORM_NAME}")
else()
    set(_cryptopp_platform "x64")
endif()

if(_cryptopp_platform STREQUAL "Win32" OR _cryptopp_platform STREQUAL "x64")
    enable_language(ASM_MASM)
    list(APPEND CRYPTOPP_ASM_SOURCES
        "${CRYPTOPP_SRC_DIR}/rdrand.asm"
        "${CRYPTOPP_SRC_DIR}/rdseed.asm"
    )
    if(_cryptopp_platform STREQUAL "x64")
        list(APPEND CRYPTOPP_ASM_SOURCES
            "${CRYPTOPP_SRC_DIR}/x64dll.asm"
            "${CRYPTOPP_SRC_DIR}/x64masm.asm"
        )
    endif()
    # cryptlib.vcxproj passes _M_X86/_M_X64 explicitly on the ml/ml64 command
    # line (its default preprocessor set doesn't include it the way ClCompile's
    # does) - CMake's ASM_MASM flags need the same.
    if(_cryptopp_platform STREQUAL "Win32")
        set_source_files_properties(${CRYPTOPP_ASM_SOURCES} PROPERTIES COMPILE_OPTIONS "/D_M_X86")
    else()
        set_source_files_properties(${CRYPTOPP_ASM_SOURCES} PROPERTIES COMPILE_OPTIONS "/D_M_X64")
    endif()
endif()

add_library(cryptopp STATIC ${CRYPTOPP_SOURCES} ${CRYPTOPP_ASM_SOURCES})

if(CRYPTOPP_ASM_SOURCES)
    # The VS generator's MASM custom-build step (unlike ClCompile) does not
    # create its own output directory: for a source outside this
    # CMakeLists.txt's own tree, the object path resolves to
    # <IntDir>/__/cryptopp/<file>.obj ("__" is CMake's escape for the ".."
    # in the relative path) and ml64.exe fails with "cannot open file"
    # because that directory doesn't exist yet. Confirmed by an actual
    # build attempt; this pre-build step creates it first.
    add_custom_command(TARGET cryptopp PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:cryptopp>/../cryptopp.dir/$<CONFIG>/__/cryptopp"
    )
endif()

set_target_properties(cryptopp PROPERTIES
    OUTPUT_NAME "cryptlib"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    INTERPROCEDURAL_OPTIMIZATION ON               # WholeProgramOptimization=true
)

target_include_directories(cryptopp PUBLIC "${CRYPTOPP_SRC_DIR}")

target_compile_definitions(cryptopp PRIVATE
    USE_PRECOMPILED_HEADERS
    $<$<CONFIG:Release>:NDEBUG>
)

# COMPILE_LANGUAGE:CXX guards every flag here - without it, these (pure
# C++-compiler) options also get handed to ml64.exe/ml.exe for the .asm
# sources above, which rejects all of them (A4018 "invalid command-line
# option"). Confirmed by an actual build attempt.
target_compile_options(cryptopp PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:MSVC>:/W4>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:MSVC>:/wd4231>>   # DisableSpecificWarnings in the vcxproj
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:MSVC>:/wd4251>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:MSVC>:/wd4275>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:MSVC>:/wd4355>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<CXX_COMPILER_ID:MSVC>:/wd4505>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Debug>>:/RTC1>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Debug>>:/Oi>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/Oy>>              # OmitFramePointers
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/Oi>>
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/Ob2>>             # InlineFunctionExpansion=AnySuitable
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/Gy>>              # FunctionLevelLinking
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/GF>>              # StringPooling
    # X86 Configuration in the vcxproj: EnableEnhancedInstructionSet=SSE2,
    # for the whole Win32 platform (x64 has no such override - SSE2 is the
    # x64 baseline already).
    $<$<COMPILE_LANGUAGE:CXX>:$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<STREQUAL:${_cryptopp_platform},Win32>>:/arch:SSE2>>
)

# chacha_avx.cpp: EnableEnhancedInstructionSet=AdvancedVectorExtensions2 for
# this one file only (excluded on the pre-2013 toolsets the vcxproj still
# guards for; not applicable to any toolset we target).
set_source_files_properties("${CRYPTOPP_SRC_DIR}/chacha_avx.cpp" PROPERTIES
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:MSVC>:/arch:AVX2>"
)

target_precompile_headers(cryptopp PRIVATE "${CRYPTOPP_SRC_DIR}/pch.h")
# dll.cpp/iterhash.cpp: <PrecompiledHeader /> (NotUsing) in the vcxproj.
set_source_files_properties(
    "${CRYPTOPP_SRC_DIR}/dll.cpp"
    "${CRYPTOPP_SRC_DIR}/iterhash.cpp"
    PROPERTIES SKIP_PRECOMPILE_HEADERS ON
)
