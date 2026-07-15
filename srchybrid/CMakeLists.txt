cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Source list - read directly from emule.vcxproj (<ClCompile Include="...">)
# so this file can never drift from what the original Visual Studio project
# actually builds. 244 files as of the v0.72a restructure.
# ---------------------------------------------------------------------------
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/emule.vcxproj" _clcompile_lines
     REGEX "<ClCompile Include=\"[^\"]+\"")

set(EMULE_SOURCES "")
foreach(_line IN LISTS _clcompile_lines)
    string(REGEX REPLACE ".*<ClCompile Include=\"([^\"]+)\".*" "\\1" _src "${_line}")
    string(REPLACE "\\" "/" _src "${_src}")
    list(APPEND EMULE_SOURCES "${_src}")
endforeach()

list(LENGTH EMULE_SOURCES _n_sources)
message(STATUS "eMule: ${_n_sources} source files read from emule.vcxproj")

# ---------------------------------------------------------------------------
# Third-party dependencies - paths/lib names copied from the <Link>
# AdditionalDependencies list and <AdditionalIncludeDirectories> in
# emule.vcxproj. Sibling directories of this repo, none vendored here yet.
# ---------------------------------------------------------------------------
if(CMAKE_VS_PLATFORM_NAME)
    set(EMULE_PLATFORM_DIR "${CMAKE_VS_PLATFORM_NAME}")
elseif(CMAKE_GENERATOR_PLATFORM)
    set(EMULE_PLATFORM_DIR "${CMAKE_GENERATOR_PLATFORM}")
else()
    set(EMULE_PLATFORM_DIR "x64")
    message(WARNING "eMule: could not determine target platform (Win32/x64/ARM64) from the generator; "
                     "defaulting to x64. Pass -A <platform> (Visual Studio generator) to be explicit.")
endif()

set(DEPENDENCY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# mbedtls and cryptopp are built from source via add_subdirectory() in the
# top-level CMakeLists.txt (vanilla submodules, no prebuilt .lib - see
# there); linked below as CMake targets (MbedTLS::mbedtls, cryptopp) instead
# of fixed paths like the others. The rest are still expected as prebuilt
# libs at the same paths emule.vcxproj's AdditionalDependencies used, none
# vendored here yet.
set(ID3LIB_LIB        "${DEPENDENCY_ROOT}/id3lib/libprj/${EMULE_PLATFORM_DIR}/$<CONFIG>/id3lib.lib")
set(MINIUPNPC_LIB      "${DEPENDENCY_ROOT}/miniupnpc/msvc/${EMULE_PLATFORM_DIR}/$<CONFIG>/miniupnpc.lib")
set(RESIZABLELIB_LIB   "${DEPENDENCY_ROOT}/resizablelib/${EMULE_PLATFORM_DIR}/$<CONFIG>/resizablelib.lib")
set(ZLIB_LIB           "${DEPENDENCY_ROOT}/zlib/contrib/vstudio/vc/${EMULE_PLATFORM_DIR}/$<CONFIG>/zlib.lib")

set(THIRDPARTY_LIBS ${ID3LIB_LIB} ${MINIUPNPC_LIB} ${RESIZABLELIB_LIB} ${ZLIB_LIB})

# Configure-time sanity check (non-fatal): these paths are config-specific
# ($<CONFIG> generator expressions can't be evaluated here), so this only
# checks that each dependency's directory tree exists at all. The link step
# will fail with a precise "file not found" for anything still missing.
# mbedtls/cryptopp are excluded - submodules, checked by their own build, not by path.
foreach(_dep id3lib miniupnpc resizablelib zlib)
    if(NOT IS_DIRECTORY "${DEPENDENCY_ROOT}/${_dep}")
        message(WARNING "eMule: sibling dependency directory not found: ${DEPENDENCY_ROOT}/${_dep} "
                         "(expected to contain a prebuilt ${_dep} matching emule.vcxproj's AdditionalDependencies)")
    endif()
endforeach()

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
add_executable(emule WIN32 ${EMULE_SOURCES} emule.rc)

set_target_properties(emule PROPERTIES
    MFC_FLAG 2                                  # static MFC/ATL, matches UseOfMfc=Static
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "emule"
)

# Stdafx.h directly #includes <afximpl.h>, an MFC *implementation* header
# under ATLMFC\src\mfc - not part of the public ATLMFC\include tree that
# MFC_FLAG wires in automatically. The vcxproj covers this via the
# MSBuild-only $(VC_ATLMFC_SourcePath) property; CMake has no equivalent, so
# it's reconstructed from the compiler path. Confirmed necessary by an actual
# build: without it, PCH generation fails with C1083 on afximpl.h.
if(MSVC)
    get_filename_component(_cl_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)   # .../bin/HostX64/x64
    get_filename_component(_cl_dir "${_cl_dir}" DIRECTORY)              # .../bin/HostX64
    get_filename_component(_cl_dir "${_cl_dir}" DIRECTORY)              # .../bin
    get_filename_component(MSVC_TOOLSET_ROOT "${_cl_dir}" DIRECTORY)    # .../<toolset version>
    set(ATLMFC_SRC_MFC "${MSVC_TOOLSET_ROOT}/ATLMFC/src/mfc")
endif()

# mbedtls/tf-psa-crypto include dirs and the MBEDTLS_USER_CONFIG_FILE define
# (which is what makes MBEDTLS_THREADING_ALT visible here too, not just when
# the mbedtls library itself is built) both come in transitively via linking
# against MbedTLS::mbedtls below - it declares them PUBLIC. Only the
# threading_alt.h override directory is added explicitly, via
# include_directories() in the top-level CMakeLists.txt.
target_include_directories(emule PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${DEPENDENCY_ROOT}/id3lib/include
    ${ATLMFC_SRC_MFC}
)

target_compile_definitions(emule PRIVATE
    ID3LIB_LINKOPTION=1
    MINIUPNP_STATICLIB
    SUPPORT_LARGE_FILES
    UNICODE
    _UNICODE
    $<$<NOT:$<STREQUAL:${EMULE_PLATFORM_DIR},ARM64>>:XP_BUILD>
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
)

# WarningLevel=EnableAllWarnings in the vcxproj -> /Wall (very noisy: enables
# every MSVC warning, including ones off by default at /W4). Kept faithful
# to the original project rather than toned down.
target_compile_options(emule PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Wall>
    $<$<CXX_COMPILER_ID:MSVC>:/Zc:throwingNew>
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<STREQUAL:${EMULE_PLATFORM_DIR},ARM64>>:/Zc:enumTypes>
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Debug>>:/RTC1>
    $<$<CXX_COMPILER_ID:MSVC>:/Oi>                                    # IntrinsicFunctions (both configs)
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/Gy>           # FunctionLevelLinking
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/Oy>           # OmitFramePointers
)
# ASSUMPTION: the vcxproj's Release <ClCompile> block does not set <Optimization>
# explicitly. CMake's default CMAKE_CXX_FLAGS_RELEASE already includes /O2 /DNDEBUG,
# which we take as the intended behavior rather than overriding it.

# Precompiled header: Stdafx.cpp creates it, all files use it except
# Parser.cpp/Scanner.cpp which declare <PrecompiledHeader /> (NotUsing) in
# the vcxproj.
target_precompile_headers(emule PRIVATE Stdafx.h)
set_source_files_properties(Parser.cpp Scanner.cpp PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

# ---------------------------------------------------------------------------
# Linking
# ---------------------------------------------------------------------------
target_link_libraries(emule PRIVATE
    ADSIId.lib
    crypt32.lib
    delayimp.lib
    iphlpapi.lib
    version.lib
    winmm.lib
    ws2_32.lib
    MbedTLS::mbedtls
    cryptopp
    ${THIRDPARTY_LIBS}
)

target_link_options(emule PRIVATE
    /DELAYLOAD:gdiplus.dll
    /DELAYLOAD:msimg32.dll
    /DELAYLOAD:oleacc.dll
    /DELAYLOAD:ws2_32.dll
    /NODEFAULTLIB:mpr.lib
    /NODEFAULTLIB:rasapi32.lib
    /NODEFAULTLIB:secur32.lib
    /NODEFAULTLIB:sensapi.lib
    /NODEFAULTLIB:vfw32.lib
    $<$<STREQUAL:${EMULE_PLATFORM_DIR},Win32>:/SAFESEH>
    "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/res/emule${EMULE_PLATFORM_DIR}.manifest"
)
# WIN32 on add_executable() already implies /SUBSYSTEM:WINDOWS.

# ---------------------------------------------------------------------------
# Optional: regenerate Parser.cpp/Scanner.cpp from their grammar/lexer
# sources. Not part of the default build - emule.vcxproj also marks this
# CustomBuild step ExcludedFromBuild=true; the generated .cpp files are
# committed and used as-is.
# ---------------------------------------------------------------------------
find_program(BISON_EXECUTABLE bison)
find_program(FLEX_EXECUTABLE flex)

if(BISON_EXECUTABLE)
    add_custom_target(regen_parser
        COMMAND ${BISON_EXECUTABLE} --no-lines --defines --output "${CMAKE_CURRENT_SOURCE_DIR}/Parser.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/Parser.y"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Regenerating Parser.cpp/.hpp from Parser.y (not part of the default build)"
    )
endif()

if(FLEX_EXECUTABLE)
    add_custom_target(regen_scanner
        COMMAND ${FLEX_EXECUTABLE} -L -o"${CMAKE_CURRENT_SOURCE_DIR}/Scanner.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/Scanner.l"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Regenerating Scanner.cpp from Scanner.l (not part of the default build)"
    )
endif()

# ---------------------------------------------------------------------------
# Known scope gap: the vcxproj also defines a third configuration,
# _SpecialBootstrapNodes (Debug settings + _BOOTSTRAPNODESDAT, always linked
# against the *Debug* third-party libs regardless of $(Configuration)). Not
# implemented as a genuine third CMAKE_CONFIGURATION_TYPES entry here - out
# of scope for a Debug/Release CI build of the mainline application. Add it
# back as a real custom configuration type if that special build is needed.
# ---------------------------------------------------------------------------
