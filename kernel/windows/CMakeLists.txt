cmake_minimum_required(VERSION 3.20)
project(AegisFusionDriver LANGUAGES C)

set(WDK_ROOT "$ENV{WDK_ROOT}" CACHE PATH "WDK root")
if(NOT WDK_ROOT)
    set(WDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
endif()

set(WDK_VERSION "$ENV{WDK_VERSION}" CACHE STRING "WDK version")
if(NOT WDK_VERSION)
    file(GLOB WDK_VERSIONS RELATIVE "${WDK_ROOT}/Include" "${WDK_ROOT}/Include/*")
    list(FILTER WDK_VERSIONS INCLUDE REGEX "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")
    list(SORT WDK_VERSIONS)
    list(GET WDK_VERSIONS -1 WDK_VERSION)
endif()

set(WDK_INCLUDE "${WDK_ROOT}/Include/${WDK_VERSION}")
set(WDK_LIB "${WDK_ROOT}/Lib/${WDK_VERSION}")
set(WDF_ROOT "${WDK_ROOT}/Include/wdf")
set(WDF_INCLUDE "")

if(NOT EXISTS "${WDK_INCLUDE}/km")
    message(FATAL_ERROR "WDK headers not found at ${WDK_INCLUDE}. Set WDK_ROOT/WDK_VERSION.")
endif()

if(EXISTS "${WDF_ROOT}/kmdf")
    file(GLOB WDF_VERSIONS RELATIVE "${WDF_ROOT}/kmdf" "${WDF_ROOT}/kmdf/*")
    list(SORT WDF_VERSIONS)
    list(GET WDF_VERSIONS -1 WDF_VERSION)
    set(WDF_INCLUDE "${WDF_ROOT}/kmdf/${WDF_VERSION}")
endif()

add_library(AegisFusion MODULE
    driver/aegis_driver.c
)

target_include_directories(AegisFusion PRIVATE
    "${WDK_INCLUDE}/km"
    "${WDK_INCLUDE}/shared"
    "${WDK_INCLUDE}/um"
    "${CMAKE_CURRENT_SOURCE_DIR}/inc"
    "${WDF_INCLUDE}"
)

target_link_directories(AegisFusion PRIVATE
    "${WDK_LIB}/km/x64"
)

target_compile_definitions(AegisFusion PRIVATE
    _WIN64
    _AMD64_
    AMD64
    UNICODE
    _UNICODE
    POOL_NX_OPTIN=1
)

target_compile_options(AegisFusion PRIVATE
    /kernel
    /GS
    /W3
    /Zp8
)

target_link_libraries(AegisFusion
    ntoskrnl
    hal
    fltMgr
    wdmsec
    BufferOverflowK
)

set_target_properties(AegisFusion PROPERTIES
    OUTPUT_NAME "AegisFusion"
    SUFFIX ".sys"
)

target_link_options(AegisFusion PRIVATE
    /DRIVER
    /SUBSYSTEM:NATIVE
    /ENTRY:DriverEntry
    /MANIFEST:NO
    /NODEFAULTLIB
)
