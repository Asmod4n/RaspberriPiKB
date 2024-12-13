cmake_minimum_required(VERSION 3.16)

project(PiKb)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
add_compile_definitions(_GNU_SOURCE)

option(DEBUG "Show Debug Output" OFF)

if(NOT HOOK_PATH)
    set(HOOK_PATH "~/PiKbhook.sh" CACHE STRING "Path to .sh toggle hook")
endif()

if(NOT KEYBOARD_VID)
    set(KEYBOARD_VID "0x04d9" CACHE STRING "Vendor ID for keyboard")
endif()

if(NOT KEYBOARD_PID)
    set(KEYBOARD_PID "0x0007" CACHE STRING "Product ID for keyboard")
endif()

if(NOT KEYBOARD_DEV)
    set(KEYBOARD_DEV "/dev/input/by-id/usb-_Raspberry_Pi_Internal_Keyboard-event-kbd" CACHE STRING "Device path for keyboard")
endif()

add_library(libusbgx INTERFACE)
target_sources(libusbgx INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/usbg_common_libconfig.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/usbg_common.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/usbg_error.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/usbg_schemes_libconfig.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/usbg.c

    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/ether.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/ffs.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/hid.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/loopback.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/midi.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/ms.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/phonet.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/serial.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/uac2.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/uvc.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/printer.c
    ${CMAKE_CURRENT_LIST_DIR}/libusbgx/src/function/9pfs.c
)


target_include_directories(libusbgx INTERFACE ${CMAKE_CURRENT_LIST_DIR}/libusbgx/include)
target_include_directories(libusbgx INTERFACE ${CMAKE_CURRENT_BINARY_DIR})

target_compile_definitions(libusbgx INTERFACE HAS_GADGET_SCHEMES)

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/libusbgx/include/usbg/usbg_version.h.in)
    set(USBG_VERSION_HEX "0x00000000")
    configure_file(${CMAKE_CURRENT_LIST_DIR}/libusbgx/include/usbg/usbg_version.h.in ${CMAKE_CURRENT_BINARY_DIR}/usbg_version.h @ONLY)
else()
    message(FATAL_ERROR "Missing usbg_version.h.in. Did you forget to `git submodule update --init`?")
endif()

find_library(libconfig libconfig)
find_library(liburing liburing)

target_link_libraries(libusbgx INTERFACE config)

add_executable(
    PiKb
    PiKb.c
    gadget-hid.c
)

target_compile_definitions(PiKb PRIVATE
    HAS_GADGET_SCHEMES

    HOOK_PATH="${HOOK_PATH}"

    KEYBOARD_VID=${KEYBOARD_VID}
    KEYBOARD_PID=${KEYBOARD_PID}
    KEYBOARD_DEV="${KEYBOARD_DEV}"
)

if(DEBUG)
    target_compile_definitions(PiKb PRIVATE DEBUG)
endif()

target_link_libraries(PiKb libusbgx uring)

install(FILES
    ${CMAKE_CURRENT_LIST_DIR}/hook.sh
    ${CMAKE_CURRENT_LIST_DIR}/PiKb.service
    ${CMAKE_CURRENT_LIST_DIR}/README.md
    DESTINATION .
)

install(TARGETS PiKb DESTINATION .)

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_GENERATOR "ZIP" "TGZ")
include(CPack)
