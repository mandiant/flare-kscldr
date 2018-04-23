#pragma once

/* For user-space applications, need <WinIoCtl.h> for IOCTLs */
#ifndef _NTDDK_
#include <WinIoCtl.h>
#endif

#define KSCLDR_DESCRIPTION_W                        L"FLARE kernel shellcode loader"
#define KSCLDR_DESCRIPTION_A                        "FLARE kernel shellcode loader"

#define KSCLDR_SERVICE_NAME_W                       L"kscldr"
#define KSCLDR_SERVICE_NAME_A                       "kscldr"

#define KSCLDR_FILE_NAME_W                          L"kscldr.sys"
#define KSCLDR_FILE_NAME_A                          "kscldr.sys"

#define KSCLDR_LINK_NAME_W                          L"\\??\\kscldr"
#define KSCLDR_LINK_NAME_A                          "\\??\\kscldr"

#define KSCLDR_FUNCTION_BASE                        0x800
#define KSCLDR_FUNCTION_SET_MAX_LENGTH              (KSCLDR_FUNCTION_BASE + 0)
#define KSCLDR_FUNCTION_SET_BREAKPOINT_DISPOSITION  (KSCLDR_FUNCTION_BASE + 1)
#define KSCLDR_FUNCTION_CALL                        (KSCLDR_FUNCTION_BASE + 2)

#define IOCTL_kscldr_setmaxlength \
    CTL_CODE( \
            FILE_DEVICE_UNKNOWN, \
            KSCLDR_FUNCTION_SET_MAX_LENGTH, \
            METHOD_BUFFERED, \
            FILE_WRITE_DATA \
       )

#define IOCTL_kscldr_setbreakpointdisposition \
    CTL_CODE( \
            FILE_DEVICE_UNKNOWN, \
            KSCLDR_FUNCTION_SET_BREAKPOINT_DISPOSITION, \
            METHOD_BUFFERED, \
            FILE_WRITE_DATA \
       )

#define IOCTL_kscldr_callsc \
    CTL_CODE( \
            FILE_DEVICE_UNKNOWN, \
            KSCLDR_FUNCTION_CALL, \
            METHOD_BUFFERED, \
            FILE_EXECUTE \
       )
