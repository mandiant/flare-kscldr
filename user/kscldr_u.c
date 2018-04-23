#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kscldr.h"
#include "kscldr_u.h"
#include "config.h"
#include "resource.h"

#pragma comment(lib, "advapi32")
#pragma comment(lib, "user32")

#define ERR_IF(_cond, _lbl, _func, ...) \
    do { \
        if (_cond) \
        { \
            _ftprintf( \
                stderr, \
                _T(_func) ## _T(" failed, %d\n"), \
                __VA_ARGS__, \
                GetLastError() \
               ); \
            goto _lbl; \
        } \
    } while (0,0)

typedef BOOL (WINAPI * pWow64DisableWow64FsRedirection_t)(
  PVOID *old_val
);

BOOL parseArgs(int argc, PTCHAR argv[], PTCHAR *pscf_name);
int usage(int err, PTCHAR argv0);
BOOL loadKernelShellCode(PTCHAR sc_fname);
BOOL uninstallService(SC_HANDLE hsvc);
BOOL startDriver(void);
BOOL stopDriver(void);
BOOL installDriver(SC_HANDLE hscm);
BOOL dropDriver(PTCHAR driver_path, DWORD bytes);
void interactiveWarning(void);

#if defined(_WIN64) && !_WIN64
// If compiled 32-bit...
BOOL DisableWow64FsVirtualization(void);
#endif // defined(_WIN64) && !_WIN64

int
_tmain(ULONG argc, PTCHAR argv[])
{
    PTCHAR sc_fname = NULL;

    if (!parseArgs(argc, argv, &sc_fname))
    {
        return usage(1, argv[0]);
    }

    interactiveWarning();

    return !loadKernelShellCode(sc_fname);
}

BOOL
parseArgs(int argc, PTCHAR argv[], PTCHAR *pscf_name)
{
    if (argc != 2)
    {
        return FALSE;
    }

    *pscf_name = argv[1];

    return TRUE;
}

int
usage(int err, PTCHAR argv0)
{
    FILE *out = err? stderr: stdout;
    _ftprintf(out, _T("Usage: %s scfile\n"), argv0);
    _ftprintf(out, _T("scfile is a binary file containing shellcode.\n"));
    return err;
}

void
interactiveWarning(void)
{
    int response = 0;

    response = MessageBox(
        NULL,

        _T("Running shellcode in the kernel can pose security risks or\n")
        _T("harm your system. Are you sure you want to proceed? If you\n")
        _T("are unsure, click NO to cancel."),

        _T("Security Warning"),
        MB_YESNO | MB_ICONEXCLAMATION | MB_SYSTEMMODAL |
        MB_DEFAULT_DESKTOP_ONLY | MB_SETFOREGROUND | MB_TOPMOST
       );

    if (response != IDYES)
    {
        _ftprintf(stderr, _T("User aborted\n"));
        ExitProcess(1);
    }
}

#if defined(_WIN64) && !_WIN64
BOOL
DisableWow64FsVirtualization(void)
{
    HANDLE hmod_k32 = NULL;
    BOOL ret = FALSE;
    PVOID old_val = 0;

    pWow64DisableWow64FsRedirection_t pWow64DisableWow64FsRedirection;

    hmod_k32 = LoadLibrary(_T("kernel32.dll"));
    ERR_IF(NULL == hmod_k32, exit, "LoadLibraryA(kernel32.dll)");

    pWow64DisableWow64FsRedirection = (pWow64DisableWow64FsRedirection_t)
            GetProcAddress(hmod_k32, "Wow64DisableWow64FsRedirection");
    ERR_IF(
        NULL == (void *)pWow64DisableWow64FsRedirection,
        exit,
        "GetProcAddress(Wow64DisableWow64FsRedirection)"
       );

    ret = pWow64DisableWow64FsRedirection(&old_val);

exit:
    return ret;
}
#endif // defined(_WIN64) && !_WIN64

BOOL
dropDriver(PTCHAR driver_path, DWORD max_driver_path)
{
    BOOL ret = FALSE;
    BOOL ok = FALSE;
    DWORD sys_dir_len = 0;
    DWORD len = 0;
    HRSRC hres_driver = NULL;
    HGLOBAL hdriver_bytes = NULL;
    const unsigned char *driver_bytes = NULL;
    HANDLE hfile = INVALID_HANDLE_VALUE;
    DWORD res_size = 0;
    DWORD bytes_xferred = 0;

    sys_dir_len = GetSystemDirectory(driver_path, max_driver_path);
    ERR_IF(0 == sys_dir_len, exit, "GetSystemDirectoryA");

    len = _stprintf_s(
        driver_path,
        max_driver_path,
        _T("%s\\%s\\%s"),
        driver_path,
        DRIVER_DIR,
        KSCLDR_FILE_NAME
       );
    ERR_IF(len <= 0, exit, "Composing driver path");

    hres_driver = FindResource(NULL, MAKEINTRESOURCE(RES_DRIVER), RT_RCDATA);
    ERR_IF(NULL == hres_driver, exit, "FindResource");

    res_size = SizeofResource(NULL, hres_driver);
    ERR_IF(0 == res_size, exit, "SizeofResource");

    hdriver_bytes = LoadResource(NULL, hres_driver);
    ERR_IF(NULL == hdriver_bytes, exit, "LoadResource");

    driver_bytes = LockResource(hdriver_bytes);
    ERR_IF(NULL == driver_bytes, exit, "LockResource");

#if !_WIN64
    ok = DisableWow64FsVirtualization();
    ERR_IF(!ok, exit, "DisableWow64FsVirtualization");
#endif // !_WIN64

    hfile = CreateFile(
        driver_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
       );
    ERR_IF(INVALID_HANDLE_VALUE == hfile, exit, "CreateFileA(%s)", driver_path);

    ok = WriteFile(hfile, driver_bytes, res_size, &bytes_xferred, NULL);
    ERR_IF(!ok, exit, "WriteFile(%s)", driver_path);

    ret = TRUE;

exit:
    if (hfile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hfile);
    }

    if (driver_bytes)
    {
        UnlockResource(driver_bytes);
    }

    return ret;
}

BOOL
installDriver(SC_HANDLE hscm)
{
    BOOL ret = FALSE;
    BOOL ok = FALSE;
    PTCHAR driver_path = NULL;
    DWORD driver_path_len = 0;
    SC_HANDLE hsvc = NULL;

    driver_path_len = MAX_PATH * sizeof(TCHAR);

    driver_path = malloc(driver_path_len);
    ERR_IF(NULL == driver_path, exit, "malloc(%d)", MAX_PATH);

    memset(driver_path, 0, driver_path_len);

    ok = dropDriver(driver_path, MAX_PATH);
    ERR_IF(!ok, exit, "dropDriver(%s)", KSCLDR_FILE_NAME_A);

    hsvc = CreateService(
        hscm,
        KSCLDR_SERVICE_NAME,
        KSCLDR_DESCRIPTION,
        SC_MANAGER_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driver_path,
        NULL /* lpLoadOrderGroup */,
        NULL /* lpdwTagId */,
        NULL /* lpDependencies */,
        NULL /* lpServiceStartName */,
        NULL /* lpPassword */
       );
    ERR_IF(NULL == hsvc, exit, "CreateService(%s)", KSCLDR_SERVICE_NAME_A);

    ret = TRUE;

exit:
    if (hsvc)
    {
        CloseServiceHandle(hsvc);
    }

    if (driver_path)
    {
        free(driver_path);
    }

    return ret;
}

BOOL
stopDriver(void)
{
    SC_HANDLE hsvc = NULL;
    SC_HANDLE hscm = NULL;
    BOOL ret = FALSE;
    BOOL ok = FALSE;
    SERVICE_STATUS svc_status = {0};

    hscm = OpenSCManager(
        NULL,
        SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_ALL_ACCESS
       );
    ERR_IF(NULL == hscm, exit, "OpenSCManager");

    hsvc = OpenService(hscm, KSCLDR_SERVICE_NAME, SC_MANAGER_ALL_ACCESS);
    ERR_IF(NULL == hsvc, exit, "OpenServiceA(%s)", KSCLDR_SERVICE_NAME_A);

    ok = ControlService(hsvc, SERVICE_CONTROL_STOP, &svc_status);
    ERR_IF(!ok, exit, "ControlService(SERVICE_CONTROL_STOP)");

    CloseServiceHandle(hsvc);

    ret = TRUE;

exit:
    return ret;
}

BOOL
uninstallService(SC_HANDLE hsvc)
{
    BOOL ret = FALSE;
    BOOL ok = FALSE;
    SERVICE_STATUS_PROCESS svc_status_ex = {0};
    SERVICE_STATUS svc_status = {0};
    DWORD bytes = 0;

    ok = QueryServiceStatusEx(
        hsvc,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&svc_status_ex,
        sizeof(svc_status_ex),
        &bytes
       );
    ERR_IF(!ok, exit, "QueryServiceStatusEx(%s)", KSCLDR_SERVICE_NAME_A);

    if (svc_status_ex.dwCurrentState != SERVICE_STOPPED)
    {
        ok = ControlService(hsvc, SERVICE_CONTROL_STOP, &svc_status);
        ERR_IF(!ok, exit, "ControlService(SERVICE_CONTROL_STOP)");

        // Wait for the service to stop
        do {
            ok = QueryServiceStatusEx(
                hsvc,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&svc_status_ex,
                sizeof(svc_status_ex),
                &bytes
               );
            ERR_IF(
                !ok,
                exit,
                "QueryServiceStatusEx(%s) #2",
                KSCLDR_SERVICE_NAME_A
               );

            if (svc_status_ex.dwCurrentState == SERVICE_STOPPED) {
                break;
            }

            Sleep(100);
        } while (svc_status_ex.dwCurrentState != SERVICE_STOPPED);
    }

    ok = DeleteService(hsvc);
    ERR_IF(!ok, exit, "DeleteService(%s)", KSCLDR_SERVICE_NAME_A);

    ret = TRUE;

exit:
    return ret;
}

/**
 * @fn
 * @return success value
 */
BOOL
startDriver(void)
{
    SC_HANDLE hscm = NULL;
    SC_HANDLE hsvc = NULL;
    BOOL ok = FALSE;
    BOOL ret = FALSE;

    hscm = OpenSCManager(
        NULL,
        SERVICES_ACTIVE_DATABASE,
        SC_MANAGER_ALL_ACCESS
       );
    ERR_IF(NULL == hscm, exit, "OpenSCManager");

    /* If the driver is already installed, get rid of its service registration.
     * This code is easier to comprehend than attempting to use the existing
     * service and recover from cases where the service registration or service
     * binary are corrupted due to tinkering. At the same time, this is more
     * robust than assuming that a leftover service installation will be in the
     * same (working) state that we left it in. */
    hsvc = OpenService(hscm, KSCLDR_SERVICE_NAME, SC_MANAGER_ALL_ACCESS);
    if (hsvc)
    {
        uninstallService(hsvc);
        CloseServiceHandle(hsvc);
    }

    ok = installDriver(hscm);
    ERR_IF(!ok, exit, "installDriver(%s) #2", KSCLDR_SERVICE_NAME_A);

    hsvc = OpenService(hscm, KSCLDR_SERVICE_NAME, SC_MANAGER_ALL_ACCESS);
    ERR_IF(!ok, exit, "OpenServiceA(%s)", KSCLDR_SERVICE_NAME_A);

    ok = StartService(hsvc, 0, NULL);
    ERR_IF(!ok, exit, "StartService(%s)", KSCLDR_SERVICE_NAME_A);

    ret = TRUE;

exit:
    if (hsvc != NULL)
    {
        CloseServiceHandle(hsvc);
    }

    if (hscm != NULL)
    {
        CloseServiceHandle(hscm);
    }

    return ret;
}

BOOL
loadKernelShellCode(PTCHAR sc_fname)
{
    HANDLE hdev = INVALID_HANDLE_VALUE;
    HANDLE hfile = INVALID_HANDLE_VALUE;
    HANDLE hfile_mapping = NULL;
    LPVOID sc = NULL;
    BOOL ok = FALSE;
    DWORD bytes_xferred = 0;
    BOOL ret = FALSE;
    LARGE_INTEGER file_size = {0};

    hfile = CreateFile(
        sc_fname,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
       );
    ERR_IF(INVALID_HANDLE_VALUE == hfile, exit, "CreateFile(%s)", sc_fname);

    hfile_mapping = CreateFileMapping(
        hfile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
       );
    ERR_IF(NULL == hfile_mapping, exit, "CreateFileMapping(%s)", sc_fname);

    sc = MapViewOfFile(hfile_mapping, FILE_MAP_READ, 0, 0, 0);
    ERR_IF(!sc, exit, "MapViewOfFile(%s)", sc_fname);

    ok = startDriver();
    ERR_IF(!ok, exit, "Start/install driver");

    hdev = CreateFile(
        KSCLDR_LINK_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
       );
    ERR_IF(
        INVALID_HANDLE_VALUE == hdev,
        exit,
        "CreateFile(%s)",
        KSCLDR_LINK_NAME_A
       );

    ok = GetFileSizeEx(hfile, &file_size);
    ERR_IF(!ok, exit, "GetFileSizeEx(%s)", KSCLDR_LINK_NAME_A);
    ERR_IF(file_size.HighPart != 0, exit, "Unsupported large file write");

    ok = WriteFile(hdev, sc, file_size.LowPart, &bytes_xferred, NULL);
    ERR_IF(!ok, exit, "WriteFile(%s)", KSCLDR_LINK_NAME_A);

    _tprintf(_T("Executing...\n"));

    ok = DeviceIoControl(
        hdev,
        IOCTL_kscldr_callsc,
        NULL,
        0,
        NULL,
        0,
        &bytes_xferred,
        NULL
       );
    ERR_IF(
        !ok,
        exit,
        "DeviceIoControl(%s, %s, ...)",
        KSCLDR_LINK_NAME_A,
        "IOCTL_kscldr_callsc"
       );

    ok = stopDriver();
    ERR_IF(!ok, exit, "stopDriver");

    _tprintf(_T("Complete\n"));

    ret = TRUE;

exit:
    if (sc)
    {
        UnmapViewOfFile(sc);
        sc = NULL;
    }

    if (hfile_mapping)
    {
        CloseHandle(hfile_mapping);
        hfile_mapping = NULL;
    }

    if (hfile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hfile);
        hfile = INVALID_HANDLE_VALUE;
    }

    if (hdev != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hdev);
        hdev = INVALID_HANDLE_VALUE;
    }

    return ret;
}
