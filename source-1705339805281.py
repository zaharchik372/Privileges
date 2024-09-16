import ctypes
import ctypes.wintypes as wintypes
import time

# Константы
SE_DEBUG_NAME = "SeDebugPrivilege"
SE_BACKUP_NAME = "SeBackupPrivilege"
SE_RESTORE_NAME = "SeRestorePrivilege"

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000


# Структуры и функции Windows API
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
OpenProcessToken.restype = wintypes.BOOL

LookupPrivilegeValue = advapi32.LookupPrivilegeValueW
LookupPrivilegeValue.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
LookupPrivilegeValue.restype = wintypes.BOOL

AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD,
                                  ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)]
AdjustTokenPrivileges.restype = wintypes.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


# Функция для проверки и включения привилегии
def enable_privilege(hToken, privilege_name):
    luid = LUID()

    if not LookupPrivilegeValue(None, privilege_name, ctypes.byref(luid)):
        raise ctypes.WinError(ctypes.get_last_error())


    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    # Активация привилегии
    if not AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None):
        raise ctypes.WinError(ctypes.get_last_error())

    print(f"Privilege {privilege_name} enabled.")
    input()


def check_and_enable_privileges():
    hToken = wintypes.HANDLE()

    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(hToken)):
        raise ctypes.WinError(ctypes.get_last_error())

    privileges = [SE_DEBUG_NAME, SE_BACKUP_NAME, SE_RESTORE_NAME]

    for privilege in privileges:
        try:
            enable_privilege(hToken, privilege)
        except Exception as e:
            print(f"Failed to enable privilege {privilege}: {e}")

    CloseHandle(hToken)


if __name__ == "__main__":
    check_and_enable_privileges()
    time.sleep(15)
