"""
process_tracker.py - Windows Restart Manager & Process Lineage Telemetry
Discovers the exact process holding active file handles using Windows Restart Manager (rstrtmgr.dll),
extracts parent process lineage and command-line execution arguments, and provides safe termination.
"""

from __future__ import annotations

import os
import sys
import ctypes
from ctypes import wintypes
import psutil

# Protected system processes that can never be terminated
_PROTECTED_PROCESSES = frozenset({
    "csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",
    "explorer.exe", "svchost.exe", "smss.exe", "dwm.exe",
    "system", "system idle process"
})


# ── Windows Restart Manager Structures & Ctypes ──────────────────────────────
if sys.platform == "win32":
    CCH_RM_SESSION_KEY = 32
    CCH_RM_MAX_APP_NAME = 255
    CCH_RM_MAX_SVC_NAME = 63

    class RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwProcessId", wintypes.DWORD),
            ("ProcessStartTime", wintypes.FILETIME),
        ]

    class RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ("Process", RM_UNIQUE_PROCESS),
            ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
            ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
            ("ApplicationType", wintypes.UINT),
            ("AppStatus", wintypes.ULONG),
            ("TSSessionId", wintypes.DWORD),
            ("bRestartable", wintypes.BOOL),
        ]

    try:
        rstrtmgr = ctypes.windll.rstrtmgr
    except Exception:
        rstrtmgr = None
else:
    rstrtmgr = None


def get_file_locking_pids(filepath: str) -> list[int]:
    """
    Query the Windows Restart Manager for PIDs currently holding an open handle to filepath.
    Returns list of PIDs.
    """
    if not rstrtmgr or not filepath or not os.path.exists(filepath):
        return []

    pids: list[int] = []
    session_handle = wintypes.DWORD()
    session_key = (wintypes.WCHAR * (CCH_RM_SESSION_KEY + 1))()

    res = rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key)
    if res != 0:
        return []

    try:
        file_arr = (wintypes.LPCWSTR * 1)(filepath)
        res = rstrtmgr.RmRegisterResources(session_handle, 1, file_arr, 0, None, 0, None)
        if res != 0:
            return []

        n_proc_info_needed = wintypes.UINT(0)
        n_proc_info = wintypes.UINT(0)
        reboot_reasons = wintypes.DWORD()

        # First call to get required buffer size
        res = rstrtmgr.RmGetList(
            session_handle,
            ctypes.byref(n_proc_info_needed),
            ctypes.byref(n_proc_info),
            None,
            ctypes.byref(reboot_reasons)
        )

        if n_proc_info_needed.value > 0:
            proc_info_arr = (RM_PROCESS_INFO * n_proc_info_needed.value)()
            n_proc_info.value = n_proc_info_needed.value

            res = rstrtmgr.RmGetList(
                session_handle,
                ctypes.byref(n_proc_info_needed),
                ctypes.byref(n_proc_info),
                proc_info_arr,
                ctypes.byref(reboot_reasons)
            )

            if res == 0:
                for i in range(n_proc_info.value):
                    pid = proc_info_arr[i].Process.dwProcessId
                    if pid and pid != os.getpid():
                        pids.append(pid)
    except Exception:
        pass
    finally:
        rstrtmgr.RmEndSession(session_handle)

    return pids


def get_process_telemetry(filepath: str = "", pid: int | None = None) -> dict:
    """
    Resolve true process attribution, parent lineage, and command-line execution arguments.

    Returns:
        {
            "pid": int | None,
            "name": str,
            "cmdline": str,
            "ppid": int | None,
            "parent_name": str,
            "lineage": str,
        }
    """
    target_pid = pid
    if isinstance(filepath, int) and target_pid is None:
        target_pid = filepath
        filepath = ""

    # 1. Try Windows Restart Manager on the target file
    if not target_pid and filepath and os.path.exists(filepath):
        pids = get_file_locking_pids(filepath)
        if pids:
            target_pid = pids[0]

    # 2. Fallback: Query Foreground Window if available
    if not target_pid and sys.platform == "win32":
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if hwnd:
                win_pid = ctypes.c_ulong()
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
                if win_pid.value and win_pid.value != os.getpid():
                    target_pid = win_pid.value
        except Exception:
            pass

    if not target_pid:
        return {
            "pid": None,
            "name": "System / Background",
            "cmdline": "N/A",
            "ppid": None,
            "parent_name": "N/A",
            "lineage": "System / Background",
        }

    try:
        proc = psutil.Process(target_pid)
        proc_name = proc.name()
        try:
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list) if cmdline_list else proc_name
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = proc_name

        ppid = proc.ppid()
        parent_name = "N/A"
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        lineage = f"{parent_name} (PID {ppid}) → {proc_name} (PID {target_pid})" if ppid else f"{proc_name} (PID {target_pid})"

        return {
            "pid": target_pid,
            "name": proc_name,
            "cmdline": cmdline[:300],  # cap at 300 chars
            "ppid": ppid,
            "parent_name": parent_name,
            "lineage": lineage,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {
            "pid": target_pid,
            "name": "System / Background",
            "cmdline": "N/A",
            "ppid": None,
            "parent_name": "N/A",
            "lineage": "System / Background",
        }


def terminate_process(pid: int) -> dict:
    """
    Safely terminate an unapproved exfiltration or suspicious utility process.
    Enforces strict guardrails to prevent terminating core Windows system processes.
    """
    if not pid or pid <= 4 or pid == os.getpid():
        return {"success": False, "error": "Cannot terminate current or root system process."}

    try:
        proc = psutil.Process(pid)
        proc_name = proc.name().lower()

        if proc_name in _PROTECTED_PROCESSES:
            return {
                "success": False,
                "error": f"Protection Policy: Termination of core process '{proc_name}' is forbidden."
            }

        proc.kill()
        return {
            "success": True,
            "message": f"Successfully terminated suspicious process '{proc_name}' (PID {pid})."
        }
    except psutil.NoSuchProcess:
        return {"success": False, "error": f"Process PID {pid} is no longer running."}
    except psutil.AccessDenied:
        return {"success": False, "error": f"Access Denied: Insufficient privilege to terminate PID {pid}."}
    except Exception as e:
        return {"success": False, "error": str(e)}
