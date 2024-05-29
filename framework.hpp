#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <windowsx.h>
#include <winternl.h>
#include <shellapi.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <oleacc.h>
#include <comutil.h>
#include <taskschd.h>
#include <TlHelp32.h>
#include <sddl.h>
#include <aclapi.h>
#include <psapi.h>
#include <dwmapi.h>
#include <detours.h>
#include <appmodel.h>
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Oleacc.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi")