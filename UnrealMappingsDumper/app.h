#pragma once

// PATCH AION2 MANUAL MAPPING STEALTH
// UE_LOG remplacé : au lieu de printf (nécessite AllocConsole = détectable),
// on écrit dans un fichier via WinAPI pur. Le fichier est ouvert par dllmain.
// Le LogPanel SysUtil Qt watch ce fichier via QFileSystemWatcher.

#include <windows.h>
#include <cstdio>
#include <cstdarg>

extern HANDLE g_umd_log;

static void UE_LOG(const char* str, ...)
{
	if (g_umd_log == INVALID_HANDLE_VALUE || g_umd_log == nullptr) return;

	char buf[2048];
	int prefix = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[=] ");

	va_list fmt;
	va_start(fmt, str);
	int n = _vsnprintf_s(buf + prefix, sizeof(buf) - prefix, _TRUNCATE, str, fmt);
	va_end(fmt);

	int total = prefix + (n > 0 ? n : 0);
	if (total < 0 || total >= (int)sizeof(buf)) total = (int)sizeof(buf) - 3;

	buf[total] = '\r';
	buf[total + 1] = '\n';

	DWORD w = 0;
	WriteFile(g_umd_log, buf, (DWORD)(total + 2), &w, nullptr);
	FlushFileBuffers(g_umd_log);
}

namespace App
{
	bool Init();
}
