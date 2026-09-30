#include "pch.h"

#include "app.h"
#include "dumper.h"

// PATCH AION2 MANUAL MAPPING STEALTH v0.1 (2026-09-06)
// - AllocConsole retiré (détectable par NCGuard + focus switch alerte)
// - CreateThread remplacé par CreateTimerQueueTimer + WT_EXECUTELONGFUNCTION
//   (thread pool worker Windows = invisible watchdog interne Aion2)
// - FreeLibraryAndExitThread remplacé par return (Manual Mapping n'a pas
//   de vrai LoadLibrary → FreeLibrary crashe)
// - Log dans C:\Users\Public\testscan.log (bénéficie du watcher SysUtil Qt)

#define UMD_VERSION "v0.1-aion2"
#define UMD_BUILD    __DATE__ " " __TIME__

HANDLE g_umd_log = INVALID_HANDLE_VALUE;
static HANDLE g_umd_timer = nullptr;

// v0.0.17.22 : enregistre les tables SEH x64 (.pdata) de notre DLL manual-mappee
// aupres du dispatcher Windows. Sans ca, __try/__except du dumper.cpp ne
// rattrapent PAS les AV : l'exception dispatch remonte au top-level handler
// -> ExitProcess. Le stub Manual Mapping d'InjectorXXX ne fait pas ce travail
// -> on le fait nous-memes cote DLL charge, ce qui est plus portable.
static bool g_umd_pdata_registered = false;
static void RegisterUmdExceptionTable(HMODULE h)
{
    if (g_umd_pdata_registered) return;
    auto dos = (PIMAGE_DOS_HEADER)h;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_DATA_DIRECTORY& ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ed.VirtualAddress == 0 || ed.Size == 0) return;
    auto rf = (PRUNTIME_FUNCTION)((BYTE*)h + ed.VirtualAddress);
    DWORD cnt = ed.Size / sizeof(RUNTIME_FUNCTION);
    if (cnt == 0) return;
    if (RtlAddFunctionTable(rf, cnt, (DWORD64)h)) {
        g_umd_pdata_registered = true;
        // Log dans un fichier a part pour tracer
        HANDLE fh = CreateFileW(L"C:\\Users\\Public\\umd-pdata.log",
            GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fh != INVALID_HANDLE_VALUE) {
            wchar_t bom = 0xFEFF; DWORD w = 0;
            WriteFile(fh, &bom, sizeof(bom), &w, nullptr);
            wchar_t line[256];
            int n = swprintf(line, 256,
                L"v0.0.17.22 : RtlAddFunctionTable OK\r\n"
                L"  base   = 0x%llX\r\n"
                L"  rf     = 0x%llX\r\n"
                L"  count  = %lu\r\n"
                L"  size   = %lu bytes\r\n",
                (unsigned long long)h, (unsigned long long)rf, cnt, ed.Size);
            WriteFile(fh, line, n * sizeof(wchar_t), &w, nullptr);
            FlushFileBuffers(fh);
            CloseHandle(fh);
        }
    }
}

// v0.0.17.21 : VEH logger — enregistre chaque exception (AV surtout) AVANT que le
// dispatcher SEH normal tente de trouver un handler. Retourne
// EXCEPTION_CONTINUE_SEARCH pour laisser __try/__except tenter apres. But :
// prouver que les crashes UMD sont des AV que le SEH ne rattrape pas (SEH x64
// table-based cassé sans RtlAddFunctionTable en Manual Mapping).
static volatile LONG g_veh_count = 0;
static LONG NTAPI UMD_VEH_Logger(EXCEPTION_POINTERS* p)
{
    LONG idx = InterlockedIncrement(&g_veh_count);
    // Fusible : ne loguer que les 50 premieres exceptions (evite spam si boucle infinie)
    if (idx > 50) return EXCEPTION_CONTINUE_SEARCH;

    HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-veh.log",
        FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
        if (sz.QuadPart == 0) {
            wchar_t bom = 0xFEFF; DWORD w = 0;
            WriteFile(h, &bom, sizeof(bom), &w, nullptr);
        }
        wchar_t line[512];
        EXCEPTION_RECORD* er = p->ExceptionRecord;
        CONTEXT* cr = p->ContextRecord;
        unsigned long long p0 = (er->NumberParameters > 0) ? (unsigned long long)er->ExceptionInformation[0] : 0ULL;
        unsigned long long p1 = (er->NumberParameters > 1) ? (unsigned long long)er->ExceptionInformation[1] : 0ULL;
        int n = swprintf(line, 512,
            L"#%ld code=0x%08lX addr=0x%llX RIP=0x%llX RAX=0x%llX RCX=0x%llX RDX=0x%llX RBX=0x%llX p0=0x%llX p1=0x%llX\r\n",
            idx,
            (unsigned long)er->ExceptionCode,
            (unsigned long long)er->ExceptionAddress,
            (unsigned long long)cr->Rip,
            (unsigned long long)cr->Rax,
            (unsigned long long)cr->Rcx,
            (unsigned long long)cr->Rdx,
            (unsigned long long)cr->Rbx,
            p0, p1);
        DWORD w = 0;
        WriteFile(h, line, n * sizeof(wchar_t), &w, nullptr);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static VOID CALLBACK UMD_ScanCallback(PVOID Context, BOOLEAN)
{
	HMODULE Module = (HMODULE)Context;

	// Wrap TOUT dans try/catch — sinon toute std::exception non catchée kill le
	// process avec exit 0xE06D7363 (Microsoft C++ exception). Aion2 = kernel AC.
	try
	{
		UE_LOG("========================================================");
		UE_LOG("UnrealMappingsDumper (Aion 2 patched) %s (build %s)", UMD_VERSION, UMD_BUILD);
		UE_LOG("========================================================");
		UE_LOG("Base module = %s", "Aion2.exe");

		UE_LOG("[trace] Calling App::Init() ...");
		bool initOk = App::Init();
		UE_LOG("[trace] App::Init() returned %d", initOk ? 1 : 0);

		if (!initOk)
		{
			UE_LOG("Failed to initialize the dumper. Returning.");
			if (g_umd_log != INVALID_HANDLE_VALUE) { FlushFileBuffers(g_umd_log); CloseHandle(g_umd_log); g_umd_log = INVALID_HANDLE_VALUE; }
			if (g_umd_timer) DeleteTimerQueueTimer(nullptr, g_umd_timer, nullptr);
			return;
		}

		UE_LOG("[trace] Starting Dumper::Run(ECompressionMethod::None) ...");
		auto Start = std::chrono::steady_clock::now();

		Dumper::Run(ECompressionMethod::None);

		auto End = std::chrono::steady_clock::now();

		UE_LOG("Successfully generated mappings file in %.02f ms",
			(End - Start).count() / 1000000.);

		// AION2 : rapporte le nb d'appels + crashes FNameToString
		UE_LOG("[AION2] FNameToString : %ld calls total, %ld crashes (safe wrapper)",
			(long)FName::s_FNameCallCount, (long)FName::s_FNameCrashCount);
		if (FName::s_FNameCallCount > 0) {
			double pct = 100.0 * FName::s_FNameCrashCount / FName::s_FNameCallCount;
			UE_LOG("[AION2] Crash rate: %.2f%% - si 0%% => RVA candidate viable, sinon fausse fonction",
				pct);
		}

		UE_LOG("=== FIN UnrealMappingsDumper (usmap ecrit dans C:\\Users\\Public\\Mappings-Aion2.usmap) ===");
	}
	catch (const std::exception& e)
	{
		UE_LOG("[FATAL] std::exception non-catchée : %s", e.what());
		UE_LOG("[FATAL] Type : %s", typeid(e).name());
	}
	catch (...)
	{
		UE_LOG("[FATAL] Exception inconnue (probable throw non-C++ ou SEH via /EHa)");
	}

	// PATCH: pas de FreeLibraryAndExitThread — Manual Mapping n'a pas de handle valide
	if (g_umd_log != INVALID_HANDLE_VALUE) {
		FlushFileBuffers(g_umd_log);
		CloseHandle(g_umd_log);
		g_umd_log = INVALID_HANDLE_VALUE;
	}
	if (g_umd_timer) DeleteTimerQueueTimer(nullptr, g_umd_timer, nullptr);
}

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);

		// v0.0.17.22 : enregistre les tables SEH x64 EN PREMIER — sans ca,
		// __try/__except du dumper.cpp ne rattrapent pas les AV.
		RegisterUmdExceptionTable(hModule);

		// v0.0.17.21 : VEH logger — logue chaque AV avant que SEH tente de la
		// dispatcher (garde pour diagnostic meme apres RtlAddFunctionTable OK).
		DeleteFileW(L"C:\\Users\\Public\\umd-veh.log");
		AddVectoredExceptionHandler(1 /*FIRST*/, UMD_VEH_Logger);

		// Ouvre le log en tout premier (visible LogPanel SysUtil)
		g_umd_log = CreateFileW(L"C:\\Users\\Public\\testscan.log",
			GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		// Défère le dump sur thread pool worker Windows (invisible watchdog Aion2)
		CreateTimerQueueTimer(&g_umd_timer, nullptr, UMD_ScanCallback,
			hModule, 0, 0, WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION);

		// Retour immédiat → thread APC libéré instantanément
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
