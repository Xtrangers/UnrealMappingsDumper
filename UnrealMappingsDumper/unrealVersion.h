#pragma once

#include "app.h"
#include "unrealTypes.h"
#include "scanning.h"
#include "aion2Offsets.h"  // D.11 : offsets lus depuis offsets-aion2.json

// v0.0.17.2 (Plan B FNamePool direct) — Implementation de FNameToString qui
// traverse GNamePool en direct au lieu d'appeler la fonction UE (introuvable
// en Aion 2, probablement inlinee LTCG). Layout confirme via
// tests/dlls/namepool-inspect (voir scratch/aion2-xrefs-None.txt).
//
// GNamePool @ Aion2Base + 0x0F0791C0 (post-maj 09/09/2026, ancien 0x0EE7AFC0) :
// v0.0.19.5 (post-maj 22/09/2026) : GObjects/GWorld ont bouge de +0x8E000.
//   GObjects   : 0x0EBC6A40 -> 0x0EC54A40 (delta +0x8E000, valide par OffsetFinder)
//   GWorld     : 0x0EED6278 -> 0x0EF64938 (utilise ailleurs, pas dans UMD)
//   GNamePool  : hypothese +0x8E000 -> 0x0F1071C0 (a confirmer runtime)
//   struct FNameEntryAllocator {
//     FRWLock Lock;              // +0x00
//     uint32  CurrentBlock;      // +0x08
//     uint32  CurrentByteCursor; // +0x0C
//     uint8*  Blocks[8192];      // +0x10 INLINE array (each = 64KB page)
//   };
//
// Split FNameEntryId : blockIdx = id >> 16 | offset = (id & 0xFFFF) * 2
// FNameEntry : Header (16 bits : bIsWide:1 | probeHash:5 | Len:10) + Data[Len]
// DEBUG : compteur global + log des 20 premiers appels dans testscan.log
static int g_ManualFNameCallCounter = 0;

static void ManualFNameToString_Aion2(const void* pThis, FString& Out) noexcept
{
	// FName layout : { uint32 ComparisonIndex; uint32 DisplayIndex; uint32 Number; }
	// On lit uniquement ComparisonIndex (le pool est indexe par ca)
	uint32_t id = *(const uint32_t*)pThis;
	uint32_t blockIdx   = id >> 16;
	uint32_t byteOffset = (id & 0xFFFF) * 2;   // stride 2

	int callNum = ++g_ManualFNameCallCounter;

	if (blockIdx >= 8192) return;

	HMODULE hAion = GetModuleHandleW(L"Aion2.exe");
	if (!hAion) return;

	uint8_t*  pool   = (uint8_t*)hAion + Aion2Offsets::FNamePool();   // D.11 : lu depuis offsets-aion2.json (fallback 0x0F1071C0)
	uint8_t** blocks = (uint8_t**)(pool + 0x10);

	uint8_t* blockPtr = blocks[blockIdx];
	if (!blockPtr) return;

	uint8_t* entry = blockPtr + byteOffset;
	uint16_t hdr   = *(uint16_t*)entry;
	bool     isWide = (hdr & 1) != 0;
	uint16_t len    = (hdr >> 6) & 0x3FF;

	// v0.0.17.25 : borne stricte Len 200 (UE max pratique) + validation charset.
	// Sans ca, quand byteOffset pointe entre 2 entries valides (id garbage), on
	// lit un "header" fait de 2 chars ASCII -> Len random grand (400+) -> on
	// concatene plusieurs vrais noms UE dans un mega-name corrompu.
	if (len == 0 || len > 200) return;

	// Alloue wchar_t buffer (LEAK volontaire — FString UMD n'a pas de destructor,
	// le heap process est libere au shutdown Aion 2).
	wchar_t* buf = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(wchar_t));
	if (!buf) return;

	if (isWide) {
		const wchar_t* src = (const wchar_t*)(entry + 2);
		for (uint16_t i = 0; i < len; ++i) {
			wchar_t c = src[i];
			if (c < 0x20 || c > 0x7E) { HeapFree(GetProcessHeap(), 0, buf); return; }
			buf[i] = c;
		}
	} else {
		const char* src = (const char*)(entry + 2);
		for (uint16_t i = 0; i < len; ++i) {
			unsigned char c = (unsigned char)src[i];
			if (c < 0x20 || c > 0x7E) { HeapFree(GetProcessHeap(), 0, buf); return; }
			buf[i] = (wchar_t)c;
		}
	}
	buf[len] = 0;

	// Set FString fields directement (FString : TArray<wchar_t>)
	// TArray layout : wchar_t* Buffer +0, int32 ArrayNum +8, int32 ArrayMax +12
	struct FStringLayout { wchar_t* buf; int32_t num; int32_t max; };
	FStringLayout* fs = (FStringLayout*)&Out;
	fs->buf = buf;
	fs->num = (int32_t)(len + 1);   // Inclut le null terminator (convention UE)
	fs->max = (int32_t)(len + 1);

	// DEBUG : log les 20 premiers calls + dump GObjects layout au premier call
	if (callNum <= 20) {
		HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-fname-debug.log",
			FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
			if (sz.QuadPart == 0) {
				wchar_t bom = 0xFEFF;
				DWORD w = 0;
				WriteFile(h, &bom, sizeof(bom), &w, nullptr);

				// Au premier call : dump GObjects layout + parse actif
				uint8_t* gobj = (uint8_t*)hAion + Aion2Offsets::GObjects();   // D.11 : lu depuis offsets-aion2.json
				uint64_t* objectsPtr = *(uint64_t**)(gobj + 0x00);
				int32_t maxEl = *(int32_t*)(gobj + 0x10);
				int32_t numEl = *(int32_t*)(gobj + 0x14);
				int32_t maxCh = *(int32_t*)(gobj + 0x18);
				int32_t numCh = *(int32_t*)(gobj + 0x1C);
				wchar_t hdr[512];
				int hLen = swprintf(hdr, 512,
					L"=== GObjects parse ===\r\n"
					L"  gobj=0x%llX  Objects[]=0x%llX  MaxEl=%d  NumEl=%d  MaxCh=%d  NumCh=%d\r\n",
					(unsigned long long)gobj, (unsigned long long)objectsPtr, maxEl, numEl, maxCh, numCh);
				WriteFile(h, hdr, hLen * sizeof(wchar_t), &w, nullptr);
				// Dump les 3 premiers chunk pointers
				if (objectsPtr) {
					for (int c = 0; c < 3; ++c) {
						uint64_t chunkPtr = objectsPtr[c];
						wchar_t line[256];
						int len2 = swprintf(line, 256, L"  Chunk[%d] = 0x%llX\r\n", c, (unsigned long long)chunkPtr);
						WriteFile(h, line, len2 * sizeof(wchar_t), &w, nullptr);
						// Pour Chunk[0], dump 3 premiers UObjects layout (48 bytes chacun)
						if (c == 0 && chunkPtr) {
							uint8_t* raw = (uint8_t*)chunkPtr;
							for (int itm = 0; itm < 3; ++itm) {
								uint64_t objPtr = *(uint64_t*)(raw + itm * 24);
								wchar_t oh[128];
								int ohl = swprintf(oh, 128, L"  UObject[%d] @ 0x%llX layout 64 bytes:\r\n", itm, (unsigned long long)objPtr);
								WriteFile(h, oh, ohl * sizeof(wchar_t), &w, nullptr);
								if (objPtr) {
									uint8_t* obj = (uint8_t*)objPtr;
									for (int row = 0; row < 4; ++row) {
										wchar_t hex[512];
										int hexLen = swprintf(hex, 512,
											L"    +%02X: q0=0x%016llX q1=0x%016llX\r\n",
											row*16,
											*(unsigned long long*)(obj + row*16),
											*(unsigned long long*)(obj + row*16 + 8));
										WriteFile(h, hex, hexLen * sizeof(wchar_t), &w, nullptr);
									}
								}
							}
						}
					}
				}
			}
			wchar_t line[512];
			int lineLen = swprintf(line, 512,
				L"[call#%d] id=0x%08X block=%u offset=%u len=%u isWide=%d str='%.*s'\r\n",
				callNum, id, blockIdx, byteOffset, (unsigned)len, isWide ? 1 : 0,
				(int)len, buf);
			DWORD written = 0;
			WriteFile(h, line, lineLen * sizeof(wchar_t), &written, nullptr);
			CloseHandle(h);
		}
	}
}

/*
* The idea here is to make something that can easily be overriden for engine or game versions with different types
* that need to be overriden or handled differently.
*/

struct IUnrealVersion
{
private:
	static bool TryDynamicOffsets();

public:

	template <typename Version>
	static bool InitTypes()
	{
		uintptr_t GObjectsAddy = 0;

		// PATCH AION 2 : GObjects manual override — les patterns UE 5.3 standards
		// ne matchent pas Aion2.exe (packé NCsoft, section .ncg0). Notre OffsetFinder
		// via patterns GSpots l'a trouvé statiquement : RVA 0x0EBC6A40 (post-maj 09/09/2026).
		// Cette valeur peut évoluer entre patches d'Aion 2 — recompiler avec la nouvelle
		// valeur trouvée par OffsetFinder si le usmap sort vide.
		{
			wchar_t modName[MAX_PATH] = {0};
			GetModuleFileNameW(nullptr, modName, MAX_PATH);
			if (wcsstr(modName, L"Aion2.exe") != nullptr)
			{
				// D.11 : lu depuis offsets-aion2.json (fallback hardcode 0x0EC54A40 dans aion2Offsets.h)
				const uintptr_t AION2_GOBJECTS_RVA = Aion2Offsets::GObjects();
				GObjectsAddy = (uintptr_t)GetModuleHandleW(nullptr) + AION2_GOBJECTS_RVA;
				UE_LOG("[AION2] GObjects override (D.11 JSON): base + 0x%llX = 0x%llX  source=%ls",
					(unsigned long long)AION2_GOBJECTS_RVA, (unsigned long long)GObjectsAddy,
					Aion2Offsets::Source());
			}
		}

		if (!GObjectsAddy)
		{
			for (auto Scan : Version::GetGObjectsPatterns())
			{
				GObjectsAddy = Scan->TryFind();

				if (GObjectsAddy)
					break;
			}
		}

		if (!GObjectsAddy)
		{
			UE_LOG("Could not find the address for GObjects. Try overriding it or adding the correct sig for it.");
			return false;
		}

		ObjObjects::SetInstance(GObjectsAddy);
		UE_LOG("[trace] ObjObjects::SetInstance OK");

		uintptr_t FNameStringAddy = 0;

		// PATCH AION 2 v0.0.17.2 — Plan B FNamePool DIRECT (bypass FName::AppendString).
		// Apres 4 tentatives infructueuses (0x04126A70, 0x03D797C0, 0x03D69450, 0x040777F0
		// = tous crashent), constatation : FName::AppendString n'existe pas comme fonction
		// distincte dans Aion 2 (probablement inlinee par LTCG). On resout via traversal
		// directe de GNamePool (RVA 0x0F0791C0, 382503 refs post-maj — ancien 0x0EE7AFC0/375192 refs) — layout valide runtime via
		// tests/dlls/namepool-inspect (voir scratch/aion2-xrefs-None.txt + fonction
		// ManualFNameToString_Aion2 en tete de ce fichier).
		bool aion2ManualOverride = false;
		{
			wchar_t modName[MAX_PATH] = {0};
			GetModuleFileNameW(nullptr, modName, MAX_PATH);
			if (wcsstr(modName, L"Aion2.exe") != nullptr)
			{
				FNameToString = ManualFNameToString_Aion2;
				FNameStringAddy = (uintptr_t)&ManualFNameToString_Aion2;
				aion2ManualOverride = true;
				UE_LOG("[AION2] FNamePool direct override (Plan B v0.0.17.2) — no UE call");
			}
		}

		// PATCH AION 2 : validation range Aion2.exe pour éviter false positives.
		// Les patterns génériques (E8 ? ? ? ? 48 8B ...) peuvent matcher dans
		// d'autres régions (heap, autres DLLs) → CALL to invalid → AV 0xC0000005.
		uintptr_t aion_base = 0, aion_end = 0;
		{
			HMODULE h = GetModuleHandleW(L"Aion2.exe");
			if (h) {
				auto dos = (PIMAGE_DOS_HEADER)h;
				auto nt = (PIMAGE_NT_HEADERS64)((BYTE*)h + dos->e_lfanew);
				aion_base = (uintptr_t)h;
				aion_end = aion_base + nt->OptionalHeader.SizeOfImage;
				UE_LOG("[trace] Aion2.exe range: 0x%llX - 0x%llX",
					(unsigned long long)aion_base, (unsigned long long)aion_end);
			}
		}

		// Skip pattern scan si l'override AION2 a deja resolu FNameToString.
		// Sinon patterns generiques peuvent false-positive et ecraser le hardcoded.
		if (!FNameStringAddy)
		{
			int scanIdx = 0;
			for (auto Scan : Version::GetFNameStringPatterns())
			{
				UE_LOG("[trace] Trying FNameString pattern #%d ...", scanIdx++);
				uintptr_t candidate = 0;
				try
				{
					candidate = Scan->TryFind();
				}
				catch (const std::exception& e)
				{
					UE_LOG("[trace] Pattern threw std::exception: %s", e.what());
					continue;
				}
				catch (...)
				{
					UE_LOG("[trace] Pattern threw unknown exception");
					continue;
				}
				UE_LOG("[trace] Pattern #%d returned 0x%llX", scanIdx - 1, (unsigned long long)candidate);

				// Validate : doit être dans Aion2.exe (protège contre false positives)
				if (candidate && aion_base && (candidate < aion_base || candidate >= aion_end))
				{
					UE_LOG("[trace] Pattern #%d REJECTED : 0x%llX hors range Aion2.exe",
						scanIdx - 1, (unsigned long long)candidate);
					continue;
				}

				if (candidate)
				{
					FNameStringAddy = candidate;
					break;
				}
			}
		}
		else
		{
			UE_LOG("[trace] FNameToString deja set par override AION2, skip pattern scan");
		}

		if (!FNameStringAddy)
		{
			UE_LOG("Could not find the address for FNameToString. Try overriding it or adding the correct sig for it.");
			UE_LOG("[AION2] Aion 2 uses non-standard FNameToString - manual override needed.");
			return false;
		}

		UE_LOG("[trace] FNameToString found at 0x%llX", (unsigned long long)FNameStringAddy);
		FNameToString = (_FNameToString)FNameStringAddy;

		using UObjectImpl = Version::Offsets::UObject;
		using UStructImpl = Version::Offsets::UStruct;

		UObject::NameOffset = UObjectImpl::NameOffset;
		FName::IsOptimized = Version::HasOptimizedFName;
		FProperty::FPropertySize = Version::FPropertySize;

		if (!TryDynamicOffsets())
		{
			UE_LOG("Could not grab dynamic offsets. Just gonna use the hardcoded ones.");

			UObject::ClassOffset = UObjectImpl::ClassOffset;
			UObject::OuterOffset = UObjectImpl::OuterOffset;

			UStruct::SuperOffset = UStructImpl::SuperOffset;
			UStruct::ChildPropertiesOffset = UStructImpl::ChildPropertiesOffset;
		}

		return true;
	}
};

/*
* Yes, it's true, UObject should pretty much always be the same across all games,
* however there are some games that use a custom UObject, so should they ever need mappings,
* this design pattern makes it easier to override the offsets.
*/

struct UnrealVersionBase : IUnrealVersion
{
	static constexpr int FPropertySize = 0x78;
	static constexpr bool HasOptimizedFName = false;

	struct Offsets
	{
		struct UObject
		{
			static constexpr int NameOffset = 0x18;
			static constexpr int ClassOffset = 0x10;
			static constexpr int OuterOffset = 0x20;
		};

		struct UStruct
		{
			static constexpr int SuperOffset = 0x40;
			static constexpr int ChildPropertiesOffset = 0x50;
		};
	};

	static std::vector<std::shared_ptr<IScanObject>> GetFNameStringPatterns()
	{
		return
		{
			// --- Patterns originaux UMD (call-sites CALL rel32) ---
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 83 7D C8 00 48 8D 15 ? ? ? ? 0F 5A DE", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8B 4C 24 ? 8B FD 48 85 C9", 1, true),// 4.12 - 5.0 EA
			std::make_shared<PatternScanObject>("E8 ? ? ? ? BD 01 00 00 00 41 39 6E ? 0F 8E", 1, true),// 4.25+ Backup

			// --- Patterns supplémentaires UE 5.3 (voie 2) : call-sites Dumper-7 ---
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8B ? 48 89 ? ? ? E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8B ? 48 8B ? ? E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8B ? ? 48 89 ? ? E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8D ? ? 48 8B ? E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8D ? ? ? 48 8B ? E8", 1, true),

			// --- Patterns UE 5.3 : call-sites communs ---
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8D 4D 78 48 8B D3 E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8B D0 48 8B CB E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 48 8D 55 ? 48 8B CB E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 4C 8D ? ? 48 8B ? E8", 1, true),
			std::make_shared<PatternScanObject>("E8 ? ? ? ? 45 33 C9 4C 8B", 1, true),

			// --- Patterns UE 5.3 : prologues de la fonction FName::ToString directement ---
			// Ceux-ci trouvent le début de la fonction (pas un call vers elle)
			// offset=0, relative=false → l'adresse trouvée EST la fonction
			std::make_shared<PatternScanObject>(
				"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B FA", 0, false),
			std::make_shared<PatternScanObject>(
				"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B DA", 0, false),
			std::make_shared<PatternScanObject>(
				"48 8B C4 55 41 56 48 8D A8 78 FE FF FF 48 81 EC 78 02", 0, false),
			std::make_shared<PatternScanObject>(
				"40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24", 0, false),
		};
	}


	static std::vector<std::shared_ptr<IScanObject>> GetGObjectsPatterns()
	{
		return
		{
			std::make_shared<PatternScanObject>("48 89 05 ? ? ? ? E8 ? ? ? ? ? ? ? 0F 84", 3, true),
			std::make_shared<PatternScanObject>("48 8B 05 ? ? ? ? 48 8B 0C 07 48 85 C9 74 20", 3, true),
			std::make_shared<PatternScanObject>("48 8B 05 ? ? ? ? 48 8B 0C", 3, true),
			std::make_shared<PatternScanObject>("48 03 ? ? ? ? ? ? ? ? ? ? 48 8B 10 48 85 D2 74 07", 3, true)

		};
	}
};

/*
* Use this if the games engine has UE_FNAME_OUTLINE_NUMBER defined as 1
*/
struct Version_OptimizedFName : UnrealVersionBase
{
	static constexpr int FPropertySize = 0x70;
	static constexpr bool HasOptimizedFName = true;
};

struct Version_FortniteLatest : Version_OptimizedFName
{
	static std::vector<std::shared_ptr<IScanObject>> GetGObjectsPatterns()
	{
		return
		{
			std::make_shared<PatternScanObject>("48 8B 05 ? ? ? ? 48 8B 0C C8", 3, true)
		};
	}
};