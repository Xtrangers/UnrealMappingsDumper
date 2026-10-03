#include "pch.h"

#include "unrealVersion.h"

#pragma comment(lib, "Version.lib")

#define SCAN_LIMIT 0x300

#define SCAN_FOR_MEMBER_OFFSET(obj, member, outOffset) \
	for (uint8_t* i = (uint8_t*)obj; ; i++)\
	{\
		auto Count = i - (uint8_t*)obj;\
		if (Count >= SCAN_LIMIT)\
			return false;\
		\
		if (*(uintptr_t*)i == (uintptr_t)member)\
		{\
			outOffset = Count;\
			break;\
		}\
	}\


// Dumper d'adresse brute : Checkpoint equivalent (dumper.cpp est le seul a l'avoir)
// On loggue via WriteFile direct dans C:\Users\Public\umd-fproperty-detect.log

static void LogFPropDetect(const wchar_t* msg) noexcept
{
	__try {
		HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-fproperty-detect.log",
			FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) return;
		DWORD w = 0;
		// Convert wchar_t -> UTF-8 approx
		char utf8[512] = {};
		int n = WideCharToMultiByte(CP_UTF8, 0, msg, -1, utf8, 511, nullptr, nullptr);
		if (n > 0) {
			WriteFile(h, utf8, (DWORD)strnlen(utf8, 511), &w, nullptr);
			WriteFile(h, "\r\n", 2, &w, nullptr);
		}
		CloseHandle(h);
	} __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Verifie qu'un pointeur est lisible ET sur une page allouee (meme logique que
// dumper.cpp IsPtrReadable).
static bool IsPtrOk(const void* p) noexcept
{
	if (!p) return false;
	MEMORY_BASIC_INFORMATION mbi{};
	if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
	if (mbi.State != MEM_COMMIT) return false;
	DWORD prot = mbi.Protect & 0xFF;
	if (prot == 0 || prot == PAGE_NOACCESS) return false;
	if (mbi.Protect & PAGE_GUARD) return false;
	return true;
}

/*
 * Detection dynamique de FPropertySize (porte depuis Dumper-7
 * FindEnumPropertyBaseOffset, OffsetFinder.cpp:1049).
 *
 * Technique : on cherche dans la classe UActorComponent la propriete
 * CreationMethod (de type EnumProperty vers l'enum EComponentCreationMethod).
 * On scanne ensuite les octets de cette FProperty a la recherche du pointeur
 * vers l'UEnum EComponentCreationMethod. L'offset trouve correspond a
 * FEnumProperty::Enum, qui est le 2e membre apres FEnumProperty::UnderlyingProp.
 * On en deduit : FPropertySize = offset_trouve - sizeof(void*).
 *
 * Avantages par rapport au hardcoding :
 *  - Marche automatiquement sur chaque patch client Aion 2
 *  - Marche sur d'autres jeux UE 5.3 custom (NCsoft a potentiellement
 *    ajoute un pointeur anti-tamper dans FField ou FProperty)
 *  - Pas besoin de reverse manuel apres chaque update
 *
 * Fallback : si la detection echoue (classe absente, enum absent, pattern
 * introuvable), on garde la valeur hardcodee de la Version<> active.
 */
static bool TryDetectFPropertySize(int32_t* outSize) noexcept
{
	*outSize = 0;

	UClass* ActorComponent = nullptr;
	UObject* CreationMethodEnum = nullptr;

	__try {
		ActorComponent = ObjObjects::FindObjectByName<UClass>(L"ActorComponent");
		CreationMethodEnum = ObjObjects::FindObjectByName(L"EComponentCreationMethod");
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		LogFPropDetect(L"[FPropDetect] FindObjectByName a throw");
		return false;
	}

	if (!IsPtrOk(ActorComponent) || !IsPtrOk(CreationMethodEnum)) {
		LogFPropDetect(L"[FPropDetect] ActorComponent ou EComponentCreationMethod absent de GObjects");
		return false;
	}

	wchar_t buf[256] = {};
	wsprintfW(buf, L"[FPropDetect] ActorComponent=%p CreationMethodEnum=%p",
		ActorComponent, CreationMethodEnum);
	LogFPropDetect(buf);

	// Scanne les octets ChildProperties..+SCAN_LIMIT pour trouver la propriete
	// dont le nom contient CreationMethod. On ne peut pas utiliser GetNext()
	// car son offset depend de FPropertySize qu'on cherche justement.
	// On fait un scan plus brute : on parcourt la zone memoire a partir de
	// ChildProperties en cherchant un bloc memoire qui ressemble a une
	// FProperty avec un nom valide, puis on scanne apres pour le pointeur
	// vers CreationMethodEnum.
	uint8_t* startAddr = (uint8_t*)ActorComponent->ChildProperties();
	if (!IsPtrOk(startAddr)) {
		LogFPropDetect(L"[FPropDetect] ChildProperties(ActorComponent) non lisible");
		return false;
	}

	wsprintfW(buf, L"[FPropDetect] ChildProperties start = %p", startAddr);
	LogFPropDetect(buf);

	// Scan en linked list : on tente plusieurs offsets de Next possibles
	// (0x28, 0x38, 0x48, 0x50) pour trouver une chaine valide qui mene a
	// une Property pointant vers CreationMethodEnum.
	//
	// Pour chaque Property dans la chaine, on scanne les slots 0x40..0x100
	// par pas de 8 en cherchant le pointeur CreationMethodEnum.
	//
	// Le premier offset qui donne un match coherent (= FPropertySize + 8)
	// est retenu.

	constexpr int kNextOffsetCandidates[] = { 0x28, 0x38, 0x48, 0x50 };
	constexpr int kMaxPropsScanned = 128;
	constexpr int kMinSlotOffset = 0x40;
	constexpr int kMaxSlotOffset = 0x120;

	int32_t bestSize = 0;

	for (int nextOff : kNextOffsetCandidates) {
		uint8_t* curProp = startAddr;
		int visited = 0;
		while (IsPtrOk(curProp) && visited++ < kMaxPropsScanned) {
			// Pour cette Property, scanner tous les slots potentiels
			for (int slot = kMinSlotOffset; slot <= kMaxSlotOffset; slot += 8) {
				uint8_t* slotAddr = curProp + slot;
				if (!IsPtrOk(slotAddr)) break;
				void* slotVal = *(void**)slotAddr;
				if (slotVal == CreationMethodEnum) {
					// Trouve ! FEnumProperty::Enum = slot
					// FPropertySize = slot - sizeof(void*) (car Enum est 2e apres UnderlyingProp)
					int32_t detectedSize = slot - (int32_t)sizeof(void*);
					wsprintfW(buf,
						L"[FPropDetect] match ! nextOff=0x%x prop=%p slot=0x%x -> FPropertySize=0x%x",
						nextOff, curProp, slot, detectedSize);
					LogFPropDetect(buf);
					if (detectedSize >= 0x40 && detectedSize <= 0x100) {
						bestSize = detectedSize;
						// Early exit : on prend le premier match plausible
						*outSize = bestSize;
						return true;
					}
				}
			}
			// Avance via le Next candidat
			uint8_t* nextAddr = curProp + nextOff;
			if (!IsPtrOk(nextAddr)) break;
			uint8_t* nextProp = *(uint8_t**)nextAddr;
			if (nextProp == curProp) break;  // boucle
			curProp = nextProp;
		}
	}

	LogFPropDetect(L"[FPropDetect] aucun match - fallback hardcode");
	return false;
}


/*
 * Detecte si FArrayProperty utilise l'ancien ordre {Inner; ArrayFlags;}
 * (UE <= 5.2) ou le nouveau ordre {ArrayFlags; Inner;} (UE 5.3+).
 *
 * Technique : parcourt plusieurs classes connues qui contiennent des
 * ArrayProperty, et pour chaque Property teste les 2 offsets Inner candidats
 * (FPropertySize+0 et FPropertySize+8). Chaque candidat est "vote" si :
 *   - l'adresse a l'offset est lisible
 *   - elle contient un pointeur lisible
 *   - ce pointeur ressemble a une FProperty (sa ClassPrivate est lisible)
 *
 * Celui qui recoit significativement plus de votes gagne. Si egalite ou
 * marge faible, on reste sur l'ancien ordre (plus sur).
 *
 * Appele apres TryDetectFPropertySize pour avoir la bonne valeur de reference.
 */
static void TryDetectArrayInnerOffset() noexcept
{
	FArrayProperty::ArrayInnerExtraOffset = 0;  // default : ancien ordre

	const wchar_t* classesToTest[] = {
		L"GameViewportClient", L"ActorComponent", L"Pawn", L"PlayerController",
		L"World", L"GameInstance", L"Actor"
	};

	int32_t votesAt0 = 0;
	int32_t votesAt8 = 0;

	for (const wchar_t* cName : classesToTest) {
		UClass* cls = nullptr;
		__try {
			cls = ObjObjects::FindObjectByName<UClass>(cName);
		} __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
		if (!IsPtrOk(cls)) continue;

		uint8_t* p = nullptr;
		__try {
			p = (uint8_t*)cls->ChildProperties();
		} __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

		int visited = 0;
		while (IsPtrOk(p) && visited++ < 128) {
			__try {
				uint8_t* at0 = p + FProperty::FPropertySize;
				uint8_t* at8 = p + FProperty::FPropertySize + 0x8;
				if (IsPtrOk(at0)) {
					void* v0 = *(void**)at0;
					if (IsPtrOk(v0)) {
						// Verifie ClassPrivate (offset 0x8 dans FField)
						void* vclass0 = *(void**)((uint8_t*)v0 + 0x8);
						if (IsPtrOk(vclass0)) votesAt0++;
					}
				}
				if (IsPtrOk(at8)) {
					void* v8 = *(void**)at8;
					if (IsPtrOk(v8)) {
						void* vclass8 = *(void**)((uint8_t*)v8 + 0x8);
						if (IsPtrOk(vclass8)) votesAt8++;
					}
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			// Avance via Next 0x48
			uint8_t* nx = p + 0x48;
			if (!IsPtrOk(nx)) break;
			uint8_t* nextP = nullptr;
			__try {
				nextP = *(uint8_t**)nx;
			} __except (EXCEPTION_EXECUTE_HANDLER) { break; }
			if (!nextP || nextP == p) break;
			p = nextP;
		}
	}

	wchar_t vbuf[256] = {};
	wsprintfW(vbuf, L"[FPropDetect] Array votes : at FPropertySize+0 = %d, at FPropertySize+8 = %d",
		votesAt0, votesAt8);
	LogFPropDetect(vbuf);
	if (votesAt8 > votesAt0 * 2) {
		FArrayProperty::ArrayInnerExtraOffset = 0x8;
		LogFPropDetect(L"[FPropDetect] -> reorder UE 5.3+ retenu : Inner a FPropertySize+8");
	} else {
		LogFPropDetect(L"[FPropDetect] -> ancien ordre retenu : Inner a FPropertySize");
	}
}


//this is super unsafe but hopefully stackoverflow comes in clutch https://stackoverflow.com/a/42389638
bool IUnrealVersion::TryDynamicOffsets()
{
	try
	{
		auto UClassPtr = ObjObjects::FindObjectByName<UClass>(L"Class");
		auto UObjectPtr = ObjObjects::FindObjectByName<UClass>(L"Object");
		auto ActorPtr = ObjObjects::FindObjectByName<UClass>(L"Actor");
		auto EnginePtr = ObjObjects::FindObjectByName(L"/Script/Engine");

		if (!UClassPtr or !UObjectPtr or !ActorPtr or !EnginePtr)
			return false;

		SCAN_FOR_MEMBER_OFFSET(UObjectPtr, UClassPtr, UObject::ClassOffset);

		if (!UObject::ClassOffset)
			return false;

		SCAN_FOR_MEMBER_OFFSET(ActorPtr, UObjectPtr, UStruct::SuperOffset);

		if (!UStruct::SuperOffset)
			return false;

		UStruct::ChildPropertiesOffset = UStruct::SuperOffset + (sizeof(void*) * 2);

		SCAN_FOR_MEMBER_OFFSET(ActorPtr, EnginePtr, UObject::OuterOffset);

		if (!UObject::OuterOffset)
			return false;

	}
	catch (...)
	{
		return false;
	}

	// Nouvelle etape (03/10/2026) : detection dynamique de FPropertySize
	// via EComponentCreationMethod dans UActorComponent. Si echec, on
	// garde la valeur hardcodee de la Version<> active (0x80 pour Aion 2).
	int32_t detectedSize = 0;
	if (TryDetectFPropertySize(&detectedSize)) {
		FProperty::FPropertySize = detectedSize;
	}

	// Nouvelle etape 2 : detection du reorder FArrayProperty UE 5.3+.
	TryDetectArrayInnerOffset();

	return true;
}