#include "pch.h"

#include "dumper.h"
#include "writer.h"
#include "oodle.h"
#include "aion2Offsets.h"

// v30 : Shell COM pour lire PKEY_Software_ProductVersion de AION2.exe
#include <shlobj.h>
#include <propsys.h>
#include <propvarutil.h>
#pragma comment(lib, "propsys.lib")

// Definition locale de PKEY_Software_ProductVersion (fmtid + pid=8).
// GUID correct = {0CEF7D53-FA64-11D1-A203-0000F81FEDEE} (System.Software.ProductVersion).
// Correctif 03/10/2026 : ancien GUID 0CEF7D0C-...-9F12 retournait VIDE sur AION2.exe
// (signale par AIONSERVER, confirme par test local). Correspond a Shell col 307.
static const PROPERTYKEY kPkeyProductVersion = {
    { 0x0CEF7D53, 0xFA64, 0x11D1, { 0xA2, 0x03, 0x00, 0x00, 0xF8, 0x1F, 0xED, 0xEE } }, 8
};

// v0.0.17.12 : validation runtime pointeur via VirtualQuery — evite les crashes
// silencieux sur UStruct partiels (heap corruption bypass SEH).
// v0.0.17.17 : revert alignment check de 17.16 qui a regresse le ForEach.
// Le baseline 17.15 marchait jusqu'a P3 iter=0, on garde cette version.
static bool IsPtrReadable(const void* p) noexcept
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

// Traite un UStruct avec __try/__except au niveau de la fonction dediee
// (SEH ne fonctionne pas toujours proprement dans une lambda C++). Retourne
// false si un crash a ete rattrape.
template<class NameMapT>
static bool TryProcessStruct(UStruct* Struct,
                              std::vector<UStruct*>& Structs,
                              NameMapT& NameMap) noexcept
{
    if (!IsPtrReadable(Struct)) return false;

    __try
    {
        Structs.push_back(Struct);

        NameMap.insert_or_assign(Struct->GetFName(), 0);

        UStruct* Super = Struct->Super();
        if (IsPtrReadable(Super) && !NameMap.contains(Super->GetFName()))
            NameMap.insert_or_assign(Super->GetFName(), 0);

        FProperty* Props = Struct->ChildProperties();
        int guardMax = 4096;  // fusible : rare struct avec > 4096 fields
        while (IsPtrReadable(Props) && guardMax-- > 0)
        {
            NameMap.insert_or_assign(Props->GetFName(), 0);
            Props = static_cast<FProperty*>(Props->GetNext());
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// v0.0.17.16 : TrySerializeOneStruct — meme pattern que TryProcessStruct mais
// pour la boucle serialisation. Evite std::vector<FPropertyData> local (C2712)
// en faisant 2 passes sur ChildProperties : (1) count PropCount/Serializable,
// (2) serialize. Ainsi __try/__except propre.
static EPropertyType GetPropertyType(FProperty* Prop);  // forward decl

// v0.0.19.15 : validation stricte de chaque FField avant utilisation.
// Verifie que le Class ET le nom sont lisibles avant d'accepter le FField.
static bool IsFieldSane(FProperty* Prop) noexcept {
    __try {
        if (!IsPtrReadable(Prop)) return false;
        auto cls = Prop->GetClass();
        if (!IsPtrReadable(cls)) return false;
        // Test lecture nom (ne pas capturer, juste s'assurer que ca ne crash pas)
        auto& fn = Prop->GetFName();
        (void)fn;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// v0.0.19.16 : collecte la chaine Props en 1 passe SAFE dans un array fixe,
// puis serialise l'array (pas la chaine). Evite Pass1 != Pass2 en cas de
// desync partielle du chaine Next.
template<class NameMapT>
static uint16_t CollectPropsSafe(UStruct* Struct, FProperty** out, uint16_t maxProps) noexcept {
    __try {
        FProperty* Props = Struct->ChildProperties();
        uint16_t count = 0;
        while (IsFieldSane(Props) && count < maxProps) {
            out[count++] = Props;
            Props = static_cast<FProperty*>(Props->GetNext());
        }
        return count;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

template<class NameMapT, class WritePropFn>
static bool TrySerializeInner(UStruct* Struct, StreamWriter& localBuf,
    NameMapT& NameMap, WritePropFn& WriteProperty) noexcept
{
    // v0.0.19.17 : max 256 props (limite stricte anti-chaine corrompue).
    // Aion 2 EU : le plus gros struct legitime a ~130 props (AionAbsorbObj etc.)
    constexpr uint16_t MAX_PROPS = 256;
    FProperty* propsArray[MAX_PROPS];
    uint16_t propsCount = CollectPropsSafe<NameMapT>(Struct, propsArray, MAX_PROPS);


    __try {
        localBuf.Write(NameMap[Struct->GetFName()]);

        UStruct* Super = Struct->Super();
        localBuf.Write<int32_t>(IsPtrReadable(Super) ? NameMap[Super->GetFName()] : int32_t(0xffffffff));

        // Calcule PropCount depuis l'array collecte (pas de re-traversal)
        uint16_t PropCount = 0;
        for (uint16_t i = 0; i < propsCount; i++) {
            PropCount += uint16_t(propsArray[i]->GetArrayDim());
        }
        localBuf.Write(PropCount);
        localBuf.Write(propsCount);

        uint16_t indexAcc = 0;
        for (uint16_t i = 0; i < propsCount; i++) {
            FProperty* Props = propsArray[i];
            uint16_t dim = uint16_t(Props->GetArrayDim());
            localBuf.Write<uint16_t>(indexAcc);
            localBuf.Write<uint8_t>(uint8_t(dim));
            localBuf.Write(NameMap[Props->GetFName()]);
            EPropertyType t = GetPropertyType(Props);
            WriteProperty(Props, t, localBuf);
            indexAcc += dim;
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Helper pour lire safe le nom d'un struct
template<class NameMapT>
static int32_t GetStructNameIdxSafe(UStruct* Struct, NameMapT& NameMap) noexcept {
    __try { return NameMap[Struct->GetFName()]; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Wrapper qui gere le StreamWriter local (destructor) et le commit atomique
template<class NameMapT, class WritePropFn>
static bool TrySerializeOneStruct(UStruct* Struct, StreamWriter& Buffer,
    NameMapT& NameMap, WritePropFn& WriteProperty) noexcept
{
    if (!IsPtrReadable(Struct)) return false;

    StreamWriter localBuf;
    bool ok = TrySerializeInner(Struct, localBuf, NameMap, WriteProperty);

    if (ok) {
        std::string localData = localBuf.GetBuffer().str();
        Buffer.Write((void*)localData.data(), localData.size());
        return true;
    } else {
        // Placeholder 12 bytes : nameIdx + superIdx=-1 + PC=0 + SP=0
        int32_t nameIdx = GetStructNameIdxSafe(Struct, NameMap);
        Buffer.Write(nameIdx);
        Buffer.Write<int32_t>(int32_t(0xffffffff));
        Buffer.Write<uint16_t>(0);
        Buffer.Write<uint16_t>(0);
        return false;
    }
}

template<class NameMapT>
static bool TryProcessEnum(UEnum* Enum,
                            std::vector<UEnum*>& Enums,
                            NameMapT& NameMap) noexcept
{
    if (!IsPtrReadable(Enum)) return false;

    __try
    {
        Enums.push_back(Enum);
        NameMap.insert_or_assign(Enum->GetFName(), 0);

        auto& EnumNames = Enum->Names();
        int n = EnumNames.Num();
        if (n < 0 || n > 100000) return true;  // fusible : garde le push_back mais skip noms
        for (int i = 0; i < n; i++)
            NameMap.insert_or_assign(EnumNames[i].Key.GetNumber(), 0);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

// v0.0.17.20 : versions "Enrich only" appelees HORS du ForEach. Le ForEach
// se contente d'un push_back + NameMap[fname]=0 (2 ops, comme 17.12 qui
// passait). L'enrichissement Super + Props (lourd, ~20 VirtualQuery par
// struct) est fait dans une phase P0 dediee AVEC checkpoints toutes les 500
// iter pour pouvoir tracer un crash precisement.
template<class NameMapT>
static bool TryEnrichStructNameMap(UStruct* Struct, NameMapT& NameMap) noexcept
{
    if (!IsPtrReadable(Struct)) return false;
    __try
    {
        UStruct* Super = Struct->Super();
        if (IsPtrReadable(Super) && !NameMap.contains(Super->GetFName()))
            NameMap.insert_or_assign(Super->GetFName(), 0);
        FProperty* Props = Struct->ChildProperties();
        int guardMax = 4096;
        while (IsPtrReadable(Props) && guardMax-- > 0)
        {
            NameMap.insert_or_assign(Props->GetFName(), 0);
            Props = static_cast<FProperty*>(Props->GetNext());
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

template<class NameMapT>
static bool TryEnrichEnumNameMap(UEnum* Enum, NameMapT& NameMap) noexcept
{
    if (!IsPtrReadable(Enum)) return false;
    __try
    {
        auto& EnumNames = Enum->Names();
        int n = EnumNames.Num();
        if (n < 0 || n > 100000) return true;
        for (int i = 0; i < n; i++)
            NameMap.insert_or_assign(EnumNames[i].Key.GetNumber(), 0);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// v0.0.17.27 : Scan FNamePool brut. Extrait en fonction free noexcept car
// Dumper::Run contient std::string/vector/unordered_map -> C2712 sur __try.
// Retourne stats via param out.
template<class NameMapT>
static void ScanFNamePoolBrut(NameMapT& NameMap,
                               int& outBlocks, int& outNames, int& outSkip) noexcept
{
    outBlocks = 0; outNames = 0; outSkip = 0;
    // nullptr = module courant (marche pour Aion2.exe TW et AION2.exe EU)
    HMODULE hAion = GetModuleHandleW(nullptr);
    if (!hAion) return;

    // v0.0.19.7 : lit l'offset depuis Aion2Offsets (JSON offsets-aion2.json)
    // au lieu du hardcode 0x0F0791C0 (TW post-maj 09/09/2026) qui ne marche pas
    // sur EU (0x0F110380). Meme mecanisme que le resolver unrealVersion.h.
    Aion2Offsets::ChargerUneFois();
    uint8_t* pool = (uint8_t*)hAion + Aion2Offsets::FNamePool();
    uint32_t currentBlock = *(uint32_t*)(pool + 0x08);
    uint32_t currentByteCursor = *(uint32_t*)(pool + 0x0C);
    uint8_t** blocks = (uint8_t**)(pool + 0x10);

    for (uint32_t blockIdx = 0; blockIdx <= currentBlock && blockIdx < 8192; blockIdx++) {
        uint8_t* blockPtr = blocks[blockIdx];
        if (!IsPtrReadable(blockPtr)) continue;
        outBlocks++;

        uint32_t blockEnd = (blockIdx == currentBlock) ? currentByteCursor : 0x10000;
        if (blockEnd > 0x10000) blockEnd = 0x10000;
        uint32_t offset = 0;

        while (offset + 2 < blockEnd) {
            uint32_t nextOffset = offset + 2;
            __try {
                uint16_t hdr = *(uint16_t*)(blockPtr + offset);
                if (hdr == 0) { nextOffset = blockEnd; }
                else {
                    bool isWide = (hdr & 1) != 0;
                    uint16_t len = (hdr >> 6) & 0x3FF;
                    if (len == 0 || len > 200) {
                        nextOffset = offset + 2;
                    } else {
                        bool valid = true;
                        if (!isWide) {
                            const char* src = (const char*)(blockPtr + offset + 2);
                            for (uint16_t i = 0; i < len; i++) {
                                unsigned char c = (unsigned char)src[i];
                                if (c < 0x20 || c > 0x7E) { valid = false; break; }
                            }
                        }
                        if (valid) {
                            uint32_t fnameId = (blockIdx << 16) | (offset / 2);
                            NameMap.insert_or_assign(FName((int)fnameId), 0);
                            outNames++;
                        } else {
                            outSkip++;
                        }
                        uint32_t entrySize = 2 + (isWide ? uint32_t(len) * 2 : uint32_t(len));
                        if (entrySize & 1) entrySize++;
                        nextOffset = offset + entrySize;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                nextOffset = offset + 2;
            }
            if (nextOffset <= offset) break;
            offset = nextOffset;
        }
    }
}

static EPropertyType GetPropertyType(FProperty* Prop)
{
	switch (Prop->GetClass()->GetId())
	{
	case CASTCLASS_FObjectProperty:
	case CASTCLASS_FClassProperty:
	case CASTCLASS_FObjectPtrProperty:
	case CASTCLASS_FClassPtrProperty:
	{
		return EPropertyType::ObjectProperty;
	}
	case CASTCLASS_FStructProperty:
	{
		return EPropertyType::StructProperty;
	}
	case CASTCLASS_FInt8Property:
	{
		return EPropertyType::Int8Property;
	}
	case CASTCLASS_FInt16Property:
	{
		return EPropertyType::Int16Property;
	}
	case CASTCLASS_FIntProperty:
	{
		return EPropertyType::IntProperty;
	}
	case CASTCLASS_FInt64Property:
	{
		return EPropertyType::Int64Property;
	}
	case CASTCLASS_FUInt16Property:
	{
		return EPropertyType::UInt16Property;
	}
	case CASTCLASS_FUInt32Property:
	{
		return EPropertyType::UInt32Property;
	}
	case CASTCLASS_FUInt64Property:
	{
		return EPropertyType::UInt64Property;
	}
	case CASTCLASS_FArrayProperty:
	{
		return EPropertyType::ArrayProperty;
	}
	case CASTCLASS_FFloatProperty:
	{
		return EPropertyType::FloatProperty;
	}
	case CASTCLASS_FDoubleProperty:
	{
		return EPropertyType::DoubleProperty;
	}
	case CASTCLASS_FBoolProperty:
	{
		return EPropertyType::BoolProperty;
	}
	case CASTCLASS_FStrProperty:
	{
		return EPropertyType::StrProperty;
	}
	case CASTCLASS_FNameProperty:
	{
		return EPropertyType::NameProperty;
	}
	case CASTCLASS_FTextProperty:
	{
		return EPropertyType::TextProperty;
	}
	case CASTCLASS_FEnumProperty:
	{
		return EPropertyType::EnumProperty;
	}
	case CASTCLASS_FInterfaceProperty:
	{
		return EPropertyType::InterfaceProperty;
	}
	case CASTCLASS_FMapProperty:
	{
		return EPropertyType::MapProperty;
	}
	case CASTCLASS_FByteProperty:
	{
		FByteProperty* ByteProp = static_cast<FByteProperty*>(Prop);

		if (ByteProp->GetEnum())
			return EPropertyType::EnumAsByteProperty;

		return EPropertyType::ByteProperty;
	}
	case CASTCLASS_FMulticastDelegateProperty:
	case CASTCLASS_FMulticastInlineDelegateProperty:
	case CASTCLASS_FMulticastSparseDelegateProperty:
	{
		return EPropertyType::MulticastDelegateProperty;
	}
	case CASTCLASS_FDelegateProperty:
	{
		return EPropertyType::DelegateProperty;
	}
	case CASTCLASS_FSoftObjectProperty:
	case CASTCLASS_FSoftClassProperty:
	{
		return EPropertyType::SoftObjectProperty;
	}
	case CASTCLASS_FWeakObjectProperty:
	{
		return EPropertyType::WeakObjectProperty;
	}
	case CASTCLASS_FLazyObjectProperty:
	{
		return EPropertyType::LazyObjectProperty;
	}
	case CASTCLASS_FSetProperty:
	{
		return EPropertyType::SetProperty;
	}
	case CASTCLASS_FFieldPathProperty:
	{
		return EPropertyType::FieldPathProperty;
	}
	case CASTCLASS_FOptionalProperty:
	{
		return EPropertyType::OptionalProperty;
	}
	default:
	{
		return EPropertyType::Unknown;
	}
	}
}

struct FPropertyData
{
	FProperty* Prop;
	uint16_t Index;
	uint8_t ArrayDim;
	FName Name;
	EPropertyType PropertyType;

	FPropertyData(FProperty* P, int Idx) :
		Prop(P),
		Index(Idx),
		ArrayDim(P->GetArrayDim()),
		Name(P->GetFName()),
		PropertyType(GetPropertyType(P))
	{
	}
};

// v0.0.19.8 : DIAG offsets UStruct/FProperty pour Aion 2 EU.
// Fonction free noexcept avec __try (evite C2712 dans Dumper::Run).
static void DumpStructLayoutDiag(const std::vector<UStruct*>& Structs,
                                 const std::vector<UEnum*>& Enums) noexcept
{
	HANDLE hDiag = CreateFileW(L"C:\\Users\\Public\\umd-struct-layout.log",
		GENERIC_WRITE, FILE_SHARE_READ, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hDiag == INVALID_HANDLE_VALUE) return;

	wchar_t bom = 0xFEFF;
	DWORD w = 0;
	WriteFile(hDiag, &bom, sizeof(bom), &w, nullptr);

	auto WriteLine = [&](const wchar_t* buf, int n) {
		if (n > 0) WriteFile(hDiag, buf, n * sizeof(wchar_t), &w, nullptr);
		const wchar_t* nl = L"\r\n";
		WriteFile(hDiag, nl, 4, &w, nullptr);
	};

	{
		wchar_t line[256];
		int n = swprintf_s(line, 256, L"=== UMD STRUCT LAYOUT DIAG (v0.0.19.8) ===");
		WriteLine(line, n);
		n = swprintf_s(line, 256, L"Structs.size = %zu, Enums.size = %zu",
			Structs.size(), Enums.size());
		WriteLine(line, n);
		n = swprintf_s(line, 256, L"Offsets UMD hardcodes : Name=0x18 Class=0x10 Super=0x40 ChildProps=0x50 PropsSize=0x58");
		WriteLine(line, n);
		WriteLine(L"", 0);
	}

	// v0.0.19.9 : inspecte 3 premiers + indices 100, 500, 2000, 5000, 10000
	// (les 3 premiers sont Object/Interface/EditorPathObjectInterface qui n'ont
	// pas de proprietes -> on veut voir des structs gameplay).
	size_t indices[] = { 0, 1, 2, 100, 500, 2000, 5000, 10000 };
	for (size_t idxIdx = 0; idxIdx < 8; idxIdx++) {
		size_t sIdx = indices[idxIdx];
		if (sIdx >= Structs.size()) continue;
		UStruct* S = Structs[sIdx];
		int inspected = (int)sIdx;
		__try {
			if (!IsPtrReadable(S)) continue;

			const uint8_t* raw = (const uint8_t*)S;
			wchar_t line[512];

			int n = swprintf_s(line, 512, L"--- Struct #%d @ 0x%p ---", inspected, S);
			WriteLine(line, n);

			// Dump 128 bytes bruts hex
			for (int i = 0; i < 128; i += 16) {
				wchar_t hexline[256] = {};
				int hp = swprintf_s(hexline, 256, L"  +%04X: ", i);
				for (int j = 0; j < 16; j++) {
					hp += swprintf_s(hexline + hp, 256 - hp, L"%02X ", raw[i + j]);
				}
				hp += swprintf_s(hexline + hp, 256 - hp, L" |");
				for (int j = 0; j < 16; j++) {
					uint8_t b = raw[i + j];
					hexline[hp++] = (b >= 32 && b < 127) ? (wchar_t)b : L'.';
				}
				hexline[hp++] = L'|';
				hexline[hp] = 0;
				WriteLine(hexline, hp);
			}

			// Reads a offsets UMD
			uint64_t nameFName = *(uint64_t*)(raw + 0x18);
			uint64_t classVal = *(uint64_t*)(raw + 0x10);
			uint64_t superVal = *(uint64_t*)(raw + 0x40);
			uint64_t childProps = *(uint64_t*)(raw + 0x50);
			int32_t propSize = *(int32_t*)(raw + 0x58);

			n = swprintf_s(line, 512, L"Reads: Class=0x%llX Name=0x%llX Super=0x%llX ChildProps=0x%llX PropsSize=%d",
				classVal, nameFName, superVal, childProps, propSize);
			WriteLine(line, n);

			// Nom via GetFName
			auto fname_str = S->GetFName().AsString();
			n = swprintf_s(line, 512, L"GetFName().AsString() = '%.*s'", (int)fname_str.size(), fname_str.data());
			WriteLine(line, n);

			// Follow ChildProperties si valide
			if (childProps && IsPtrReadable((void*)childProps)) {
				const uint8_t* propRaw = (const uint8_t*)childProps;
				n = swprintf_s(line, 512, L"1er FProperty @ 0x%llX :", childProps);
				WriteLine(line, n);

				// Dump 128 bytes FProperty (au lieu de 64)
				for (int i = 0; i < 128; i += 16) {
					wchar_t hexline[256] = {};
					int hp = swprintf_s(hexline, 256, L"  +%04X: ", i);
					for (int j = 0; j < 16; j++) {
						hp += swprintf_s(hexline + hp, 256 - hp, L"%02X ", propRaw[i + j]);
					}
					hp += swprintf_s(hexline + hp, 256 - hp, L" |");
					for (int j = 0; j < 16; j++) {
						uint8_t b = propRaw[i + j];
						hexline[hp++] = (b >= 32 && b < 127) ? (wchar_t)b : L'.';
					}
					hexline[hp++] = L'|';
					hexline[hp] = 0;
					WriteLine(hexline, hp);
				}

				// Tente de resoudre chaque uint32 possible comme FName ID
				// et logge le nom si le resolver retourne quelque chose
				WriteLine(L"Test resolveur : essai de chaque u32 comme FName ID", 50);
				for (int offset = 0x10; offset <= 0x40; offset += 4) {
					uint32_t maybe_id = *(uint32_t*)(propRaw + offset);
					if (maybe_id == 0 || maybe_id > 10000000) continue;
					// Construit un faux FName sur la stack pour appeler resolver
					uint32_t fname_data[3] = { maybe_id, 0, 0 };
					FName fake_name(0);
					memcpy(&fake_name, fname_data, sizeof(FName));
					auto ns = fake_name.AsString();
					if (!ns.empty()) {
						n = swprintf_s(line, 512, L"  +%02X u32=%u -> '%.*s'",
							offset, maybe_id, (int)ns.size(), ns.data());
						WriteLine(line, n);
					}
				}

				// v0.0.19.10 : Follow chain Next a +0x48 sur 5 FField successifs
				// Dumpe 32 bytes au debut de chaque, resout le nom
				WriteLine(L"", 0);
				WriteLine(L"Chain Next @ +0x48 (5 premiers FField) :", 50);
				const uint8_t* cur = propRaw;
				for (int k = 0; k < 5; k++) {
					if (!IsPtrReadable(cur)) {
						n = swprintf_s(line, 512, L"  [%d] 0x%p NON READABLE", k, cur);
						WriteLine(line, n);
						break;
					}
					uint32_t nid = *(uint32_t*)(cur + 0x20);
					uint32_t fname_data[3] = { nid, 0, 0 };
					FName fake_name(0);
					memcpy(&fake_name, fname_data, sizeof(FName));
					auto ns = fake_name.AsString();
					n = swprintf_s(line, 512, L"  [%d] @ 0x%p nid=%u name='%.*s'",
						k, cur, nid, (int)ns.size(), ns.data());
					WriteLine(line, n);
					// Dump les 32 premiers bytes de ce FField
					wchar_t hexline[128] = {};
					int hp = swprintf_s(hexline, 128, L"       ");
					for (int j = 0; j < 32; j++) {
						hp += swprintf_s(hexline + hp, 128 - hp, L"%02X ", cur[j]);
					}
					WriteLine(hexline, hp);
					// Move to Next
					uint64_t nextPtr = *(uint64_t*)(cur + 0x48);
					cur = (const uint8_t*)nextPtr;
				}
			} else {
				WriteLine(L"ChildProps=0 ou invalide, pas de sous-inspection", 40);
			}
			WriteLine(L"", 0);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			wchar_t line[128];
			int n = swprintf_s(line, 128, L"SEH sur struct #%d, skip", inspected);
			WriteLine(line, n);
		}
	}

	// v0.0.19.11 : diag UEnum layout
	WriteLine(L"", 0);
	WriteLine(L"=== UENUM LAYOUT DIAG ===", 25);
	for (int ei = 0; ei < 3 && ei < (int)Enums.size(); ei++) {
		UEnum* E = Enums[ei];
		__try {
			if (!IsPtrReadable(E)) continue;
			const uint8_t* raw = (const uint8_t*)E;
			wchar_t line[512];
			auto ns = E->GetFName().AsString();
			int n = swprintf_s(line, 512, L"UEnum #%d @ 0x%p name='%.*s'",
				ei, E, (int)ns.size(), ns.data());
			WriteLine(line, n);

			// Dump 256 bytes
			for (int i = 0; i < 256; i += 16) {
				wchar_t hexline[256] = {};
				int hp = swprintf_s(hexline, 256, L"  +%04X: ", i);
				for (int j = 0; j < 16; j++) {
					hp += swprintf_s(hexline + hp, 256 - hp, L"%02X ", raw[i + j]);
				}
				hp += swprintf_s(hexline + hp, 256 - hp, L" |");
				for (int j = 0; j < 16; j++) {
					uint8_t b = raw[i + j];
					hexline[hp++] = (b >= 32 && b < 127) ? (wchar_t)b : L'.';
				}
				hexline[hp++] = L'|';
				hexline[hp] = 0;
				WriteLine(hexline, hp);
			}

			// Cherche TArray pattern : { void* + int32 + int32 } avec int32 > 0 et < 1000
			WriteLine(L"Recherche TArray pattern (ptr + Num + Max):", 45);
			for (int off = 0x30; off <= 0xE0; off += 8) {
				uint64_t ptr = *(uint64_t*)(raw + off);
				int32_t num = *(int32_t*)(raw + off + 8);
				int32_t max = *(int32_t*)(raw + off + 12);
				if (num > 0 && num < 1000 && max >= num && ptr != 0) {
					n = swprintf_s(line, 512, L"  +0x%02X : ptr=0x%llX Num=%d Max=%d - CANDIDAT",
						off, ptr, num, max);
					WriteLine(line, n);
					// Essaie de lire le 1er element : {FName, int64}
					if (IsPtrReadable((void*)ptr)) {
						uint32_t fn0 = *(uint32_t*)ptr;
						int64_t v0 = *(int64_t*)(ptr + sizeof(FName));
						uint32_t fname_data[3] = { fn0, 0, 0 };
						FName fake_name(0);
						memcpy(&fake_name, fname_data, sizeof(FName));
						auto rns = fake_name.AsString();
						n = swprintf_s(line, 512, L"    -> [0].name='%.*s' val=%lld",
							(int)rns.size(), rns.data(), v0);
						WriteLine(line, n);
					}
				}
			}
			WriteLine(L"", 0);
		} __except (EXCEPTION_EXECUTE_HANDLER) {}
	}

	WriteLine(L"=== FIN DIAG ===", 15);
	FlushFileBuffers(hDiag);
	CloseHandle(hDiag);
}

void Dumper::Run(ECompressionMethod CompressionMethod)
{
	StreamWriter Buffer;
	phmap::parallel_flat_hash_map<FName, int> NameMap;

	std::vector<UEnum*> Enums;
	std::vector<UStruct*> Structs; // TODO: a better way than making this completely dynamic

	std::function<void(class FProperty*&, EPropertyType, StreamWriter&)> WritePropertyWrapper{}; // hacky.. i know

	auto WriteProperty = [&](FProperty*& Prop, EPropertyType Type, StreamWriter& Buffer)
	{
		if (Type == EPropertyType::EnumAsByteProperty)
			Buffer.Write(EPropertyType::EnumProperty);
		else Buffer.Write(Type);

		switch (Type)
		{
		case EPropertyType::EnumProperty:
		{
			auto EnumProp = static_cast<FEnumProperty*>(Prop);

			auto Inner = EnumProp->GetUnderlying();
			// v0.0.19.13 EU : validation renforcee - IsPtrReadable + verif que
			// GetClass() retourne un objet lisible (pour rejeter les pointeurs
			// valides mais qui pointent sur du garbage).
			bool innerOk = false;
			__try {
				if (IsPtrReadable(Inner)) {
					auto cls = Inner->GetClass();
					if (IsPtrReadable(cls)) innerOk = true;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			if (!innerOk) {
				Buffer.Write(EPropertyType::Unknown);
				Buffer.Write<int32_t>(0);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType, Buffer);

			int32_t enumNameIdx = 0;
			__try {
				auto EnumObj = EnumProp->GetEnum();
				if (IsPtrReadable(EnumObj)) enumNameIdx = NameMap[EnumObj->GetFName()];
			} __except (EXCEPTION_EXECUTE_HANDLER) {}
			Buffer.Write(enumNameIdx);
			break;
		}
		case EPropertyType::EnumAsByteProperty:
		{
			Buffer.Write(EPropertyType::ByteProperty);
			int32_t enumNameIdx = 0;
			__try {
				auto EnumObj = static_cast<FByteProperty*>(Prop)->GetEnum();
				if (IsPtrReadable(EnumObj)) enumNameIdx = NameMap[EnumObj->GetFName()];
			} __except (EXCEPTION_EXECUTE_HANDLER) {}
			Buffer.Write(enumNameIdx);
			break;
		}
		case EPropertyType::StructProperty:
		{
			int32_t structNameIdx = 0;
			__try {
				auto StructObj = static_cast<FStructProperty*>(Prop)->GetStruct();
				if (IsPtrReadable(StructObj)) structNameIdx = NameMap[StructObj->GetFName()];
			} __except (EXCEPTION_EXECUTE_HANDLER) {}
			Buffer.Write(structNameIdx);
			break;
		}
		case EPropertyType::ArrayProperty:
		{
			bool innerOk = false;
			FProperty* Inner = nullptr;
			__try {
				Inner = static_cast<FArrayProperty*>(Prop)->GetInner();
				if (IsPtrReadable(Inner)) {
					auto cls = Inner->GetClass();
					if (IsPtrReadable(cls)) innerOk = true;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			if (!innerOk) {
				Buffer.Write(EPropertyType::Unknown);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType, Buffer);
			break;
		}
		case EPropertyType::SetProperty:
		{
			// FSetProperty layout different de FArrayProperty :
			// pas de EArrayPropertyFlags, donc ElementProp (= Inner) est a
			// FPropertySize sans l'ArrayInnerExtraOffset du reorder UE 5.3+.
			bool innerOk = false;
			FProperty* Inner = nullptr;
			__try {
				Inner = static_cast<FSetProperty*>(Prop)->GetInner();
				if (IsPtrReadable(Inner)) {
					auto cls = Inner->GetClass();
					if (IsPtrReadable(cls)) innerOk = true;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			if (!innerOk) {
				Buffer.Write(EPropertyType::Unknown);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType, Buffer);
			break;
		}
		case EPropertyType::MapProperty:
		{
			bool keyOk = false, valueOk = false;
			FProperty* Inner = nullptr;
			FProperty* Value = nullptr;
			__try {
				Inner = static_cast<FMapProperty*>(Prop)->GetKey();
				Value = static_cast<FMapProperty*>(Prop)->GetValue();
				if (IsPtrReadable(Inner)) {
					auto c1 = Inner->GetClass();
					if (IsPtrReadable(c1)) keyOk = true;
				}
				if (IsPtrReadable(Value)) {
					auto c2 = Value->GetClass();
					if (IsPtrReadable(c2)) valueOk = true;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			if (!keyOk || !valueOk) {
				Buffer.Write(EPropertyType::Unknown);
				Buffer.Write(EPropertyType::Unknown);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType, Buffer);
			auto ValueType = GetPropertyType(Value);
			WritePropertyWrapper(Value, ValueType, Buffer);
			break;
		}
		case EPropertyType::OptionalProperty:
		{
			// FOptionalProperty = { FProperty* ValueProperty; }
			// Nouvelle en UE 5.3, equivalente a TOptional<T>. On ecrit le
			// type de son ValueProperty comme sous-type (meme pattern que
			// ArrayProperty mais sans ArrayFlags).
			// Ajoute 04/10/2026 pour debloquer les 3 cas restants chez
			// AIONSERVER (apres validation COURANT v10).
			bool innerOk = false;
			FProperty* Inner = nullptr;
			__try {
				Inner = static_cast<FOptionalProperty*>(Prop)->GetValueProperty();
				if (IsPtrReadable(Inner)) {
					auto cls = Inner->GetClass();
					if (IsPtrReadable(cls)) innerOk = true;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			if (!innerOk) {
				Buffer.Write(EPropertyType::Unknown);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType, Buffer);
			break;
		}
		}
	};

	WritePropertyWrapper = WriteProperty;

	// v0.0.17.7 AION 2 : resolveur dynamique final. Dump 17.6 a revele :
	//   - GetName() du Package = "/Script/CoreUObject" (path complet)
	//   - "Class" a idx=10, "ScriptStruct" a idx=8, "Enum" a idx=16 (dans les 30
	//     premiers, safe pour Class() deref)
	// Strategie :
	//   1) Scanner les 50 premiers (safe zone verifiee via 17.6 dump).
	//   2) Pas de filtre Outer (les 3 noms sont uniques dans cette zone).
	//   3) Utiliser obj->Class() -> pointeur meta-type stable.
	//   4) Reactiver le ForEach compare-by-pointer (validee safe par 17.3 sur 386k).
	UObject* pUClass  = nullptr;
	UObject* pUStruct = nullptr;
	UObject* pUEnum   = nullptr;
	int pUClassIdx = -1, pUStructIdx = -1, pUEnumIdx = -1;

	int scanMax = 50;
	if (ObjObjects::Num() < scanMax) scanMax = ObjObjects::Num();

	for (int i = 0; i < scanMax; i++)
	{
		UObject* obj = ObjObjects::GetObjectByIndex(i);
		if (!obj) continue;

		auto n = obj->GetName();
		if (n.empty()) continue;

		// v0.0.17.8 : prendre obj (pas obj->Class()) : le UObject nomme "Class" EST
		// le meta-type UClass. Object->Class() de tout Object UClass retourne cet
		// UObject "Class". Idem pour ScriptStruct et Enum. Evite l'appel Class()
		// sur les 3 meta-types dans le scan (source du crash 17.7).
		if (!pUClass  && n == std::wstring_view(L"Class"))        { pUClass  = obj; pUClassIdx  = i; }
		if (!pUStruct && n == std::wstring_view(L"ScriptStruct")) { pUStruct = obj; pUStructIdx = i; }
		if (!pUEnum   && n == std::wstring_view(L"Enum"))         { pUEnum   = obj; pUEnumIdx   = i; }

		if (pUClass && pUStruct && pUEnum) break;
	}

	// v0.0.17.10 : ECRIRE fichier debug AVANT le ForEach avec stats resolveur seul.
	// Comme ca, meme si ForEach crash, on saura si le resolveur a marche.
	{
		HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-foreach-debug.log",
			GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			wchar_t bom = 0xFEFF; DWORD w = 0;
			WriteFile(h, &bom, sizeof(bom), &w, nullptr);
			wchar_t line[1024];
			int len = swprintf(line, 1024,
				L"v0.0.17.10 : resolveur (scan %d) — ECRIT AVANT ForEach\r\n"
				L"  Num()      = %d\r\n"
				L"  pUClass    = 0x%llX (idx=%d)\r\n"
				L"  pUStruct   = 0x%llX (idx=%d)\r\n"
				L"  pUEnum     = 0x%llX (idx=%d)\r\n"
				L"\r\n[Attente ForEach...]\r\n",
				scanMax, ObjObjects::Num(),
				(unsigned long long)pUClass, pUClassIdx,
				(unsigned long long)pUStruct, pUStructIdx,
				(unsigned long long)pUEnum, pUEnumIdx);
			WriteFile(h, line, len * sizeof(wchar_t), &w, nullptr);
			FlushFileBuffers(h);
			CloseHandle(h);
		}
	}

	// v0.0.17.27 : Phase P-1 SCAN FNAMEPOOL BRUT (via fonction free noexcept)
	{
		int p1TotalBlocks = 0, p1TotalNames = 0, p1SkipInvalid = 0;
		ScanFNamePoolBrut(NameMap, p1TotalBlocks, p1TotalNames, p1SkipInvalid);

		HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-namepool-scan.log",
			GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			wchar_t bom = 0xFEFF; DWORD w = 0;
			WriteFile(h, &bom, sizeof(bom), &w, nullptr);
			wchar_t line[512];
			int n = swprintf(line, 512,
				L"v0.0.17.27 : P-1 scan FNamePool brut\r\n"
				L"  Blocks scanned       = %d\r\n"
				L"  Names ajoutes        = %d\r\n"
				L"  Skip invalid charset = %d\r\n"
				L"  NameMap.size apres   = %zu\r\n",
				p1TotalBlocks, p1TotalNames, p1SkipInvalid, NameMap.size());
			WriteFile(h, line, n * sizeof(wchar_t), &w, nullptr);
			FlushFileBuffers(h);
			CloseHandle(h);
		}
	}

	int g_ForEachIter = 0;
	int g_ForEachNullObj = 0;
	int g_ForEachClassMatch = 0;
	int g_ForEachEnumMatch = 0;
	int g_ForEachSkipped = 0;

	// v0.0.17.12 : ForEach avec TryProcessStruct/TryProcessEnum fonctions dediees
	// qui portent le SEH __try/__except (plus fiable que lambda) + validation
	// VirtualQuery de chaque pointeur avant deref.
	int g_ForEachRejectStruct = 0;
	int g_ForEachRejectEnum   = 0;

	// v0.0.17.20 : ForEach STRICT 17.12 — push_back + NameMap[fname]=0 UNIQUEMENT
	// dans le hot path (2 ops par match). L'enrichissement Super+Props est
	// deporte dans une phase P0 dediee avec checkpoints (voir plus bas). But :
	// tenir sous ~5s dans le ForEach (validee 17.12 sur 386k iter).
	ObjObjects::ForEach([&](UObject*& Object)
		{
			g_ForEachIter++;
			if (!Object) { g_ForEachNullObj++; return; }
			if (!IsPtrReadable(Object)) { g_ForEachSkipped++; return; }

			UObject* cls = nullptr;
			__try {
				cls = Object->Class();
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				g_ForEachSkipped++;
				return;
			}
			if (!IsPtrReadable(cls)) return;

			// v0.0.17.26 : capture GREEDY tous les FName + Outer chain (max 10)
			// pour approcher les 74k noms du usmap reference. Sans ca on reste a
			// ~24k (juste les 14337 Structs+Enums matched).
			__try {
				NameMap.insert_or_assign(Object->GetFName(), 0);
				UObject* o = Object;
				for (int d = 0; d < 10; d++) {
					UObject* outer = o->Outer();
					if (!IsPtrReadable(outer) || outer == o) break;
					NameMap.insert_or_assign(outer->GetFName(), 0);
					o = outer;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {}

			if (cls == pUClass || cls == pUStruct)
			{
				g_ForEachClassMatch++;
				__try {
					Structs.push_back(static_cast<UStruct*>(Object));
					NameMap.insert_or_assign(Object->GetFName(), 0);
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					g_ForEachRejectStruct++;
				}
			}
			else if (cls == pUEnum)
			{
				g_ForEachEnumMatch++;
				__try {
					Enums.push_back(static_cast<UEnum*>(Object));
					NameMap.insert_or_assign(Object->GetFName(), 0);
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					g_ForEachRejectEnum++;
				}
			}
		});

	// Ecrit stats ForEach dans un 2eme fichier.
	{
		HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-foreach-after.log",
			GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			wchar_t bom = 0xFEFF; DWORD w = 0;
			WriteFile(h, &bom, sizeof(bom), &w, nullptr);
			wchar_t line[1024];
			int len = swprintf(line, 1024,
				L"v0.0.17.12 : ForEach + TryProcess dediees + VirtualQuery gate\r\n"
				L"  Iter                 = %d\r\n"
				L"  NullObjects          = %d\r\n"
				L"  Skipped (bad ptr)    = %d\r\n"
				L"  UClass+Struct match  = %d\r\n"
				L"  UEnum match          = %d\r\n"
				L"  Struct rejects (SEH) = %d\r\n"
				L"  Enum rejects (SEH)   = %d\r\n"
				L"  Structs.size()       = %zu\r\n"
				L"  Enums.size()         = %zu\r\n"
				L"  NameMap.size()       = %zu\r\n",
				g_ForEachIter, g_ForEachNullObj, g_ForEachSkipped,
				g_ForEachClassMatch, g_ForEachEnumMatch,
				g_ForEachRejectStruct, g_ForEachRejectEnum,
				Structs.size(), Enums.size(), NameMap.size());
			WriteFile(h, line, len * sizeof(wchar_t), &w, nullptr);
			FlushFileBuffers(h);
			CloseHandle(h);
		}
	}

	// v0.0.17.15 : CHECKPOINT tracing pour identifier ou crash arrive.
	// Chaque phase incremente un checkpoint file avec flush.
	auto Checkpoint = [](const wchar_t* fmt, ...) noexcept {
		HANDLE h = CreateFileW(L"C:\\Users\\Public\\umd-checkpoint.log",
			FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) return;
		LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
		if (sz.QuadPart == 0) {
			wchar_t bom = 0xFEFF; DWORD w=0;
			WriteFile(h, &bom, sizeof(bom), &w, nullptr);
		}
		wchar_t line[512];
		va_list ap; va_start(ap, fmt);
		int n = vswprintf(line, 512, fmt, ap);
		va_end(ap);
		if (n < 0) n = 0;
		DWORD w=0;
		WriteFile(h, line, n * sizeof(wchar_t), &w, nullptr);
		WriteFile(h, L"\r\n", 4, &w, nullptr);
		FlushFileBuffers(h);
		CloseHandle(h);
	};

	// v0.0.19.8 : Phase P0-PRE DIAG offsets UStruct/FProperty pour Aion 2 EU.
	DumpStructLayoutDiag(Structs, Enums);

	// v0.0.17.20 : Phase P0 Enrichment — populate NameMap avec Super+Props (Structs)
	// et EnumNames (Enums), boucles SEPAREES du ForEach avec checkpoints toutes les
	// 500 iter. Si le watchdog Aion 2 tue le thread ici, on aura l'index exact.
	{
		Checkpoint(L"P0 Enrich Structs start : Structs.size=%zu", Structs.size());
		int p0StructSkipped = 0;
		int p0StructIter = 0;
		for (auto* S : Structs)
		{
			if (p0StructIter > 0 && (p0StructIter % 500) == 0)
				Checkpoint(L"P0 Enrich Structs iter=%d/%zu (skipped=%d)",
					p0StructIter, Structs.size(), p0StructSkipped);
			if (!TryEnrichStructNameMap(S, NameMap)) p0StructSkipped++;
			p0StructIter++;
		}
		Checkpoint(L"P0 Enrich Structs done : iter=%d skipped=%d NameMap.size=%zu",
			p0StructIter, p0StructSkipped, NameMap.size());

		Checkpoint(L"P0 Enrich Enums start : Enums.size=%zu", Enums.size());
		int p0EnumSkipped = 0;
		int p0EnumIter = 0;
		for (auto* E : Enums)
		{
			if (p0EnumIter > 0 && (p0EnumIter % 500) == 0)
				Checkpoint(L"P0 Enrich Enums iter=%d/%zu (skipped=%d)",
					p0EnumIter, Enums.size(), p0EnumSkipped);
			if (!TryEnrichEnumNameMap(E, NameMap)) p0EnumSkipped++;
			p0EnumIter++;
		}
		Checkpoint(L"P0 Enrich Enums done : iter=%d skipped=%d NameMap.size=%zu",
			p0EnumIter, p0EnumSkipped, NameMap.size());
	}

	Checkpoint(L"P1 start : NameMap.size=%zu", NameMap.size());
	Buffer.Write<int>(NameMap.size());

	int CurrentNameIndex = 0;

	for (auto&& N : NameMap)
	{
		if ((CurrentNameIndex % 2000) == 0)
			Checkpoint(L"P1 NameMap iter=%d/%zu", CurrentNameIndex, NameMap.size());

		NameMap[N.first] = CurrentNameIndex;

		auto Name = N.first.ToString();
		std::string_view NameView = Name;

		auto Find = Name.find("::");
		if (Find != std::string::npos)
		{
			NameView = NameView.substr(Find + 2);
		}

		// v0.0.17.24 : u16 length (format usmap v3+) — u8 truncatait les names
		// > 255 chars et desalignait tous les names suivants. Compat CUE4Parse/FModel.
		Buffer.Write<uint16_t>(uint16_t(NameView.length()));
		Buffer.WriteString(NameView);

		CurrentNameIndex++;
	}
	Checkpoint(L"P1 done : %d names ecrits", CurrentNameIndex);

	// v0.0.19.28 : SECURITE post-patch — refuse d'ecrire un dump incomplet.
	// Si Structs OU Enums est vide, les offsets GObjects/FNamePool/GWorld sont
	// probablement obsoletes (patch client Aion 2). Mieux vaut aucun fichier
	// qu'un .usmap tronque qu'on confondra plus tard avec un vrai dump.
	if (Structs.size() == 0 || Enums.size() == 0)
	{
		Checkpoint(L"ABANDON : dump INCOMPLET - Structs.size=%zu Enums.size=%zu "
		           L"- probable nouveaux offsets Aion 2 apres un patch client. "
		           L"Lance AION2 Studio -> onglet Scan Offsets pour rescanner "
		           L"GObjects/FNamePool/GWorld, puis mets a jour offsets-aion2.json.",
		           Structs.size(), Enums.size());

		// Ecrit un marqueur texte a cote (dans %TEMP%) pour que SysUtil
		// puisse detecter l'abandon et avertir l'operateur.
		wchar_t tmp[MAX_PATH] = {};
		DWORD nTmp = GetTempPathW(MAX_PATH, tmp);
		if (nTmp > 0 && nTmp < MAX_PATH)
		{
			wchar_t marker[MAX_PATH] = {};
			for (DWORD i = 0; i < nTmp && i < MAX_PATH - 32; ++i) marker[i] = tmp[i];
			const wchar_t fname[] = L"umd-abandon-offsets-invalides.txt";
			DWORD ml = 0;
			while (marker[ml]) ++ml;
			for (int j = 0; fname[j] && ml < MAX_PATH - 1; ++j) marker[ml++] = fname[j];
			marker[ml] = 0;

			HANDLE h = CreateFileW(marker, GENERIC_WRITE, 0, nullptr,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (h != INVALID_HANDLE_VALUE)
			{
				char msg[512] = {};
				int len = wsprintfA(msg,
					"UMD a abandonne : Structs=%zu Enums=%zu.\r\n"
					"Les offsets Aion 2 sont probablement obsoletes (patch client).\r\n"
					"Lance AION2 Studio -> Scan Offsets, puis relance ce dump.\r\n",
					Structs.size(), Enums.size());
				DWORD w = 0;
				WriteFile(h, msg, len, &w, nullptr);
				CloseHandle(h);
			}
		}
		return; // ne pas ecrire le .usmap
	}

	// Sanity check additionnel : seuils plausibles pour Aion 2.
	// Un dump sain = ~14 000 structs et ~2 600 enums. En dessous de 1000/100
	// on considere que les offsets ont partiellement foire.
	if (Structs.size() < 1000 || Enums.size() < 100)
	{
		Checkpoint(L"AVERTISSEMENT : dump sous-dimensionne (Structs=%zu, Enums=%zu). "
		           L"Attendu ~14k structs / ~2.6k enums. Verifier offsets apres patch client.",
		           Structs.size(), Enums.size());
		// On ecrit quand meme — ce peut etre un cas limite (dump tres tot au boot).
	}

	Checkpoint(L"P2 start : Enums.size=%zu", Enums.size());
	Buffer.Write<uint32_t>(Enums.size());

	int enumIdx = 0;
	for (auto Enum : Enums)
	{
		if ((enumIdx % 500) == 0)
			Checkpoint(L"P2 Enums iter=%d/%zu", enumIdx, Enums.size());
		enumIdx++;

		if (!IsPtrReadable(Enum)) {
			Buffer.Write<uint32_t>(0);   // name index dummy
			Buffer.Write<uint8_t>(0);    // 0 enum entries
			continue;
		}
		Buffer.Write(NameMap[Enum->GetFName()]);

		auto& EnumNames = Enum->Names();
		int nEnums = EnumNames.Num();
		if (nEnums < 0 || nEnums > 255) nEnums = 0;
		Buffer.Write<uint8_t>(uint8_t(nEnums));

		for (int i = 0; i < nEnums; i++)
		{
			Buffer.Write<int>(NameMap[EnumNames[i].Key]);
		}
	}
	Checkpoint(L"P2 done");

	// v0.0.17.13 : boucle Structs de serialisation avec VirtualQuery gate.
	Checkpoint(L"P3 start V19.16 ATOMIC : Structs.size=%zu", Structs.size());
	Buffer.Write<uint32_t>(Structs.size());

	// v0.0.17.16 : fonction dediee TrySerializeOneStruct avec __try/__except.
	// La lambda contient un std::vector local (C2712 empeche __try dedans), donc
	// on delegue a une fonction free qui gere tout via SEH.
	int structIdx = 0;
	int structSkipped = 0;
	for (auto Struct : Structs)
	{
		if ((structIdx % 100) == 0)
			Checkpoint(L"P3 Structs iter=%d/%zu (skipped=%d)", structIdx, Structs.size(), structSkipped);
		structIdx++;

		// v0.0.19.14 : TrySerializeOneStruct est ATOMIQUE (utilise un StreamWriter
		// local et n'ecrit dans Buffer que si tout est OK). Sur echec, elle ecrit
		// elle-meme un placeholder 12 bytes. Plus besoin de rewind ici.
		uint64_t posBefore = uint64_t(Buffer.GetBuffer().tellp());
		bool ok = TrySerializeOneStruct(Struct, Buffer, NameMap, WriteProperty);
		uint64_t posAfter = uint64_t(Buffer.GetBuffer().tellp());
		if (!ok) structSkipped++;

	}
	Checkpoint(L"P3 done : %d skipped", structSkipped);

	Checkpoint(L"P4 start compression");
	std::vector<uint8_t> UsmapData;

	switch (CompressionMethod)
	{
	case ECompressionMethod::Oodle:
	{
		UsmapData = Oodle::Compress(Buffer.GetBuffer());
		break;
	}
	default:
	{
		// v0.0.17.28 : truncate a tellp() reel pour eviter les garbage residuels
		// laisses au-dela du put pointer par les rewinds P3.
		auto& ss = Buffer.GetBuffer();
		size_t realSize = size_t(ss.tellp());
		std::string UncompressedStream = ss.str();
		if (realSize > UncompressedStream.size()) realSize = UncompressedStream.size();
		UsmapData.resize(realSize);
		if (realSize > 0)
			memcpy(UsmapData.data(), UncompressedStream.data(), realSize);
	}
	}
	Checkpoint(L"P4 done : UsmapData.size=%zu", UsmapData.size());

	// v0.0.19.8 (30/09/2026) : ecrit UNIQUEMENT dans l'emplacement version-scope.
	// v30 (03/10/2026) : refonte -> CLIENT\<region>\<versionKey>\Usmap\Mappings-Aion2-<ts>.usmap
	// L'ancien fallback C:\Users\Public\Mappings-Aion2.usmap est supprime pour
	// eviter la confusion (deux fichiers = deux verites, l'un ecrasant l'autre a
	// chaque dump). La suite (P5b) fait l'ecriture reelle.
	Checkpoint(L"P5 done : UsmapData prete pour P5b (taille=%zu)", UsmapData.size());

	// --- P5b : copie horodatee dans CLIENT\<region>\<versionKey>\Usmap\ ---
	//
	// Auto-detection region + version selon le processus courant :
	//   1. Si l'exe se trouve sous "AION2_TW\..." -> region TW, version lue dans
	//      VersionInfo_A2_TW_L_GA_PURPLE.xml (balise <Version>).
	//   2. Si l'exe se trouve sous "steamapps\common\AION2\..." -> region EU,
	//      version = buildid lu dans steamapps\appmanifest_3393110.acf.
	//   3. Sinon -> "UNKNOWN-_version-inconnue".
	auto ReadFileAll = [](const wchar_t* path, char* out, DWORD outSize) -> DWORD {
		HANDLE h = CreateFileW(path, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) return 0;
		DWORD read = 0;
		ReadFile(h, out, outSize - 1, &read, nullptr);
		CloseHandle(h);
		if (read < outSize) out[read] = 0;
		return read;
	};
	auto TrimVerAscii = [](std::string& v) {
		while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\n' || v.back() == '\t' || v.back() == '"'))
			v.pop_back();
		while (!v.empty() && (v.front() == ' ' || v.front() == '\r' || v.front() == '\n' || v.front() == '\t' || v.front() == '"'))
			v.erase(0, 1);
	};

	// Recupere le chemin de l'exe courant
	wchar_t exePath[MAX_PATH * 2] = {};
	GetModuleFileNameW(nullptr, exePath, MAX_PATH * 2);

	std::string versionKey = "UNKNOWN-_version-inconnue";

	// v30 (03/10/2026) : UMD autonome. Il lit lui-meme la "Version du produit"
	// du exe cible via Shell COM (PKEY_Software_ProductVersion = index 307).
	// Format : "1.0.21.0.2026031801" -> on split au dernier point :
	//   jeu   = "1.0.21.0"
	//   build = "2026031801"
	// => versionKey = "<REGION>-<jeu>-<build>" ex "EU-1.0.21.0-2026031801"
	{
		// Determine la region a partir du chemin
		std::string region;
		if (wcsstr(exePath, L"AION2_TW") != nullptr) {
			region = "TW";
		} else if (wcsstr(exePath, L"steamapps") != nullptr) {
			region = "EU";
		} else {
			region = "UNKNOWN";
		}

		// Lit la Version du produit via Shell COM
		std::string productVersion;
		HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
		const bool coInit = SUCCEEDED(hr);
		IPropertyStore* pStore = nullptr;
		hr = SHGetPropertyStoreFromParsingName(exePath, nullptr, GPS_DEFAULT,
			IID_PPV_ARGS(&pStore));
		if (SUCCEEDED(hr) && pStore) {
			PROPVARIANT pv;
			PropVariantInit(&pv);
			if (SUCCEEDED(pStore->GetValue(kPkeyProductVersion, &pv))) {
				if (pv.vt == VT_LPWSTR && pv.pwszVal) {
					char buf[128] = {};
					WideCharToMultiByte(CP_UTF8, 0, pv.pwszVal, -1, buf, 128, nullptr, nullptr);
					productVersion = buf;
					TrimVerAscii(productVersion);
				}
				PropVariantClear(&pv);
			}
			pStore->Release();
		}
		if (coInit) CoUninitialize();

		// Construit la cle
		if (productVersion.empty()) {
			versionKey = region + "-_version-inconnue";
		} else {
			size_t lastDot = productVersion.find_last_of('.');
			if (lastDot == std::string::npos) {
				versionKey = region + "-" + productVersion;
			} else {
				std::string versionJeu = productVersion.substr(0, lastDot);
				std::string buildId    = productVersion.substr(lastDot + 1);
				if (buildId.empty()) {
					versionKey = region + "-" + versionJeu;
				} else {
					versionKey = region + "-" + versionJeu + "-" + buildId;
				}
			}
		}
	}

	// Log de la cle detectee
	{
		wchar_t wKey[64] = {};
		MultiByteToWideChar(CP_UTF8, 0, versionKey.c_str(), -1, wKey, 64);
		Checkpoint(L"P5b info : versionKey detectee = %s", wKey);
	}

	SYSTEMTIME st;
	GetLocalTime(&st);
	char stamp[32];
	wsprintfA(stamp, "%04d-%02d-%02d-%02dh%02d",
	          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

	// Tag optionnel : Remi ecrit un nom court dans C:\Users\Public\umd-tag.txt
	// avant l'injection (ex: "lvl05-menu", "lvl20-donjon"). Le nom devient
	// Mappings-Aion2-<tag>-<timestamp>.usmap. Si absent ou vide -> pas de tag.
	std::string tag;
	{
		char tagBuf[128] = {};
		DWORD n = ReadFileAll(L"C:\\Users\\Public\\umd-tag.txt", tagBuf, sizeof(tagBuf));
		if (n > 0) {
			tag.assign(tagBuf, tagBuf + strnlen(tagBuf, sizeof(tagBuf)));
			TrimVerAscii(tag);
			// Nettoie les caracteres interdits dans un nom de fichier Windows
			// (<>:"/\|?* + espaces au milieu) -> remplace par '-'.
			for (size_t i = 0; i < tag.size(); i++) {
				char c = tag[i];
				if (c == '<' || c == '>' || c == ':' || c == '"' || c == '/' ||
				    c == '\\' || c == '|' || c == '?' || c == '*' || c == ' ' ||
				    (unsigned char)c < 32) {
					tag[i] = '-';
				}
			}
			// Cap la longueur pour eviter les chemins trop longs
			if (tag.size() > 48) tag.resize(48);
		}
		wchar_t wTag[128] = {};
		if (!tag.empty()) {
			MultiByteToWideChar(CP_UTF8, 0, tag.c_str(), -1, wTag, 128);
			Checkpoint(L"P5b info : tag lu = %s", wTag);
		} else {
			Checkpoint(L"P5b info : pas de tag (umd-tag.txt absent ou vide)");
		}
	}

	// v30 : refonte arborescence CLIENT\<region>\<versionKey>\Usmap
	// region = 2 premiers chars de versionKey ("EU", "TW" ou "UN"...)
	std::string region = versionKey.substr(0, 2);
	std::string clientUsmapDir = "C:\\IA\\Aion\\Aion 2\\Projet\\CLIENT\\"
	                           + region + "\\" + versionKey + "\\Usmap";

	// std::filesystem cree l'arbo entiere (deja inclus dans framework.h, pas de nouvelle dependance).
	// create_directories retourne true si nouveau dossier cree, false si deja existant ou echec.
	// Le vrai indicateur d'echec = fsEc non zero.
	std::error_code fsEc;
	std::filesystem::create_directories(clientUsmapDir, fsEc);
	if (fsEc) {
		wchar_t wErr[64] = {};
		wsprintfW(wErr, L"%d", fsEc.value());
		Checkpoint(L"P5b ERREUR : create_directories a echoue (err=%s) - dump NON copie dans CLIENT\\<region>\\<versionKey>\\Usmap", wErr);
		return;
	}

	// Verifie qu'apres l'appel, le dossier existe reellement (double check).
	if (!std::filesystem::exists(clientUsmapDir, fsEc)) {
		Checkpoint(L"P5b ERREUR : dossier cible inexistant apres create_directories - dump NON copie");
		return;
	}

	// Construit le nom final : Mappings-Aion2[-<tag>]-<timestamp>.usmap
	std::string outUsmapPath = clientUsmapDir + "\\Mappings-Aion2";
	if (!tag.empty()) outUsmapPath += "-" + tag;
	outUsmapPath += "-" + std::string(stamp) + ".usmap";

	// Ouverture safe : verifie fopen_s AVANT d'utiliser FileWriter (qui fait fclose(nullptr)
	// dans son dtor si l'ouverture a echoue).
	FILE* fh = nullptr;
	if (fopen_s(&fh, outUsmapPath.c_str(), "wb") != 0 || fh == nullptr) {
		wchar_t wPath[MAX_PATH * 2] = {};
		MultiByteToWideChar(CP_UTF8, 0, outUsmapPath.c_str(), -1, wPath, MAX_PATH * 2);
		Checkpoint(L"P5b ERREUR : fopen_s a echoue sur %s - dump NON copie", wPath);
		return;
	}
	// Ecrit directement via le FILE* (evite la double ouverture de FileWriter).
	uint16_t magic  = 0x30C4;
	uint8_t  ver    = 3;
	uint8_t  hasVer = 0;
	uint32_t sz     = static_cast<uint32_t>(UsmapData.size());
	fwrite(&magic,  sizeof(magic),  1, fh);
	fwrite(&ver,    sizeof(ver),    1, fh);
	fwrite(&hasVer, sizeof(hasVer), 1, fh);
	fwrite(&CompressionMethod, sizeof(CompressionMethod), 1, fh);
	fwrite(&sz, sizeof(sz), 1, fh);      // compressed
	fwrite(&sz, sizeof(sz), 1, fh);      // decompressed
	size_t wrote = fwrite(UsmapData.data(), 1, UsmapData.size(), fh);
	fflush(fh);
	fclose(fh);

	wchar_t wOutPath[MAX_PATH * 2] = {};
	MultiByteToWideChar(CP_UTF8, 0, outUsmapPath.c_str(), -1, wOutPath, MAX_PATH * 2);
	if (wrote == UsmapData.size()) {
		Checkpoint(L"P5b done : usmap ecrit dans %s (taille=%zu)", wOutPath, wrote);
	} else {
		Checkpoint(L"P5b PARTIEL : ecrit %zu/%zu octets dans %s", wrote, UsmapData.size(), wOutPath);
	}
}