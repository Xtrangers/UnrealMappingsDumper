#include "pch.h"

#include "dumper.h"
#include "writer.h"
#include "oodle.h"
#include "aion2Offsets.h"

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

template<class NameMapT, class WritePropFn>
static bool TrySerializeOneStruct(UStruct* Struct, StreamWriter& Buffer,
    NameMapT& NameMap, WritePropFn& WriteProperty) noexcept
{
    if (!IsPtrReadable(Struct)) return false;
    __try
    {
        Buffer.Write(NameMap[Struct->GetFName()]);

        UStruct* Super = Struct->Super();
        Buffer.Write<int32_t>(IsPtrReadable(Super) ? NameMap[Super->GetFName()] : int32_t(0xffffffff));

        // Pass 1 : count PropCount + SerializablePropCount
        FProperty* first = Struct->ChildProperties();
        FProperty* Props = first;
        uint16_t PropCount = 0;
        uint16_t SerializablePropCount = 0;
        int guardMax = 4096;
        while (IsPtrReadable(Props) && guardMax-- > 0)
        {
            uint16_t dim = uint16_t(Props->GetArrayDim());
            PropCount += dim;
            SerializablePropCount++;
            Props = static_cast<FProperty*>(Props->GetNext());
        }

        Buffer.Write(PropCount);
        Buffer.Write(SerializablePropCount);

        // Pass 2 : serialize
        Props = first;
        uint16_t indexAcc = 0;
        int guardMax2 = 4096;
        while (IsPtrReadable(Props) && guardMax2-- > 0)
        {
            uint16_t dim = uint16_t(Props->GetArrayDim());
            Buffer.Write<uint16_t>(indexAcc);
            Buffer.Write<uint8_t>(uint8_t(dim));    // v0.0.19.4 post-maj : u8 pas u16 (CUE4Parse attend byte)
            Buffer.Write(NameMap[Props->GetFName()]);
            EPropertyType t = GetPropertyType(Props);
            WriteProperty(Props, t);
            indexAcc += dim;
            Props = static_cast<FProperty*>(Props->GetNext());
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
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

	std::function<void(class FProperty*&, EPropertyType)> WritePropertyWrapper{}; // hacky.. i know

	auto WriteProperty = [&](FProperty*& Prop, EPropertyType Type)
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
			// v0.0.19.11 EU : validation defensive pour eviter crash sur pointeurs
			// invalides (sous-classes de FProperty avec layout non-standard).
			if (!IsPtrReadable(Inner)) {
				Buffer.Write(EPropertyType::Unknown);
				Buffer.Write<int32_t>(0);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType);
			auto EnumObj = EnumProp->GetEnum();
			if (IsPtrReadable(EnumObj))
				Buffer.Write(NameMap[EnumObj->GetFName()]);
			else
				Buffer.Write<int32_t>(0);

			break;
		}
		case EPropertyType::EnumAsByteProperty:
		{
			Buffer.Write(EPropertyType::ByteProperty);
			auto EnumObj = static_cast<FByteProperty*>(Prop)->GetEnum();
			if (IsPtrReadable(EnumObj))
				Buffer.Write(NameMap[EnumObj->GetFName()]);
			else
				Buffer.Write<int32_t>(0);

			break;
		}
		case EPropertyType::StructProperty:
		{
			auto StructObj = static_cast<FStructProperty*>(Prop)->GetStruct();
			if (IsPtrReadable(StructObj))
				Buffer.Write(NameMap[StructObj->GetFName()]);
			else
				Buffer.Write<int32_t>(0);
			break;
		}
		case EPropertyType::SetProperty:
		case EPropertyType::ArrayProperty:
		{
			auto Inner = static_cast<FArrayProperty*>(Prop)->GetInner();
			if (!IsPtrReadable(Inner)) {
				Buffer.Write(EPropertyType::Unknown);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType);

			break;
		}
		case EPropertyType::MapProperty:
		{
			auto Inner = static_cast<FMapProperty*>(Prop)->GetKey();
			auto Value = static_cast<FMapProperty*>(Prop)->GetValue();
			if (!IsPtrReadable(Inner) || !IsPtrReadable(Value)) {
				Buffer.Write(EPropertyType::Unknown);
				Buffer.Write(EPropertyType::Unknown);
				break;
			}
			auto InnerType = GetPropertyType(Inner);
			WritePropertyWrapper(Inner, InnerType);

			auto ValueType = GetPropertyType(Value);
			WritePropertyWrapper(Value, ValueType);

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
	Checkpoint(L"P3 start : Structs.size=%zu", Structs.size());
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

		// v0.0.17.28 : Sauver position AVANT TrySerializeOneStruct. Si crash au
		// milieu, on rewind et ecrit un placeholder valide 12 bytes -> les prochaines
		// writes overwritent le garbage. Sans ca le parser lit un struct avec
		// nameIdx/serPropCount corrompu -> desync.
		uint32_t posBefore = uint32_t(Buffer.GetBuffer().tellp());
		bool ok = TrySerializeOneStruct(Struct, Buffer, NameMap, WriteProperty);
		if (!ok) {
			structSkipped++;
			Buffer.GetBuffer().seekp(posBefore);  // rewind
			Buffer.Write<uint32_t>(0);
			Buffer.Write<int32_t>(int32_t(0xffffffff));
			Buffer.Write<uint16_t>(0);
			Buffer.Write<uint16_t>(0);
		}
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

	// v0.0.17.25 (30/09/2026) : ecrit dans DEUX endroits.
	//   1. C:\Users\Public\Mappings-Aion2.usmap  (compat + fallback historique)
	//   2. CLIENT-EXTRAIT\SCHEMAS\versions\<REGION-Version>\dumps\umd\Mappings-Aion2-<ts>.usmap
	//      (rangement par version du client Aion 2, cf. reorg 30/09/2026)
	//
	// Lit la version dynamiquement dans :
	//   C:\IA\Aion\Aion 2\Client\AION2_TW\VersionInfo_A2_TW_L_GA_PURPLE.xml (balise <Version>)
	//   -> cle "TW-<version>", fallback "TW-_version-inconnue" sinon.
	Checkpoint(L"P5 start WriteFile usmap");
	auto FileOutput = FileWriter("C:\\Users\\Public\\Mappings-Aion2.usmap");

	// v0.0.17.24 : usmap v3+ (compat CUE4Parse/FModel).
	FileOutput.Write<uint16_t>(0x30C4);          // magic
	FileOutput.Write<uint8_t>(3);                // version 3 (support u16 name length)
	FileOutput.Write<uint8_t>(0);                // bHasVersioning = 0
	FileOutput.Write(CompressionMethod);         // compression
	FileOutput.Write<uint32_t>(UsmapData.size());       // compressed size
	FileOutput.Write<uint32_t>(uint32_t(UsmapData.size())); // decompressed size (= comp car None ; ancienne Buffer.Size() incluait garbage residuel)

	FileOutput.Write(UsmapData.data(), UsmapData.size());
	Checkpoint(L"P5 done : usmap ECRIT (taille compressed=%zu decompressed=%zu)",
	           UsmapData.size(), (size_t)Buffer.Size());

	// --- P5b : copie horodatee dans SCHEMAS\versions\<REGION-Version>\dumps\umd\ ---
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

	// --- Piste TW : chemin contient "AION2_TW" ---
	if (wcsstr(exePath, L"AION2_TW") != nullptr) {
		char buf[2048] = {};
		DWORD n = ReadFileAll(
			L"C:\\IA\\Aion\\Aion 2\\Client\\AION2_TW\\VersionInfo_A2_TW_L_GA_PURPLE.xml",
			buf, sizeof(buf));
		versionKey = "TW-_version-inconnue";
		if (n > 0) {
			const char* op = strstr(buf, "<Version>");
			if (op) {
				op += 9;
				const char* cl = strstr(op, "</Version>");
				if (cl && cl > op && (cl - op) <= 16) {
					std::string ver(op, cl - op);
					TrimVerAscii(ver);
					if (!ver.empty()) versionKey = "TW-" + ver;
				}
			}
		}
	}
	// --- Piste EU : chemin contient "steamapps\common\AION2" ---
	else if (wcsstr(exePath, L"steamapps") != nullptr) {
		char buf[4096] = {};
		DWORD n = ReadFileAll(
			L"C:\\Program Files (x86)\\Steam\\steamapps\\appmanifest_3393110.acf",
			buf, sizeof(buf));
		versionKey = "EU-_version-inconnue";
		if (n > 0) {
			// Format ACF Steam : "buildid"\t\t"25624879"\n
			// Apres la cle "buildid" (fermee par "), on cherche le PROCHAIN " qui
			// ouvre la valeur, puis le " qui la ferme.
			const char* op = strstr(buf, "\"buildid\"");
			if (op) {
				op += 9;                        // saute "buildid" (9 chars)
				op = strchr(op, '"');           // ouverture de la valeur
				if (op) {
					op++;                       // debut de la valeur
					const char* cl = strchr(op, '"'); // fermeture
					if (cl && cl > op && (cl - op) <= 16) {
						std::string ver(op, cl - op);
						TrimVerAscii(ver);
						if (!ver.empty()) versionKey = "EU-" + ver;
					}
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

	std::string schemaBase = "C:\\IA\\Aion\\Aion 2\\Projet\\CLIENT-EXTRAIT\\SCHEMAS\\versions\\"
	                       + versionKey + "\\dumps\\umd";

	// std::filesystem cree l'arbo entiere (deja inclus dans framework.h, pas de nouvelle dependance).
	// create_directories retourne true si nouveau dossier cree, false si deja existant ou echec.
	// Le vrai indicateur d'echec = fsEc non zero.
	std::error_code fsEc;
	std::filesystem::create_directories(schemaBase, fsEc);
	if (fsEc) {
		wchar_t wErr[64] = {};
		wsprintfW(wErr, L"%d", fsEc.value());
		Checkpoint(L"P5b ERREUR : create_directories a echoue (err=%s) - dump NON copie en SCHEMAS", wErr);
		return;
	}

	// Verifie qu'apres l'appel, le dossier existe reellement (double check).
	if (!std::filesystem::exists(schemaBase, fsEc)) {
		Checkpoint(L"P5b ERREUR : dossier cible inexistant apres create_directories - dump NON copie");
		return;
	}

	// Construit le nom final : Mappings-Aion2[-<tag>]-<timestamp>.usmap
	std::string schemaFile = schemaBase + "\\Mappings-Aion2";
	if (!tag.empty()) schemaFile += "-" + tag;
	schemaFile += "-" + std::string(stamp) + ".usmap";

	// Ouverture safe : verifie fopen_s AVANT d'utiliser FileWriter (qui fait fclose(nullptr)
	// dans son dtor si l'ouverture a echoue).
	FILE* fh = nullptr;
	if (fopen_s(&fh, schemaFile.c_str(), "wb") != 0 || fh == nullptr) {
		wchar_t wPath[MAX_PATH * 2] = {};
		MultiByteToWideChar(CP_UTF8, 0, schemaFile.c_str(), -1, wPath, MAX_PATH * 2);
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

	wchar_t wSchemaFile[MAX_PATH * 2] = {};
	MultiByteToWideChar(CP_UTF8, 0, schemaFile.c_str(), -1, wSchemaFile, MAX_PATH * 2);
	if (wrote == UsmapData.size()) {
		Checkpoint(L"P5b done : usmap AUSSI ECRIT dans %s (taille=%zu)", wSchemaFile, wrote);
	} else {
		Checkpoint(L"P5b PARTIEL : ecrit %zu/%zu octets dans %s", wrote, UsmapData.size(), wSchemaFile);
	}
}