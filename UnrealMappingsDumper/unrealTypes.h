#pragma once

#include <string>
#include <winnt.h>
#include <functional>

#include "unrealEnums.h"
#include "unrealFunctions.h"

#define QUICK_OFFSET(type, offset) (*(type*)((uintptr_t)this + offset))

// v0.0.17.2 PATCH AION 2 : FindObjectByName (juste nom) au lieu de FindObject (path
// complet). Le GetPath() d'Aion 2 construit un path different de "/Script/CoreUObject.X",
// alors que les noms "Class", "ScriptStruct", "Enum" sont uniques dans le pool.
// La macro accepte encore le PATH complet en argument pour ne pas casser d'autres
// invocations existantes ; on extrait le "shortName" apres le dernier '.' via
// runtime helper WcsLastToken.
static FORCEINLINE const wchar_t* WcsLastToken(const wchar_t* s) {
	const wchar_t* last = s;
	for (const wchar_t* p = s; *p; ++p) if (*p == L'.' || *p == L'/') last = p + 1;
	return last;
}
#define DECLARE_STATIC_CLASS(PATH) \
    static FORCEINLINE class UClass* StaticClass() \
	{ \
		static auto Inst = ObjObjects::FindObjectByName<class UClass>(WcsLastToken(PATH)); \
		return Inst; \
	} \

class FName
{
private:

	uint32_t Number = 0;
	uint32_t Padding = 0;

public:

	static inline bool IsOptimized = false;

	__forceinline FName(int InNum) : Number(InNum), Padding(0)
	{
	}

	__forceinline static std::string GetString(int Number)
	{
		return FName(Number).ToString();
	}

	__forceinline uint32_t GetNumber()
	{
		return Number;
	}

	bool operator== (FName n) const
	{
		return Number == n.Number;
	}

	friend size_t hash_value(const FName& p)
	{
		return size_t(p.Number);
	}

	// AION2 : counter SEH pour proteger le call qui crash parfois
	// (FName::AppendString inline en LTCG => hardcoded RVA peut etre faux).
	// On log le nb de crashes et retourne empty au lieu de tuer Aion2.
	static inline volatile long s_FNameCrashCount = 0;
	static inline volatile long s_FNameCallCount = 0;

	static bool SafeCallFNameToString_impl(const void* pThis, FString& Out) noexcept
	{
		__try {
			FNameToString(pThis, Out);
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	std::wstring_view AsString() const
	{
		FString Ret;
		InterlockedIncrement(&s_FNameCallCount);

		if (!SafeCallFNameToString_impl(this, Ret))
		{
			InterlockedIncrement(&s_FNameCrashCount);
			// Log est fait apres le dump dans dumper.cpp via les compteurs statiques
			return {};
		}

		if (Ret.Data() != nullptr)
		{
			return std::wstring_view(Ret.Data());
		}

		return {};
	}

	std::string ToString() const
	{
		auto Ret = AsString();

		return std::string(Ret.begin(), Ret.end());
	}
};

class UObject
{
private:

	static inline int NameOffset = 0;
	static inline int ClassOffset = 0;
	static inline int OuterOffset = 0;

	friend struct IUnrealVersion;

public:

	void GetPathName(std::wstring& Result, UObject* StopOuter = nullptr)
	{
		if (this == StopOuter || this == NULL)
		{
			Result += L"None";
			return;
		}

		if (Outer() && Outer() != StopOuter)
		{
			Outer()->GetPathName(Result, StopOuter);
			Result += L".";
		}

		Result += GetFName().AsString();
	}

	FORCEINLINE std::wstring_view GetName()
	{
		auto& Name = QUICK_OFFSET(FName, NameOffset);
		return Name.AsString();
	}

	FORCEINLINE FName GetFName()
	{
		return QUICK_OFFSET(FName, NameOffset);
	}

	FORCEINLINE std::wstring GetPath()
	{
		std::wstring Ret;

		GetPathName(Ret);

		return Ret;
	}

	FORCEINLINE class UClass* Class()
	{
		return QUICK_OFFSET(class UClass*, ClassOffset);
	}

	FORCEINLINE UObject* Outer()
	{
		return QUICK_OFFSET(UObject*, OuterOffset);
	}
};

class ObjObjects
{
	enum
	{
		NumElementsPerChunk = 64 * 1024,
	};

	static inline ObjObjects* Inst;

public:

	struct FUObjectItem
	{
		UObject* Object;
		int32_t Flags;
		int32_t ClusterRootIndex;
		int32_t SerialNumber;
	};

	ObjObjects& operator=(const ObjObjects&) = delete;

private:

	FUObjectItem** Objects;
	FUObjectItem* PreAllocatedObjects;
	int32_t MaxElements;
	int32_t NumElements;
	int32_t MaxChunks;
	int32_t NumChunks;

public:

	static UObject* GetObjectByIndex(int Index)
	{
		int ChunkIndex = Index / NumElementsPerChunk;
		int WithinChunkIndex = Index % NumElementsPerChunk;

		if (
			Index < Inst->NumElements &&
			Index >= 0 &&
			ChunkIndex < Inst->NumChunks &&
			Index < Inst->MaxElements
			)
		{
			auto Chunk = Inst->Objects[ChunkIndex];

			if (Chunk)
				return (Chunk + WithinChunkIndex)->Object;
		}

		return nullptr;
	}

	static FORCEINLINE int Num()
	{
		return Inst->NumElements;
	}

	static void SetInstance(uintptr_t Val)
	{
		if (Val)
			Inst = (ObjObjects*)Val;
	}

	template <class T = UObject>
	static T* FindObjectByName(const wchar_t* ObjectName)
	{
		for (int i = 0; i < Num(); i++)
		{
			auto Obj = GetObjectByIndex(i);

			if (!Obj) continue;

			if (Obj->GetName() == ObjectName)
				return (T*)Obj;
		}

		return nullptr;
	}

	static void ForEach(std::function<void(UObject*&)> Action)
	{
		for (int i = 0; i < Num(); i++)
		{
			auto Obj = GetObjectByIndex(i);

			if (!Obj) continue;

			Action(Obj);
		}
	}

	template <class T>
	static T* FindObject(std::wstring FullName)
	{
		for (int i = 0; i < Num(); i++)
		{
			auto Obj = GetObjectByIndex(i);

			if (!Obj) continue;

			auto Path = Obj->GetPath();

			if (FullName.size() != Path.size())
				continue;

			bool Same = wcsncmp(FullName.c_str(), Path.c_str(), FullName.size()) == 0;

			if (Same)
				return (T*)Obj;
		}

		return nullptr;
	}
};

class UStruct : public UObject
{
private:

	static inline int SuperOffset = 0;
	static inline int ChildPropertiesOffset = 0;

	friend struct IUnrealVersion;

public:

	FORCEINLINE UStruct* Super()
	{
		return QUICK_OFFSET(UStruct*, SuperOffset);
	}

	FORCEINLINE int32_t PropertiesSize()
	{
		return QUICK_OFFSET(int32_t, ChildPropertiesOffset + sizeof(void*));
	}

	FORCEINLINE class FProperty* ChildProperties()
	{
		return QUICK_OFFSET(class FProperty*, ChildPropertiesOffset);
	}
};

class UClass : public UStruct
{
public:

	DECLARE_STATIC_CLASS(L"/Script/CoreUObject.Class");
};

class UScriptStruct : public UStruct
{
public:

	DECLARE_STATIC_CLASS(L"/Script/CoreUObject.ScriptStruct");
};

class FFieldClass
{
	FName Name;
	EClassCastFlags Id;

public:

	FORCEINLINE FName GetFName()
	{
		return Name;
	}

	FORCEINLINE std::wstring_view GetName()
	{
		return Name.AsString();
	}

	FORCEINLINE EClassCastFlags GetId()
	{
		return Id;
	}
};

class FField
{
public:

	class Variant
	{
		union FFieldObjectUnion
		{
			FField* Field;
			UObject* Object;
		}Container;

		bool bIsUObject;
	};

private:

	// Layout Aion 2 EU (buildid 25624879, valide 30/09/2026 via umd-struct-layout.log):
	//   +0x00: Vtbl (8)
	//   +0x08: ClassPrivate (8)
	//   +0x10: Owner (Variant, 16)
	//   +0x20: NamePrivate (FName, 8)      <- MODIFIE vs vanilla UE 5.3 (+0x28)
	//   +0x28: FlagsPrivate (u32) + pad (4) (8)
	//
	// FProperty EU (herite FField):
	//   +0x30: ArrayDim (u32)               <- observe = 1 sur tous les samples
	//   +0x34: ElementSize (u32)
	//   +0x38-0x40: PropertyFlags + RepIndex + autres
	//   +0x48: Next (FField*, 8)            <- observe pointe sur FField suivant
	// FField total : 0x30 bytes. FProperty total EU : 0x50 bytes.

	void* Vtbl;
	FFieldClass* ClassPrivate;
	Variant Owner;
	FName NamePrivate;              // +0x20
	uint32_t FlagsPrivate_padded;   // +0x28 (u32) + reserved 4 bytes pour tenir en 8
	uint32_t _reserved_2C;          // +0x2C

public:

	FORCEINLINE FName& GetFName()
	{
		return NamePrivate;
	}

	FORCEINLINE FField* GetNext() const
	{
		// Next est en +0x48 sur EU (au sein du sous-type FProperty)
		return *(FField* const*)((const uint8_t*)this + 0x48);
	}

	FORCEINLINE FFieldClass* GetClass() const
	{
		return ClassPrivate;
	}

	FORCEINLINE EObjectFlags GetFlags() const
	{
		if (FName::IsOptimized)
		{
			return QUICK_OFFSET(EObjectFlags, offsetof(FField, NamePrivate) + 4);
		}
		return (EObjectFlags)FlagsPrivate_padded;
	}
};

class FProperty : public FField
{
private:

	// FField vanilla se termine a 0x30. Sur EU FField = 0x30 aussi.
	// FProperty::ArrayDim est directement apres.
	uint32_t ArrayDim;      // +0x30
	uint32_t ElementSize;   // +0x34

public:

	// Public pour permettre la detection dynamique en dehors de IUnrealVersion
	// (voir unrealVersion.cpp TryDetectArrayInnerOffset et autres helpers).
	static inline int FPropertySize = 0;

	friend struct IUnrealVersion;

	FORCEINLINE int32_t GetArrayDim()
	{
		if (FName::IsOptimized)
		{
			return QUICK_OFFSET(int32_t, sizeof(FField) - 8);
		}
		return (int32_t)ArrayDim;
	}
};

class UEnum : public UObject
{
public:

	typedef TArray<TPair<FName, int64_t>> EnumNameMap;

	EnumNameMap& Names()
	{
		// v0.0.19.12 : Aion 2 EU - Names est a +0x40 (verifie via
		// umd-struct-layout.log diag5 : EAutomationEventType +0x40 = 'Info',
		// ERangeBoundTypes +0x40 = 'Exclusive'). Vanilla UE 5.3 utilisait
		// FieldSize + sizeof(FString) qui ne matche pas sur EU.
		return QUICK_OFFSET(EnumNameMap, 0x40);
	}

	DECLARE_STATIC_CLASS(L"/Script/CoreUObject.Enum");
};

class FStructProperty : public FProperty
{
	UScriptStruct* Struct;

public:

	FORCEINLINE UScriptStruct* GetStruct()
	{
		return QUICK_OFFSET(UScriptStruct*, FPropertySize);
	}
};

class FByteProperty : public FProperty
{
	UEnum* Enum;

public:

	FORCEINLINE UEnum* GetEnum()
	{
		return QUICK_OFFSET(UEnum*, FPropertySize);
	}
};

class FArrayProperty : public FProperty
{
	enum class EArrayPropertyFlags
	{
		None,
		UsesMemoryImageAllocator
	};

	// Ordre reel dans Aion 2 (detecte dynamiquement) :
	// Avant 5.3 : { FProperty* Inner; EArrayPropertyFlags ArrayFlags; }
	//   -> Inner a FPropertySize
	// En 5.3+   : { EArrayPropertyFlags ArrayFlags; FProperty* Inner; }
	//   -> Inner a FPropertySize + 8 (ArrayFlags int32 + padding 4)
	// L'ArrayInnerExtraOffset est calcule au runtime par
	// TryDynamicOffsets() via UGameViewportClient::DebugProperties
	// (meme technique que Dumper-7 FindInnerTypeOffset).

public:

	// = 0 pour UE <= 5.2, = 8 pour UE 5.3+. Detecte au runtime.
	static inline int ArrayInnerExtraOffset = 0;

	FORCEINLINE FProperty* GetInner()
	{
		return QUICK_OFFSET(FProperty*, FPropertySize + ArrayInnerExtraOffset);
	}
};

class FMapProperty : public FProperty
{
	FProperty* KeyProp;
	FProperty* ValueProp;

public:

	FORCEINLINE FProperty* GetKey()
	{
		return QUICK_OFFSET(FProperty*, FPropertySize);
	}

	FORCEINLINE FProperty* GetValue()
	{
		return QUICK_OFFSET(FProperty*, FPropertySize + sizeof(FProperty*));
	}
};

class FEnumProperty : public FProperty
{
	FProperty* UnderlyingProp;
	UEnum* Enum;

public:

	FORCEINLINE FProperty* GetUnderlying()
	{
		return QUICK_OFFSET(FProperty*, FPropertySize);
	}

	FORCEINLINE UEnum* GetEnum()
	{
		return QUICK_OFFSET(UEnum*, FPropertySize + sizeof(FProperty*));
	}
};