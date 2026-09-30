#pragma once
//
// aion2Offsets.h — v0.0.19.6 (D.11)
//
// Charge les 3 offsets Aion 2 (GObjects, FNamePool, GWorld) depuis un
// fichier JSON externe au chargement de UMD.dll. Si le fichier est absent
// ou invalide, on fallback aux valeurs hardcodees (post-maj 22/09/2026).
//
// Objectif : plus jamais patcher UMD.dll binaire apres un patch Aion 2.
// L'app AION2 Studio met a jour offsets-aion2.json + UMD lit ce fichier
// au prochain chargement.
//
// Emplacement du fichier (par ordre de priorite) :
//   1) %TEMP%\DumperAion2\offsets-aion2.json  (extrait par AION2 Studio)
//   2) C:\Users\Public\offsets-aion2.json     (fallback publique)
//
// Format attendu (extrait, seules 3 cles utilisees) :
//   {
//     "Offsets": {
//       "GObjects":  "0xEC54A40",
//       "FNamePool": "0xF1071C0",
//       "GWorld":    "0xEF64938"
//     }
//   }
//
// Contraintes UMD :
//   - /MT /NODEFAULTLIB : ZERO CRT, pas de <stdio.h>, pas de fopen/fread
//   - WinAPI pur : CreateFileW + ReadFile + CloseHandle
//   - Parser JSON minimal fait maison (200 lignes) : cherche les 3 cles,
//     extrait les valeurs "0x...", parse en uintptr_t. Aucune dependance.
//   - Idempotent : appeler ChargerUneFois() plusieurs fois est sans effet
//     apres la 1re initialisation.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>

namespace Aion2Offsets
{
    // Valeurs par defaut hardcodees (fallback si JSON absent/invalide).
    // Post-maj 22/09/2026.
    static constexpr uintptr_t DEFAUT_GOBJECTS  = 0x0EC54A40;
    static constexpr uintptr_t DEFAUT_FNAMEPOOL = 0x0F1071C0;
    static constexpr uintptr_t DEFAUT_GWORLD    = 0x0EF64938;

    // Cache runtime (rempli au 1er appel a ChargerUneFois)
    static uintptr_t g_GObjects  = 0;
    static uintptr_t g_FNamePool = 0;
    static uintptr_t g_GWorld    = 0;
    static bool      g_Charge    = false;
    static wchar_t   g_Source[256] = { 0 };  // pour trace : chemin fichier lu, ou "defauts"

    // ==== Utils sans CRT ====

    // Concatene deux chemins wide (basique : ne verifie pas les slashes).
    static void wcat(wchar_t* dst, size_t cap, const wchar_t* src)
    {
        size_t n = 0;
        while (n < cap - 1 && dst[n]) ++n;
        while (n < cap - 1 && *src) dst[n++] = *src++;
        dst[n] = 0;
    }

    // Cherche une sous-chaine (case-sensitive) dans buffer[0..len].
    // Retourne le pointeur au debut du match, ou nullptr.
    static const char* find_str(const char* buf, size_t len, const char* needle)
    {
        size_t nlen = 0;
        while (needle[nlen]) ++nlen;
        if (nlen == 0 || nlen > len) return nullptr;
        for (size_t i = 0; i + nlen <= len; ++i)
        {
            bool match = true;
            for (size_t j = 0; j < nlen; ++j)
            {
                if (buf[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return buf + i;
        }
        return nullptr;
    }

    // Parse un uintptr_t depuis "0xXXX" ou "0XXXX" (le X initial optionnel).
    // Retourne 0 si echec.
    static uintptr_t parse_hex(const char* p, const char* end)
    {
        // Skip whitespace
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == '"')) ++p;
        // Optional 0x prefix
        if (p + 1 < end && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        uintptr_t v = 0;
        int digits = 0;
        while (p < end && digits < 16)
        {
            char c = *p;
            uintptr_t d;
            if      (c >= '0' && c <= '9') d = (uintptr_t)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (uintptr_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (uintptr_t)(c - 'A' + 10);
            else break;
            v = (v << 4) | d;
            ++p;
            ++digits;
        }
        return v;
    }

    // Cherche "key" : "0x..." dans le JSON et retourne la valeur parseee.
    // Format cherche : "GObjects":"0xEC54A40" ou "GObjects": "0xEC54A40" (avec espace).
    // 0 si non trouve.
    static uintptr_t extract_offset(const char* buf, size_t len, const char* key)
    {
        // Construction naive du pattern "GObjects" avec guillemets
        char pattern[64];
        int plen = 0;
        pattern[plen++] = '"';
        while (*key && plen < 61) pattern[plen++] = *key++;
        pattern[plen++] = '"';
        pattern[plen] = 0;

        const char* found = find_str(buf, len, pattern);
        if (!found) return 0;
        // Avance apres la cle, cherche ':' puis '"'
        const char* p = found + plen;
        const char* end = buf + len;
        while (p < end && *p != ':') ++p;
        if (p >= end) return 0;
        ++p; // skip ':'
        // Skip whitespace jusqu'au premier '"'
        while (p < end && *p != '"') ++p;
        if (p >= end) return 0;
        ++p; // skip guillemet ouvrant

        // parse_hex s'arrete au premier char non-hex (dont le guillemet fermant)
        uintptr_t val = parse_hex(p, end);
        return val;
    }

    // Lit un fichier entier via WinAPI (max 64 Ko). Retourne le buffer alloue
    // via HeapAlloc (a HeapFree apres usage) et setLen le nb octets lus.
    // nullptr si echec.
    static char* read_file_all(const wchar_t* path, DWORD* outLen)
    {
        *outLen = 0;
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return nullptr;

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 65536)
        {
            CloseHandle(h);
            return nullptr;
        }
        DWORD size = (DWORD)sz.QuadPart;
        HANDLE heap = GetProcessHeap();
        char* buf = (char*)HeapAlloc(heap, 0, size + 1);
        if (!buf) { CloseHandle(h); return nullptr; }
        DWORD read = 0;
        BOOL ok = ReadFile(h, buf, size, &read, nullptr);
        CloseHandle(h);
        if (!ok || read == 0) { HeapFree(heap, 0, buf); return nullptr; }
        buf[read] = 0;
        *outLen = read;
        return buf;
    }

    // Charge les 3 offsets depuis le premier JSON trouve. Idempotent.
    static void ChargerUneFois()
    {
        if (g_Charge) return;
        g_Charge = true;

        // Defauts par avance (au cas ou tout echoue)
        g_GObjects  = DEFAUT_GOBJECTS;
        g_FNamePool = DEFAUT_FNAMEPOOL;
        g_GWorld    = DEFAUT_GWORLD;
        // Marque : par defaut = "defauts"
        const wchar_t defaut_label[] = L"defauts-hardcodes";
        for (int i = 0; defaut_label[i] && i < 255; ++i) g_Source[i] = defaut_label[i];

        // Chemins candidats
        wchar_t temp[MAX_PATH] = { 0 };
        DWORD nTemp = GetTempPathW(MAX_PATH, temp);
        if (nTemp == 0 || nTemp >= MAX_PATH) return;

        wchar_t path1[MAX_PATH] = { 0 };
        for (DWORD i = 0; i < nTemp; ++i) path1[i] = temp[i];
        wcat(path1, MAX_PATH, L"DumperAion2\\offsets-aion2.json");

        const wchar_t path2[] = L"C:\\Users\\Public\\offsets-aion2.json";

        const wchar_t* candidats[2] = { path1, path2 };

        for (int i = 0; i < 2; ++i)
        {
            DWORD len = 0;
            char* buf = read_file_all(candidats[i], &len);
            if (!buf) continue;

            uintptr_t gobj = extract_offset(buf, len, "GObjects");
            uintptr_t fnp  = extract_offset(buf, len, "FNamePool");
            uintptr_t gw   = extract_offset(buf, len, "GWorld");
            HeapFree(GetProcessHeap(), 0, buf);

            // Validation basique : les 3 offsets doivent etre non-nuls
            // et dans une plage plausible pour Aion2 (base 0x140000000,
            // taille ~0x19685000 = ~400 Mo). RVA typique 0x00100000-0x19700000.
            bool valides = (gobj > 0x100000 && gobj < 0x20000000)
                        && (fnp  > 0x100000 && fnp  < 0x20000000)
                        && (gw   > 0x100000 && gw   < 0x20000000);
            if (!valides) continue;

            g_GObjects  = gobj;
            g_FNamePool = fnp;
            g_GWorld    = gw;
            // Enregistre source
            for (int k = 0; k < 255 && candidats[i][k]; ++k) g_Source[k] = candidats[i][k];
            g_Source[255] = 0;
            break;
        }
    }

    // ==== API simple ====
    static uintptr_t GObjects()  { ChargerUneFois(); return g_GObjects;  }
    static uintptr_t FNamePool() { ChargerUneFois(); return g_FNamePool; }
    static uintptr_t GWorld()    { ChargerUneFois(); return g_GWorld;    }
    static const wchar_t* Source() { ChargerUneFois(); return g_Source; }
}
