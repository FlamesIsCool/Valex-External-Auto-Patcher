#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>

#pragma pack(push, 1)
struct DOS_HEADER { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc; uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss; uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo; uint16_t e_res2[10]; int32_t e_lfanew; };
struct PE_HEADER { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; };
struct OPTIONAL_HEADER64 { uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; };
struct SECTION_HEADER { char Name[8]; uint32_t VirtualSize; uint32_t VirtualAddress; uint32_t SizeOfRawData; uint32_t PointerToRawData; uint32_t PointerToRelocations; uint32_t PointerToLinenumbers; uint16_t NumberOfRelocations; uint16_t NumberOfLinenumbers; uint32_t Characteristics; };
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: patcher.exe <input.exe> [output.exe]\n";
        return 1;
    }

    std::string input = argv[1];
    std::string output = (argc > 2) ? argv[2] : "patched_" + std::string(input.substr(input.find_last_of("\\/") + 1));

    std::ifstream in(input, std::ios::binary);
    if (!in) { std::cerr << "Cannot open input file\n"; return 1; }
    in.seekg(0, std::ios::end);
    size_t size = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    in.read((char*)buf.data(), size);
    in.close();

    auto* dos = (DOS_HEADER*)buf.data();
    if (dos->e_magic != 0x5A4D) { std::cerr << "Not MZ\n"; return 1; }
    auto* pe = (PE_HEADER*)(buf.data() + dos->e_lfanew);
    if (pe->Signature != 0x4550) { std::cerr << "Not PE\n"; return 1; }
    auto* opt = (OPTIONAL_HEADER64*)((uint8_t*)pe + sizeof(PE_HEADER));
    if (opt->Magic != 0x20B) { std::cerr << "Not x64\n"; return 1; }
    uint64_t image_base = opt->ImageBase;
    auto* sections = (SECTION_HEADER*)((uint8_t*)opt + pe->SizeOfOptionalHeader);

    std::string failed_str = "Authentication failed";
    std::string success_str = "Authentication successful.";
    std::vector<size_t> failed_pos, success_pos;

    for (size_t i = 0; i <= size - failed_str.size(); ++i)
        if (memcmp(&buf[i], failed_str.c_str(), failed_str.size()) == 0)
            failed_pos.push_back(i);
    for (size_t i = 0; i <= size - success_str.size(); ++i)
        if (memcmp(&buf[i], success_str.c_str(), success_str.size()) == 0)
            success_pos.push_back(i);

    if (failed_pos.empty() || success_pos.empty()) {
        std::cerr << "Auth strings not found\n"; return 1;
    }

    auto file_to_va = [&](size_t off) -> uint64_t {
        for (int s = 0; s < pe->NumberOfSections; ++s) {
            auto& sec = sections[s];
            if (off >= sec.PointerToRawData && off < sec.PointerToRawData + sec.SizeOfRawData)
                return image_base + sec.VirtualAddress + (off - sec.PointerToRawData);
        }
        return 0;
        };

    uint64_t failed_lea_va = 0, success_lea_va = 0, jne_va = 0;
    int32_t jne_rel = 0;

    for (int s = 0; s < pe->NumberOfSections; ++s) {
        auto& sec = sections[s];
        if (!(sec.Characteristics & 0x20000000)) continue;
        size_t start = sec.PointerToRawData;
        size_t end = start + sec.SizeOfRawData;
        uint32_t rva_base = sec.VirtualAddress;

        for (size_t i = start; i + 7 < end; ++i) {
            if (buf[i] == 0x48 && buf[i + 1] == 0x8D && buf[i + 2] == 0x05) {
                int32_t rel = *(int32_t*)&buf[i + 3];
                uint64_t instr_va = image_base + rva_base + (i - start);
                uint64_t target = instr_va + 7 + rel;

                for (auto pos : failed_pos) if (file_to_va(pos) == target) failed_lea_va = instr_va;
                for (auto pos : success_pos) if (file_to_va(pos) == target) success_lea_va = instr_va;
            }
        }
    }

    if (failed_lea_va == 0 || success_lea_va == 0) {
        std::cerr << "LEA instructions not found\n";
        return 1;
    }

    std::cout << "[INFO] Success LEA at: 0x" << std::hex << success_lea_va << "\n";

    for (int s = 0; s < pe->NumberOfSections; ++s) {
        auto& sec = sections[s];
        if (!(sec.Characteristics & 0x20000000)) continue;
        size_t start = sec.PointerToRawData;
        size_t end = start + sec.SizeOfRawData;
        uint32_t rva_base = sec.VirtualAddress;

        for (size_t i = start; i + 6 < end; ++i) {
            if (buf[i] == 0x84 && buf[i + 1] == 0xC0 && buf[i + 2] == 0x0F && buf[i + 3] == 0x85) {
                int32_t rel = *(int32_t*)&buf[i + 4];
                uint64_t instr_va = image_base + rva_base + (i - start);
                uint64_t target = instr_va + 6 + rel;

                if (target >= success_lea_va - 8 && target <= success_lea_va + 8) {
                    jne_va = instr_va;
                    jne_rel = rel;
                    std::cout << "[FOUND] JNE at 0x" << std::hex << jne_va << " -> 0x" << target << " (near success LEA)\n";
                    break;
                }
            }
        }
        if (jne_va) break;
    }

    if (jne_va == 0) {
        std::cerr << "JNE near success LEA not found\n";
        return 1;
    }

    auto patch_at_va = [&](uint64_t va, auto patch_func) {
        size_t rva = va - image_base;
        for (int s = 0; s < pe->NumberOfSections; ++s) {
            auto& sec = sections[s];
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.SizeOfRawData) {
                size_t file_off = sec.PointerToRawData + (rva - sec.VirtualAddress);
                patch_func(file_off);
                return true;
            }
        }
        return false;
        };

    patch_at_va(failed_lea_va, [&](size_t off) {
        int64_t new_rel = file_to_va(success_pos[0]) - (failed_lea_va + 7);
        *(int32_t*)&buf[off + 3] = (int32_t)new_rel;
        std::cout << "[1] Patched LEA: failed -> success at 0x" << std::hex << failed_lea_va << "\n";
        });

    patch_at_va(jne_va, [&](size_t off) {
        buf[off + 2] = 0xE9;
        *(int32_t*)&buf[off + 3] = jne_rel + 1;
        std::cout << "[2] Patched JNE -> JMP at 0x" << std::hex << jne_va << "\n";
        });

    std::ofstream out(output, std::ios::binary);
    out.write((char*)buf.data(), size);
    out.close();

    std::cout << "\nSUCCESS: Authentication fully bypassed!\n";
    std::cout << "Output: " << output << "\n";
    return 0;
}
