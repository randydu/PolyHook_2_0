//
// Created by randy on 5/11/21.
//
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/Detour/ADetour.hpp"
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/ZydisDisassembler.hpp"
#include <Catch.hpp>

namespace {
void dummy() {}

bool no_reloc(const PLH::Instruction &inst, int64_t delta) {
    return false;
}
bool always_reloc(const PLH::Instruction &inst, int64_t delta) {
    return true;
}

} // namespace

TEMPLATE_TEST_CASE("disp", "[inst]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
    using namespace PLH;

    TestType dis(Mode::x64);

    SECTION("Indirect Call (0xFF,0x15)") {
        constexpr uint64_t target_addr = 0x776DCE00; //call-target
        constexpr int code_size = 6;

        std::vector<uint8_t> codes = {
            0xFF, 0x15, 0x08, 0x00, 0x00, 0x00,             //call qword ptr [rip+8] => 0x776DCE00 (ntdll::RtlSetIoCompletionCallback)
            '*', '*', '*', '*', '*', '*', '*', '*',         //<== code-end
            0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //target
        };

        uint64_t code_start = (uint64_t)codes.data();
        uint64_t code_end = code_start + code_size;
        uint64_t &target = *(uint64_t *)(code_start + 14);

        x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
        const auto &ma = detour.memAccesor();
        insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

        auto &inst = prologue[0];

        SECTION("Check destionation settor/gettor consistency") {
            const uint64_t new_target = 0x1122334455667788;
            CHECK(inst.getDestination() == target_addr);
            CHECK_NOTHROW(inst.setDestination(new_target, ma));
            CHECK(inst.getDestination() == new_target);
            CHECK(target == new_target); //the content of indirect qword is updated.

            CHECK_NOTHROW(inst.setDestination(target_addr, ma)); //rollback
        }

        SECTION("Move Inst to new location") {
            std::vector<uint8_t> expected = {0xFF, 0x15, 0x08, 0x00, 0x00, 0x00};
            std::vector<uint8_t> buf(codes.size());

            const uint64_t new_addr = (uint64_t)buf.data();
            inst.setAddress(new_addr);
            CHECK(inst.getDestination() != target_addr);

            dis.writeEncoding(inst, ma);
            buf.resize(expected.size());
            CHECK(buf == expected); //inst moved to new location without changing bytes
        }
    }
}

TEMPLATE_TEST_CASE("Trampoline", "[x64Detour],[ADetour]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
    using namespace PLH;

    TestType dis(Mode::x64);

    constexpr auto max_trampoline_size = 1024;
    constexpr uint8_t destHldrSz = 8;
    constexpr int MINJMPSIZE = 6; // == getMinJmpSize()

    std::vector<uint8_t> tpl(max_trampoline_size);
    const uint64_t trampoline = (uint64_t)tpl.data();

    SECTION("LEA") {
        /* 
        Win8/x64::Kernelbase::FindNextChangeNotification:

        00007FFEF8212A30 | FFF3                     | push rbx                                |
        00007FFEF8212A32 | 48:83EC 50               | sub rsp,50                              |
        00007FFEF8212A36 | 48:8D05 E32D0C00         | lea rax,qword ptr ds:[7FFEF82D5820]     | <= LEA
        00007FFEF8212A3D | BB 01000000              | mov ebx,1                               |

        Win7/x64::Kernelbase::FindNextChangeNotification:
        000007FEFD332C60 | FFF3                     | push rbx                                |
        000007FEFD332C62 | 48:83EC 50               | sub rsp,50                              |
        000007FEFD332C66 | 48:8D05 33DB0200         | lea rax,qword ptr ds:[7FEFD3607A0]      | <= LEA
        000007FEFD332C6D | BB 01000000              | mov ebx,1                               |

        Win10/x64::Kernelbase::FindNextChangeNotification:
        00007FFF3A2DCFD0 | 40:53                    | push rbx                                |
        00007FFF3A2DCFD2 | 48:83EC 50               | sub rsp,50                              |
        00007FFF3A2DCFD6 | 48:8D05 C3EE2000         | lea rax,qword ptr ds:[7FFF3A4EBEA0]     | <= LEA
        00007FFF3A2DCFDD | BB 01000000              | mov ebx,1                               |
        */
        constexpr int code_size = 13; //prologue size

        std::vector<uint8_t> codes = {
            0xFF, 0xF3,
            0x48, 0x83, 0xEC, 0x50,
            0x48, 0x8D, 0x05, 0xE3, 0x2D, 0x0C, 0x00};

        uint64_t code_start = (uint64_t)codes.data();
        uint64_t code_end = code_start + code_size;

        x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
        const PLH::MemAccessor &ma{detour.memAccesor()};

        insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

        const Instruction &inst = prologue[2];
        CHECK_FALSE(inst.isBranching());
        CHECK_FALSE(inst.isCalling());
        CHECK_FALSE(inst.m_isIndirect);
        CHECK(inst.isDisplacementRelative());

        const int64_t delta = trampoline - code_start;

        insts_t insts_needing_entry;
        insts_t insts_needing_reloc;

        //Currently, we cannot fix out-of-2G MOV/relative instuction if it cannot be relocated.
        CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc) == inst.canRelocate(delta));
    }

    SECTION("MOV") {
        //"Win8/x64
        /*
        Kernelbase::GetFileAttributesW:
        00007FFEF81E9190 | FFF7                     | push rdi                                |
        00007FFEF81E9192 | 48:81EC 90000000         | sub rsp,90                              |
        00007FFEF81E9199 | 48:8B05 58A90E00         | mov rax,qword ptr ds:[7FFEF82D3AF8]     | <= MOV
        00007FFEF81E91A0 | 48:33C4                  | xor rax,rsp                             |

        Kernelbase::GetFileTime:
        00007FFEF8201200 | FFF3                     | push rbx                                |
        00007FFEF8201202 | 56                       | push rsi                                |
        00007FFEF8201203 | 57                       | push rdi                                |
        00007FFEF8201204 | 48:83EC 70               | sub rsp,70                              |
        00007FFEF8201208 | 48:8B05 E9280D00         | mov rax,qword ptr ds:[7FFEF82D3AF8]     | <= MOV
        00007FFEF820120F | 48:33C4                  | xor rax,rsp                             |

        Kernelbase::GetFileSizeEx:
        00007FFEF81E8C30 | FFF3                     | push rbx                                |
        00007FFEF81E8C32 | 48:83EC 60               | sub rsp,60                              |
        00007FFEF81E8C36 | 48:8B05 BBAE0E00         | mov rax,qword ptr ds:[7FFEF82D3AF8]     | <= MOV
        00007FFEF81E8C3D | 48:33C4                  | xor rax,rsp                             |

        Kernelbase::SetFilePointer:
        00007FFEF81E8690 | FFF3                     | push rbx                                |
        00007FFEF81E8692 | 56                       | push rsi                                |
        00007FFEF81E8693 | 57                       | push rdi                                |
        00007FFEF81E8694 | 48:83EC 70               | sub rsp,70                              |
        00007FFEF81E8698 | 48:8B05 59B40E00         | mov rax,qword ptr ds:[7FFEF82D3AF8]     | <= MOV
        00007FFEF81E869F | 48:33C4                  | xor rax,rsp                             |
        */

        // Win7/x64
        /*
        Kernelbase::GetFileInformationByHandle:
        000007FEFD312AF0 | 4C:8BDC                  | mov r11,rsp                             |
        000007FEFD312AF3 | 48:81EC 18010000         | sub rsp,118                             |
        000007FEFD312AFA | 48:8B05 0FD50400         | mov rax,qword ptr ds:[7FEFD360010]      | <= MOV
        000007FEFD312B01 | 48:33C4                  | xor rax,rsp   

        Kernelbase::GetCurrentDirectoryA:
        000007FEFD314740 | FFF5                     | push rbp                                |
        000007FEFD314742 | 56                       | push rsi                                |
        000007FEFD314743 | 48:81EC 68010000         | sub rsp,168                             |
        000007FEFD31474A | 48:8B05 BFB80400         | mov rax,qword ptr ds:[7FEFD360010]      | <= MOV
        000007FEFD314751 | 48:33C4                  | xor rax,rsp                             |
        */

        constexpr int code_size = 16; //prologue size

        std::vector<uint8_t> codes = {
            0xFF, 0xF7,
            0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x05, 0x58, 0xA9, 0x0E, 0x00};

        uint64_t code_start = (uint64_t)codes.data();
        uint64_t code_end = code_start + code_size;

        x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
        const PLH::MemAccessor &ma{detour.memAccesor()};

        insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

        const Instruction &inst = prologue[2];
        CHECK_FALSE(inst.isBranching());
        CHECK_FALSE(inst.isCalling());
        CHECK_FALSE(inst.m_isIndirect);
        CHECK(inst.isDisplacementRelative());

        const int64_t delta = trampoline - code_start;

        insts_t insts_needing_entry;
        insts_t insts_needing_reloc;

        //Currently, we cannot fix out-of-2G MOV/relative instuction if it cannot be relocated.
        CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc) == inst.canRelocate(delta));
    }
    SECTION("Call") {
        SECTION("Indirect Call (0xFF,0x15)") {
            //Win7/x64: BindIoCompletionCallback
            constexpr uint64_t target_addr = 0x776DCE00; //call-target
            constexpr int code_size = 10;                //prologue size

            std::vector<uint8_t> codes = {
                0x48, 0x83, 0xEC, 0x28,                         //sub esp, 28h <== code-start
                0xFF, 0x15, 0x08, 0x00, 0x00, 0x00,             //call qword ptr [rip+8] => 0x776DCE00 (ntdll::RtlSetIoCompletionCallback)
                '*', '*', '*', '*', '*', '*', '*', '*',         //<== code-end
                0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //target
            };

            uint64_t code_start = (uint64_t)codes.data();
            uint64_t code_end = code_start + code_size;

            x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
            const PLH::MemAccessor &ma{detour.memAccesor()};

            insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

            const Instruction &inst = prologue[1];
            CHECK(inst.isBranching());
            CHECK(inst.isCalling());
            CHECK(inst.m_isIndirect);
            CHECK(inst.isDisplacementRelative());
            CHECK(inst.getDestination() == target_addr);

            insts_t insts_needing_entry;
            insts_t insts_needing_reloc;

            const uint64_t prolStart = prologue.front().getAddress();
            CHECK(prolStart == code_start);
            const uint16_t prolSz = calcInstsSz(prologue);
            CHECK(prolSz == code_size);

            SECTION("Near (relocation)") {
                return; //TODO: find a way to test relocation.

                std::vector<uint8_t> expected = {
                    0x48, 0x83, 0xEC, 0x28,             //sub esp, 28h
                    0xFF, 0x15, 0x06, 0x00, 0x00, 0x00, //call qword ptr [rip+6] => 0x776DCE00 (ntdll::RtlSetIoCompletionCallback)
                    0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, //jmp qword ptr [rip+8] => code-end

                    0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //target
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
                };

                tpl.resize(expected.size());
                const int64_t delta = trampoline - prolStart;

                //fill-in the expected code-end
                *(uint64_t *)(expected.data() + expected.size() - 8) = code_end;

                CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc, always_reloc));
                CHECK(insts_needing_entry.size() == 0);
                CHECK(insts_needing_reloc.size() == 1);

                const uint64_t jmpToProlAddr = trampoline + prolSz;
                auto trampolineSz = tpl.size();
                const uint64_t jmpHolderCurAddr = (trampoline + trampolineSz - destHldrSz);
                {
                    const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
                    dis.writeEncoding(jmpToProl, ma);
                }

                const auto makeJmpFn = std::bind(makeJmpX64, _1, _2, jmpHolderCurAddr, MINJMPSIZE, destHldrSz, trampoline, trampolineSz, delta, ma);

                const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
                insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, ma);

                CHECK(tpl == expected);
            }

            SECTION("Far (No relocation)") {

                std::vector<uint8_t> expected = {
                    0x48, 0x83, 0xEC, 0x28,             //sub esp, 28h
                    0xFF, 0x15, 0x06, 0x00, 0x00, 0x00, //call qword ptr [rip+6] => 0x776DCE00 (ntdll::RtlSetIoCompletionCallback)
                    0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, //jmp qword ptr [rip+8] => code-end

                    0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //target
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
                };

                tpl.resize(expected.size());
                const int64_t delta = trampoline - prolStart;

                //fill-in the expected code-end
                *(uint64_t *)(expected.data() + expected.size() - 8) = code_end;

                CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc, no_reloc));
                CHECK(insts_needing_entry.size() == 1);
                CHECK(insts_needing_reloc.size() == 0);

                const uint64_t jmpToProlAddr = trampoline + prolSz;
                auto trampolineSz = tpl.size();
                const uint64_t jmpHolderCurAddr = (trampoline + trampolineSz - destHldrSz);
                {
                    const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
                    dis.writeEncoding(jmpToProl, ma);
                }

                const auto makeJmpFn = std::bind(makeJmpX64, _1, _2, jmpHolderCurAddr, MINJMPSIZE, destHldrSz, trampoline, trampolineSz, delta, ma);

                const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
                insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, ma);

                CHECK(tpl == expected);
            }
            SECTION("Relative Call (0xE8)") {
                /* entry of an api callback
			00007FF7C647014C 40 53                push        rbx  
			00007FF7C647014E 56                   push        rsi  
			00007FF7C647014F 57                   push        rdi  
			00007FF7C6470150 48 83 EC 30          sub         rsp,30h  
			00007FF7C6470154 48 8B F9             mov         rdi,rcx  
			00007FF7C6470157 E8 4C 2D FF FF       call        vm::settings::debug_hooked_api (07FF7C6462EA8h)
			*/
                constexpr int code_size = 16; //prologue size (INPLACE scheme)

                std::vector<uint8_t> codes = {
                    0x40, 0x53,
                    0x56,
                    0x57,
                    0x48, 0x83, 0xEC, 0x30,
                    0x48, 0x8B, 0xF9,
                    0xE8, 0x4C, 0x2D, 0xFF, 0xFF,
                    '*', '*', '*', '*', '*', '*', '*', '*', //<== code-end
                };

                std::vector<uint8_t> expected = {
                    0x40, 0x53,
                    0x56,
                    0x57,
                    0x48, 0x83, 0xEC, 0x30,
                    0x48, 0x8B, 0xF9,
                    0xE8, 0x06, 0x00, 0x00, 0x00, // call eip+6 => local jmp => call-target

                    0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, //jmp qword ptr [rip+0Eh] => code-end
                    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [eip+0]

                    0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //call-target, to be filled manually
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
                };

                tpl.resize(expected.size());

                uint64_t code_start = (uint64_t)codes.data();
                uint64_t code_end = code_start + code_size;

                //fill-in the expected code-end
                *(uint64_t *)(expected.data() + expected.size() - 8) = code_end;

                uint64_t call_target = (uint64_t)(codes.data() + 16 + (int32_t)0xFFFF2D4C); // E8 4C 2D FF FF
                *(uint64_t *)(expected.data() + expected.size() - 16) = call_target;

                x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
                const auto &ma = detour.memAccesor();
                insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

                const Instruction &inst = prologue[5];
                CHECK(inst.isBranching());
                CHECK(inst.isCalling());
                CHECK_FALSE(inst.m_isIndirect);
                CHECK(inst.isDisplacementRelative());
                CHECK(inst.getDestination() == call_target);

                insts_t insts_needing_entry;
                insts_t insts_needing_reloc;

                const uint64_t prolStart = prologue.front().getAddress();
                CHECK(prolStart == code_start);
                const int64_t delta = trampoline - prolStart;

                CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc));
                CHECK(insts_needing_entry.size() == 1);
                CHECK(insts_needing_reloc.size() == 0);

                const uint16_t prolSz = calcInstsSz(prologue);
                CHECK(prolSz == code_size);
                const uint64_t jmpToProlAddr = trampoline + prolSz;
                auto trampolineSz = tpl.size();
                const uint8_t destHldrSz = 8;
                const uint64_t jmpHolderCurAddr = (trampoline + trampolineSz - destHldrSz);
                {
                    const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
                    dis.writeEncoding(jmpToProl, ma);
                }

                const auto makeJmpFn = std::bind(makeJmpX64, _1, _2, jmpHolderCurAddr, MINJMPSIZE, destHldrSz, trampoline, trampolineSz, delta, ma);

                const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
                insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, ma);

                CHECK(tpl == expected);
            }
        }
    }
    SECTION("Jmp") {
        SECTION("Indirect Jmp (0xFF, 0x25)") {
            /*
			00007FFA901E4ED0 | FF25 A2E80600            | jmp qword ptr ds:[<&ReadFileEx>]        |
			*/
            constexpr int code_size = 14; //prologue size (INPLACE_JMP scheme)
            constexpr uint64_t fake_jmp_target = 0xC8C7C6C5C4C3C2C1;

            std::vector<uint8_t> codes = {
                0xFF, 0x25, 0x10, 0x00, 0x00, 0x00, // jmp qword ptr [eip+10h]
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                '*', '*', '*', '*', '*', '*', '*', '*',        //<== code-end
                0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8 //fake jmp target
            };

            uint64_t code_start = (uint64_t)codes.data();
            uint64_t code_end = code_start + code_size;

            x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
            const auto &ma = detour.memAccesor();
            insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

            const Instruction &inst = prologue[0];
            CHECK(inst.isBranching());
            CHECK(inst.m_isIndirect);
            CHECK_FALSE(inst.isCalling());
            CHECK(inst.isDisplacementRelative());
            CHECK(inst.getDestination() == fake_jmp_target);

            insts_t insts_needing_entry;
            insts_t insts_needing_reloc;

            const uint64_t prolStart = prologue.front().getAddress();
            CHECK(prolStart == code_start);
            const int64_t delta = trampoline - prolStart;

            CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc));

            if (inst.canRelocate(delta)) {
                CHECK(insts_needing_entry.size() == 0);
                CHECK(insts_needing_reloc.size() == 1);

            } else {
                CHECK(insts_needing_entry.size() == 1);
                CHECK(insts_needing_reloc.size() == 0);

                std::vector<uint8_t> expected = {
                    0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, // jmp qword ptr [eip+0Eh] => fake-jmp-target
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

                    0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, //jmp qword ptr [rip+0Eh] => code-end (useless code, left for consistency)

                    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, //fake jmp target
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
                };

                //fill-in the expected code-end
                *(uint64_t *)(expected.data() + expected.size() - 8) = code_end;

                const uint16_t prolSz = calcInstsSz(prologue);
                CHECK(prolSz == code_size);
                const uint64_t jmpToProlAddr = trampoline + prolSz;
                auto trampolineSz = tpl.size();
                const uint8_t destHldrSz = 8;
                const uint64_t jmpHolderCurAddr = (trampoline + trampolineSz - destHldrSz);
                {
                    const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
                    dis.writeEncoding(jmpToProl, ma);
                }

                const auto makeJmpFn = std::bind(makeJmpX64, _1, _2, jmpHolderCurAddr, MINJMPSIZE, destHldrSz, trampoline, trampolineSz, delta, ma);

                const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
                insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, ma);

                CHECK(tpl == expected);
            }
        }
        SECTION("Near- Jmp (0xEB)") {
            /* Win8/x64: kernelbase::UnmapViewOfFile()
			00007FFA8F331D70 | 33D2                     | xor edx,edx                             |
			00007FFA8F331D72 | EB AC                    | jmp <kernelbase.UnmapViewOfFileEx>      |
			00007FFA8F331D74 | 90                       | nop                                     |
			00007FFA8F331D75 | 90                       | nop                                     |
			*/

            constexpr int code_size = 6; //prologue size (CODE-CAVE scheme)

            std::vector<uint8_t> codes = {
                0x33, 0xD2,                             // xor edx, edx <== code-start
                0xEB, 0xAC,                             //jmp <kernelbase.UnmapViewOfFileEx>
                0x90, 0x90,                             //NOP, NOP
                '*', '*', '*', '*', '*', '*', '*', '*', //<== code-end
            };

            std::vector<uint8_t> expected = {
                0x33, 0xD2,
                0xEB, 0x08, //jmp eip+8
                0x90, 0x90, //NOP, NOP

                0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, //jmp qword ptr [rip+0Eh] => code-end
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [eip+0]

                0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //jmp-target, to be filled manually
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
            };

            tpl.resize(expected.size());

            uint64_t code_start = (uint64_t)codes.data();
            uint64_t code_end = code_start + code_size;

            //fill-in the expected code-end
            *(uint64_t *)(expected.data() + expected.size() - 8) = code_end;

            uint64_t jmp_target = (uint64_t)(codes.data() + 4 + (int8_t)0xAC); //EB AC
            *(uint64_t *)(expected.data() + expected.size() - 16) = jmp_target;

            x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
            const auto &ma = detour.memAccesor();
            insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

            const Instruction &inst = prologue[1];
            CHECK(inst.isBranching());
            CHECK_FALSE(inst.m_isIndirect);
            CHECK_FALSE(inst.isCalling());
            CHECK(inst.isDisplacementRelative());
            CHECK(inst.getDestination() == jmp_target);

            insts_t insts_needing_entry;
            insts_t insts_needing_reloc;

            const uint64_t prolStart = prologue.front().getAddress();
            CHECK(prolStart == code_start);
            const int64_t delta = trampoline - prolStart;

            CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc));
            CHECK(insts_needing_entry.size() == 1);
            CHECK(insts_needing_reloc.size() == 0);

            const uint16_t prolSz = calcInstsSz(prologue);
            CHECK(prolSz == code_size);
            const uint64_t jmpToProlAddr = trampoline + prolSz;
            auto trampolineSz = tpl.size();
            const uint8_t destHldrSz = 8;
            const uint64_t jmpHolderCurAddr = (trampoline + trampolineSz - destHldrSz);
            {
                const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
                dis.writeEncoding(jmpToProl, ma);
            }

            const auto makeJmpFn = std::bind(makeJmpX64, _1, _2, jmpHolderCurAddr, MINJMPSIZE, destHldrSz, trampoline, trampolineSz, delta, ma);

            const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
            insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, ma);

            CHECK(tpl == expected);
        }
        SECTION("Jmp & Conditional Jmp (JE, JNE)") {
            return; //TODO: allocate a FAR test trampoline (out of reach of JE, JNE, JMP) for tbl-entry based route patch.
            /*
			00007FFA901E4EDC | 80FA 22                  | cmp dl,22                               | 22:'\"'
			00007FFA901E4EDF | 0F84 78C40000            | je kernel32.7FFA901F135D                |
			00007FFA901E4EE5 | 80FA 27                  | cmp dl,27                               | 27:'''
			00007FFA901E4EE8 | 0F85 22E6F5FF            | jne kernel32.7FFA90143510               |
			00007FFA901E4EEE | E9 9E660000              | jmp kernel32.7FFA901EB591               |
			*/

            std::vector<uint8_t> codes = {
                0x80, 0xFA, 0x22,
                0x0F, 0x84, 0x78, 0xC4, 0x00, 0x00, //JE
                0x80, 0xFA, 0x27,
                0x0F, 0x85, 0x22, 0xE6, 0xF5, 0xFF, //JNE
                0xE9, 0x9E, 0x66, 0x00, 0x00,       //JMP
            };
            const int code_size = codes.size(); //prologue size (no detour scheme will output such a long trampoline, just test our algorithm)

            std::vector<uint8_t> expected = {
                0x80, 0xFA, 0x22,
                0x0F, 0x84, 0x14, 0x00, 0x00, 0x00, //JE => jmp-entry of JE
                0x80, 0xFA, 0x27,
                0x0F, 0x85, 0x11, 0x00, 0x00, 0x00, //JNE => jmp-entry of JNE
                0xE9, 0x12, 0x00, 0x00, 0x00,       //JMP => jmp-entry of JMP

                0xFF, 0x25, 0x2A, 0x00, 0x00, 0x00, //jmp qword ptr [rip+2Ah] => code-end

                0xFF, 0x25, 0x1C, 0x00, 0x00, 0x00, // jmp-entry for JE
                0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, // jmp-entry for JNE
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp-entry for JMP

                0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //dest-holder for JMP, to be filled manually
                0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //dest-holder for JNE, to be filled manually
                0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //dest-holder for JE, to be filled manually
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
            };

            tpl.resize(expected.size());

            uint64_t code_start = (uint64_t)codes.data();
            uint64_t code_end = code_start + code_size;

            //fill-in the expected code-end
            *(uint64_t *)(expected.data() + expected.size() - 8) = code_end;

            auto JE_target = (uint64_t)(code_start + 9 + (int32_t)0x0000C478);
            *(uint64_t *)(expected.data() + expected.size() - 16) = JE_target;

            auto JNE_target = (uint64_t)(code_start + 18 + (int32_t)0xFFF5E622);
            *(uint64_t *)(expected.data() + expected.size() - 24) = JNE_target;

            uint64_t JMP_target = (uint64_t)(code_start + code_size + (int32_t)0x0000669E);
            *(uint64_t *)(expected.data() + expected.size() - 32) = JMP_target;

            x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
            const auto &ma = detour.memAccesor();
            insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

            {
                const Instruction &inst = prologue[1]; //JE
                CHECK(inst.isBranching());
                CHECK_FALSE(inst.m_isIndirect);
                CHECK_FALSE(inst.isCalling());
                CHECK(inst.isDisplacementRelative());
                CHECK(inst.getDestination() == JE_target);
            }
            {
                const Instruction &inst = prologue[3]; //JNE
                CHECK(inst.isBranching());
                CHECK_FALSE(inst.m_isIndirect);
                CHECK_FALSE(inst.isCalling());
                CHECK(inst.isDisplacementRelative());
                CHECK(inst.getDestination() == JNE_target);
            }
            {
                const Instruction &inst = prologue[4]; //JMP
                CHECK(inst.isBranching());
                CHECK_FALSE(inst.m_isIndirect);
                CHECK_FALSE(inst.isCalling());
                CHECK(inst.isDisplacementRelative());
                CHECK(inst.getDestination() == JMP_target);
            }

            insts_t insts_needing_entry;
            insts_t insts_needing_reloc;

            const uint64_t prolStart = prologue.front().getAddress();
            CHECK(prolStart == code_start);
            const int64_t delta = trampoline - prolStart;

            CHECK(buildRelocationList(prologue, code_size, delta, insts_needing_entry, insts_needing_reloc));
            CHECK(insts_needing_entry.size() == 3);
            CHECK(insts_needing_reloc.size() == 0);

            const uint16_t prolSz = calcInstsSz(prologue);
            CHECK(prolSz == code_size);
            const uint64_t jmpToProlAddr = trampoline + prolSz;
            auto trampolineSz = tpl.size();
            const uint8_t destHldrSz = 8;
            const uint64_t jmpHolderCurAddr = (trampoline + trampolineSz - destHldrSz);
            {
                const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);
                dis.writeEncoding(jmpToProl, ma);
            }

            const auto makeJmpFn = std::bind(makeJmpX64, _1, _2, jmpHolderCurAddr, MINJMPSIZE, destHldrSz, trampoline, trampolineSz, delta, ma);

            const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
            insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, ma);

            CHECK(tpl == expected);
        }
    }
}