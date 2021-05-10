//
// Created by steve on 7/9/18.
//
#include <Catch.hpp>
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/Detour/ADetour.hpp"
#include "polyhook2/CapstoneDisassembler.hpp"
#include "polyhook2/ZydisDisassembler.hpp"

#include "polyhook2/Tests/StackCanary.hpp"
#include "polyhook2/Tests/TestEffectTracker.hpp"

EffectTracker effects;

/**These tests can spontaneously fail if the compiler desides to optimize away
the handler or inline the function. NOINLINE attempts to fix the latter, the former
is out of our control but typically returning volatile things, volatile locals, and a
printf inside the body can mitigate this significantly. Do serious checking in debug
or releasewithdebinfo mode (relwithdebinfo optimizes sliiiightly less)**/

NOINLINE void hookMe1() {
	PLH::StackCanary canary;
	volatile int var = 1;
	volatile int var2 = 0;
	var2 += 3;
	var2 = var + var2;
	var2 *= 30 / 3;
	var = 2;
	printf("%d %d\n", var, var2); // 2, 40
	REQUIRE(var == 2);
	REQUIRE(var2 == 40);
}
uint64_t hookMe1Tramp = NULL;
HOOK_CALLBACK(&hookMe1, h_hookMe1, {
	PLH::StackCanary canary;
	std::cout << "Hook 1 Called!" << std::endl;
	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMe1Tramp, &hookMe1)();
});

NOINLINE void hookMe2() {
	PLH::StackCanary canary;
	for (int i = 0; i < 10; i++) {
		printf("%d\n", i);
	}
}
uint64_t hookMe2Tramp = NULL;
HOOK_CALLBACK(&hookMe2, h_hookMe2, {
	PLH::StackCanary canary;
	std::cout << "Hook 2 Called!" << std::endl;
	effects.PeakEffect().trigger();
	return PLH::FnCast(hookMe2Tramp, &hookMe2)();
});

unsigned char hookMe3[] = {
0x57, // push rdi 
0x74,0xf9,
0x74, 0xf0,//je 0x0
0x90, 0x90, 0x90, 0x90,
0x90, 0x90, 0x90, 0x90,
0x90, 0x90, 0x90, 0x90,
0xc3
};

unsigned char hookMe4[] = {
	0x57, // push rdi
	0x48, 0x83, 0xec, 0x30, //sub rsp, 0x30
	0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90,
	0x74,0xf2, //je 0x0
	0xc3
};

uint64_t nullTramp = NULL;
NOINLINE void h_nullstub() {
	PLH::StackCanary canary;
	volatile int i = 0;
	PH_UNUSED(i);
}

#include <stdlib.h>
uint64_t hookMallocTramp = NULL;
HOOK_CALLBACK(&malloc, h_hookMalloc, {
	PLH::StackCanary canary;
	volatile int i = 0;
	PH_UNUSED(i);
	effects.PeakEffect().trigger();

	return PLH::FnCast(hookMallocTramp, &malloc)(_args...);
});

uint64_t oCreateMutexExA = 0;
HOOK_CALLBACK(&CreateMutexExA, hCreateMutexExA, {
	PLH::StackCanary canary;
	LPCSTR lpName = GET_ARG(1);
	printf("kernel32!CreateMutexExA  Name:%s",  lpName);
	return PLH::FnCast(oCreateMutexExA, &CreateMutexExA)(_args...);
});

TEMPLATE_TEST_CASE("Testing 64 detours", "[x64Detour],[ADetour]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
	TestType dis(PLH::Mode::x64);


	SECTION("Normal function") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe1, (char*)h_hookMe1, &hookMe1Tramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Normal function rehook")
	{
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe1, (char*)h_hookMe1, &hookMe1Tramp, dis);
		REQUIRE(detour.hook() == true);
		
		effects.PushEffect();
		REQUIRE(detour.reHook() == true); // can only really test this doesn't cause memory corruption easily
		hookMe1();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	// In release mode win apis usually go through two levels of jmps 
	/*
	0xe9 ... jmp iat_thunk

	iat_thunk:
	0xff 25 ... jmp [api_implementation]

	api_implementation:
	    sub rsp, ...
		... the goods ...
	*/
	SECTION("WinApi Indirection") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&CreateMutexExA, (char*)hCreateMutexExA, &oCreateMutexExA, dis);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Loop function") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe2, (char*)h_hookMe2, &hookMe2Tramp, dis);
		REQUIRE(detour.hook() == true);

		effects.PushEffect();
		hookMe2();
		REQUIRE(effects.PopEffect().didExecute());
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prol w/src in range") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe3, (char*)&h_nullstub, &nullTramp, dis);
		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("Jmp into prol w/src out of range") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&hookMe4, (char*)&h_nullstub, &nullTramp, dis);

		REQUIRE(detour.hook() == true);
		REQUIRE(detour.unHook() == true);
	}

	SECTION("hook malloc") {
		PLH::StackCanary canary;
		PLH::x64Detour detour((char*)&malloc, (char*)h_hookMalloc, &hookMallocTramp, dis);
		effects.PushEffect(); // catch does some allocations, push effect first so peak works
		bool result = detour.hook();

		REQUIRE(result == true);

		void* pMem = malloc(16);
		free(pMem);
		detour.unHook(); // unhook so we can popeffect safely w/o catch allocation happening again
		REQUIRE(effects.PopEffect().didExecute());
	}
}

namespace {
	void dummy(){}
}

TEMPLATE_TEST_CASE("Trampoline", "[x64Detour],[ADetour]", PLH::CapstoneDisassembler, PLH::ZydisDisassembler) {
	using namespace PLH;

	TestType dis(Mode::x64);

	constexpr int MINJMPSIZE = 6; // == getMinJmpSize()

	SECTION("Call"){
		SECTION("Indirect Call (0xFF,0x15)"){
			//Win7/x64: BindIoCompletionCallback
			constexpr uint64_t target_addr = 0x776DCE00; //call-target
			constexpr int code_size = 10; //prologue size

			std::vector<uint8_t> codes = {
				0x48, 0x83, 0xEC, 0x28, 						//sub esp, 28h <== code-start
				0xFF, 0x15, 0x08, 0x00, 0x00, 0x00, 			//call qword ptr [rip+8] => 0x776DCE00 (ntdll::RtlSetIoCompletionCallback)
				'*', '*', '*', '*', '*', '*', '*', '*', 		//<== code-end
				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //target
			};

			std::vector<uint8_t> expected = {
				0x48, 0x83, 0xEC, 0x28, //sub esp, 28h
				0xFF, 0x15, 0x06, 0x00, 0x00, 0x00, //call qword ptr [rip+6] => 0x776DCE00 (ntdll::RtlSetIoCompletionCallback)
				0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, //jmp qword ptr [rip+8] => code-end

				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //target
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
			};

			std::vector<uint8_t> tpl(expected.size());

			uint64_t code_start = (uint64_t)codes.data();
			uint64_t code_end = code_start + code_size;

			//fill-in the expected code-end
			*(uint64_t*)(expected.data() + expected.size() - 8) = code_end;
		
			x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
			insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

			const Instruction& inst = prologue[1];
			CHECK(inst.isBranching());
			CHECK(inst.isCalling());
			CHECK(inst.m_isIndirect);
			CHECK(inst.isDisplacementRelative());
			CHECK(inst.getDestination() == target_addr);

			insts_t insts_needing_entry;
			insts_t insts_needing_reloc;

			const uint64_t prolStart = prologue.front().getAddress();
			CHECK(prolStart == code_start);
			const uint64_t trampoline = (uint64_t)tpl.data();
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
				dis.writeEncoding(jmpToProl, detour);
			}

			// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
			const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, PLH::Instruction& inst) mutable {
				captureAddress -= destHldrSz;
				assert(captureAddress > (uint64_t)trampoline && (captureAddress + destHldrSz) < (trampoline + trampolineSz));

				// move inst to trampoline and point instruction to entry
				auto oldDest = inst.getDestination();
				inst.setAddress(inst.getAddress() + delta);

				bool destHolderOnly = inst.m_isIndirect; //re-use the call instrunction's own displacement storage, no need for extra JMP [xxx]
				inst.setDestination( destHolderOnly ? captureAddress : a);

				return destHolderOnly ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(a, oldDest, captureAddress);
			};

			const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
			insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, MINJMPSIZE, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, detour);

			CHECK(tpl == expected);
		}
		SECTION("Relative Call (0xE8)"){
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
				'*', '*', '*', '*', '*', '*', '*', '*', 		//<== code-end
			};

			std::vector<uint8_t> expected = {
				0x40, 0x53,
				0x56,
				0x57,
				0x48, 0x83, 0xEC, 0x30,
				0x48, 0x8B, 0xF9,
				0xE8, 0x06, 0x00, 0x00, 0x00,  // call eip+6 => local jmp => call-target

				0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, //jmp qword ptr [rip+0Eh] => code-end
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,	// jmp [eip+0]

				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //call-target, to be filled manually
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
			};

			std::vector<uint8_t> tpl(expected.size());

			uint64_t code_start = (uint64_t)codes.data();
			uint64_t code_end = code_start + code_size;

			//fill-in the expected code-end
			*(uint64_t*)(expected.data() + expected.size() - 8) = code_end;

			uint64_t call_target = (uint64_t)(codes.data() + 16 + (int32_t)0xFFFF2D4C); // E8 4C 2D FF FF
			*(uint64_t*)(expected.data() + expected.size() - 16) = call_target;
		
			x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
			insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

			const Instruction& inst = prologue[5];
			CHECK(inst.isBranching());
			CHECK(inst.isCalling());
			CHECK_FALSE(inst.m_isIndirect);
			CHECK(inst.isDisplacementRelative());
			CHECK(inst.getDestination() == call_target);

			insts_t insts_needing_entry;
			insts_t insts_needing_reloc;

			const uint64_t prolStart = prologue.front().getAddress();
			CHECK(prolStart == code_start);
			const uint64_t trampoline = (uint64_t)tpl.data();
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
				dis.writeEncoding(jmpToProl, detour);
			}

			// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
			const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, PLH::Instruction& inst) mutable {
				captureAddress -= destHldrSz;
				assert(captureAddress > (uint64_t)trampoline && (captureAddress + destHldrSz) < (trampoline + trampolineSz));

				// move inst to trampoline and point instruction to entry
				auto oldDest = inst.getDestination();
				inst.setAddress(inst.getAddress() + delta);

				bool destHolderOnly = inst.m_isIndirect; //re-use the call instrunction's own displacement storage, no need for extra JMP [xxx]
				inst.setDestination( destHolderOnly ? captureAddress : a);

				return destHolderOnly ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(a, oldDest, captureAddress);
			};

			const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
			insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, MINJMPSIZE, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, detour);

			CHECK(tpl == expected);
		}
	}
	SECTION("Jmp"){
		SECTION("Indirect Jmp (0xFF, 0x25)"){
			/*
			00007FFA901E4ED0 | FF25 A2E80600            | jmp qword ptr ds:[<&ReadFileEx>]        |
			*/
			constexpr int code_size = 14; //prologue size (INPLACE_JMP scheme)
			constexpr uint64_t fake_jmp_target = 0xC8C7C6C5C4C3C2C1;

			std::vector<uint8_t> codes = {
				0xFF, 0x25, 0x10, 0x00, 0x00, 0x00,  // jmp qword ptr [eip+10h]
				0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
				'*', '*', '*', '*', '*', '*', '*', '*', 		//<== code-end
				0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8  //fake jmp target
			};

			std::vector<uint8_t> expected = {
				0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00,  // jmp qword ptr [eip+0Eh] => fake-jmp-target
				0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

				0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, //jmp qword ptr [rip+0Eh] => code-end (useless code, left for consistency)

				0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,  //fake jmp target
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
			};

			std::vector<uint8_t> tpl(expected.size());

			uint64_t code_start = (uint64_t)codes.data();
			uint64_t code_end = code_start + code_size;

			//fill-in the expected code-end
			*(uint64_t*)(expected.data() + expected.size() - 8) = code_end;

		
			x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
			insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

			const Instruction& inst = prologue[0];
			CHECK(inst.isBranching());
			CHECK(inst.m_isIndirect);
			CHECK_FALSE(inst.isCalling());
			CHECK(inst.isDisplacementRelative());
			CHECK(inst.getDestination() == fake_jmp_target);

			insts_t insts_needing_entry;
			insts_t insts_needing_reloc;

			const uint64_t prolStart = prologue.front().getAddress();
			CHECK(prolStart == code_start);
			const uint64_t trampoline = (uint64_t)tpl.data();
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
				dis.writeEncoding(jmpToProl, detour);
			}

			// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
			const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, PLH::Instruction& inst) mutable {
				captureAddress -= destHldrSz;
				assert(captureAddress > (uint64_t)trampoline && (captureAddress + destHldrSz) < (trampoline + trampolineSz));

				// move inst to trampoline and point instruction to entry
				auto oldDest = inst.getDestination();
				inst.setAddress(inst.getAddress() + delta);

				bool destHolderOnly = inst.m_isIndirect; //re-use the call instrunction's own displacement storage, no need for extra JMP [xxx]
				inst.setDestination( destHolderOnly ? captureAddress : a);

				return destHolderOnly ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(a, oldDest, captureAddress);
			};

			const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
			insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, MINJMPSIZE, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, detour);

			CHECK(tpl == expected);

		}
		SECTION("Near- Jmp (0xEB)"){
			/* Win8/x64: kernelbase::UnmapViewOfFile()
			00007FFA8F331D70 | 33D2                     | xor edx,edx                             |
			00007FFA8F331D72 | EB AC                    | jmp <kernelbase.UnmapViewOfFileEx>      |
			00007FFA8F331D74 | 90                       | nop                                     |
			00007FFA8F331D75 | 90                       | nop                                     |
			*/

			constexpr int code_size = 6; //prologue size (CODE-CAVE scheme)

			std::vector<uint8_t> codes = {
				0x33, 0xD2, 			// xor edx, edx <== code-start
				0xEB, 0xAC, 			//jmp <kernelbase.UnmapViewOfFileEx>
				0x90, 0x90,				//NOP, NOP
				'*', '*', '*', '*', '*', '*', '*', '*', 		//<== code-end
			};

			std::vector<uint8_t> expected = {
				0x33, 0xD2,
				0xEB, 0x08, 			//jmp eip+8
				0x90, 0x90,				//NOP, NOP

				0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, //jmp qword ptr [rip+0Eh] => code-end
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,	// jmp [eip+0]

				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //jmp-target, to be filled manually
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
			};

			std::vector<uint8_t> tpl(expected.size());

			uint64_t code_start = (uint64_t)codes.data();
			uint64_t code_end = code_start + code_size;

			//fill-in the expected code-end
			*(uint64_t*)(expected.data() + expected.size() - 8) = code_end;

			uint64_t jmp_target = (uint64_t)(codes.data() + 4 + (int8_t)0xAC); //EB AC
			*(uint64_t*)(expected.data() + expected.size() - 16) = jmp_target;
		
			x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
			insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

			const Instruction& inst = prologue[1];
			CHECK(inst.isBranching());
			CHECK_FALSE(inst.m_isIndirect);
			CHECK_FALSE(inst.isCalling());
			CHECK(inst.isDisplacementRelative());
			CHECK(inst.getDestination() == jmp_target);

			insts_t insts_needing_entry;
			insts_t insts_needing_reloc;

			const uint64_t prolStart = prologue.front().getAddress();
			CHECK(prolStart == code_start);
			const uint64_t trampoline = (uint64_t)tpl.data();
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
				dis.writeEncoding(jmpToProl, detour);
			}

			// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
			const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, PLH::Instruction& inst) mutable {
				captureAddress -= destHldrSz;
				assert(captureAddress > (uint64_t)trampoline && (captureAddress + destHldrSz) < (trampoline + trampolineSz));

				// move inst to trampoline and point instruction to entry
				auto oldDest = inst.getDestination();
				inst.setAddress(inst.getAddress() + delta);

				bool destHolderOnly = inst.m_isIndirect; //re-use the call instrunction's own displacement storage, no need for extra JMP [xxx]
				inst.setDestination( destHolderOnly ? captureAddress : a);

				return destHolderOnly ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(a, oldDest, captureAddress);
			};

			const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
			insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, MINJMPSIZE, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, detour);

			CHECK(tpl == expected);
		}
		SECTION("Jmp & Conditional Jmp (JE, JNE)"){
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
				0xE9, 0x9E, 0x66, 0x00, 0x00,  		//JMP
			};
			const int code_size = codes.size(); //prologue size (no detour scheme will output such a long trampoline, just test our algorithm)

			std::vector<uint8_t> expected = {
				0x80, 0xFA, 0x22,
				0x0F, 0x84, 0x14, 0x00, 0x00, 0x00, //JE => jmp-entry of JE
				0x80, 0xFA, 0x27,
				0x0F, 0x85, 0x11, 0x00, 0x00, 0x00, //JNE => jmp-entry of JNE
				0xE9, 0x12, 0x00, 0x00, 0x00,  		//JMP => jmp-entry of JMP

				0xFF, 0x25, 0x2A, 0x00, 0x00, 0x00, //jmp qword ptr [rip+2Ah] => code-end

				0xFF, 0x25, 0x1C, 0x00, 0x00, 0x00,	// jmp-entry for JE
				0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00,	// jmp-entry for JNE
				0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,	// jmp-entry for JMP

				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //dest-holder for JMP, to be filled manually
				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //dest-holder for JNE, to be filled manually
				0x00, 0xCE, 0x6D, 0x77, 0x00, 0x00, 0x00, 0x00, //dest-holder for JE, to be filled manually
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //code-end, to be filled manually
			};

			std::vector<uint8_t> tpl(expected.size());

			uint64_t code_start = (uint64_t)codes.data();
			uint64_t code_end = code_start + code_size;

			//fill-in the expected code-end
			*(uint64_t*)(expected.data() + expected.size() - 8) = code_end;

			auto JE_target = (uint64_t)(code_start + 9 + (int32_t)0x0000C478);
			*(uint64_t*)(expected.data() + expected.size() - 16) = JE_target;

			auto JNE_target = (uint64_t)(code_start + 18 + (int32_t)0xFFF5E622);
			*(uint64_t*)(expected.data() + expected.size() - 24) = JNE_target;

			uint64_t JMP_target = (uint64_t)(code_start + code_size + (int32_t)0x0000669E);
			*(uint64_t*)(expected.data() + expected.size() - 32) = JMP_target;
		
			x64Detour detour(code_start, (uint64_t)&dummy, nullptr, dis);
			insts_t prologue = dis.disassemble(code_start, code_start, code_end, detour);

			{
				const Instruction& inst = prologue[1]; //JE
				CHECK(inst.isBranching());
				CHECK_FALSE(inst.m_isIndirect);
				CHECK_FALSE(inst.isCalling());
				CHECK(inst.isDisplacementRelative());
				CHECK(inst.getDestination() == JE_target);
			}
			{
				const Instruction& inst = prologue[3]; //JNE
				CHECK(inst.isBranching());
				CHECK_FALSE(inst.m_isIndirect);
				CHECK_FALSE(inst.isCalling());
				CHECK(inst.isDisplacementRelative());
				CHECK(inst.getDestination() == JNE_target);
			}
			{
				const Instruction& inst = prologue[4]; //JMP
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
			const uint64_t trampoline = (uint64_t)tpl.data();
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
				dis.writeEncoding(jmpToProl, detour);
			}

			// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
			const auto makeJmpFn = [=, captureAddress = jmpHolderCurAddr](uint64_t a, PLH::Instruction& inst) mutable {
				captureAddress -= destHldrSz;
				assert(captureAddress > (uint64_t)trampoline && (captureAddress + destHldrSz) < (trampoline + trampolineSz));

				// move inst to trampoline and point instruction to entry
				auto oldDest = inst.getDestination();
				inst.setAddress(inst.getAddress() + delta);

				bool destHolderOnly = inst.m_isIndirect; //re-use the call instrunction's own displacement storage, no need for extra JMP [xxx]
				inst.setDestination( destHolderOnly ? captureAddress : a);

				return destHolderOnly ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(a, oldDest, captureAddress);
			};

			const uint64_t jmpTblStart = jmpToProlAddr + MINJMPSIZE;
			insts_t trampolineOut = processTrampoline(prologue, jmpTblStart, delta, MINJMPSIZE, makeJmpFn, insts_needing_reloc, insts_needing_entry, dis, detour);

			CHECK(tpl == expected);


		}
	}
}