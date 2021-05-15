//
// Created by steve on 7/5/17.
//
#include <sstream>
#include <algorithm>
#include <functional>

#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/Misc.hpp"
#include "polyhook2/MemProtector.hpp"
#include "polyhook2/PE/PEB.hpp"

PLH::x64Detour::x64Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis), m_allocator(8, 100) {

}

PLH::x64Detour::x64Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis), m_allocator(8, 100) {

}

PLH::x64Detour::~x64Detour()
{
	if (m_valloc2_region) {
		m_allocator.deallocate(*m_valloc2_region);
		m_valloc2_region = {};
	}
}

PLH::Mode PLH::x64Detour::getArchType() const {
	return PLH::Mode::x64;
}

uint8_t PLH::x64Detour::getMinJmpSize() const {
	return 6;
}

uint8_t PLH::x64Detour::getPrefJmpSize() const {
	return 16;
}

PLH::x64Detour::detour_scheme_t PLH::x64Detour::getDetourScheme() const{
	return _detourScheme;
}

void PLH::x64Detour::setDetourScheme(detour_scheme_t scheme){
	_detourScheme = scheme;
}

namespace {	

	struct gc_t {
		uint64_t begin;
		uint64_t end;
		uint64_t pos; //current available position

		uint64_t alloc(uint16_t size){
			auto addr = begin + pos;
			if(addr + size <= end){
				pos += size;
				return addr;
			}
			return 0; //fails
		}
		
		//allocate inside range [low, high)
		uint64_t allocInRange(uint64_t low, uint64_t high, uint16_t size){
			auto addr = begin + pos;
			if(addr >= low && addr < high && addr + size <= end){
				pos += size;
				return addr;
			}
			return 0;
		}
	};

	using gsc_t = std::vector<gc_t>;

	struct module_t {
		std::wstring_view name;
		uint64_t begin;
		uint64_t end;
		gsc_t gcs;

		module_t(const std::wstring_view& nm, uint64_t b, uint64_t e):name(nm), begin(b), end(e){}
		bool has(uint64_t addr) const {
			return addr >= begin && addr < end;
		}

		uint64_t allocWithin2G(uint64_t addr, uint16_t size) {
			auto low_2g = PLH::calc_2gb_below(addr);
			auto high_2g = PLH::calc_2gb_above(addr);
			if(begin >= high_2g || end <= low_2g) return 0;

			for(auto& gc: gcs){
				if(auto found = gc.allocInRange(low_2g, high_2g, size); found)
					return found;
			}
			return 0; //fails
		}

		uint64_t alloc(uint16_t size){
			for(auto& gc: gcs){
				if(auto found = gc.alloc(size); found)
					return found;
			}
			return 0; //fails
		}
	};

	std::vector<std::shared_ptr<module_t>> modules;

	bool parseModule(std::shared_ptr<module_t> md){
		uint64_t moduleBase = md->begin;

		IMAGE_DOS_HEADER* pImg = (IMAGE_DOS_HEADER*)moduleBase;
		if(pImg->e_magic != IMAGE_DOS_SIGNATURE) return false; //Invalid pe header
		
		IMAGE_NT_HEADERS64* pNtHdr = (IMAGE_NT_HEADERS64*)(moduleBase + pImg->e_lfanew);
		if(pNtHdr->Signature != IMAGE_NT_SIGNATURE) return false; //Invalid NT header
		if(pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false; //Invalid PE64 image

		IMAGE_SECTION_HEADER* pSec = (IMAGE_SECTION_HEADER*)(pNtHdr + 1); 
		int N = pNtHdr->FileHeader.NumberOfSections;
		for(int i = 0; i < N; i++, pSec++){
			char name[IMAGE_SIZEOF_SHORT_NAME + 1]{0};
			memcpy(name, &pSec->Name[0], IMAGE_SIZEOF_SHORT_NAME);

			auto begin = moduleBase + pSec->VirtualAddress;
			auto end = i == N-1 ? md->end : (moduleBase + (pSec+1)->VirtualAddress);

			if(strcmp(name, ".reloc") == 0){//.reloc section is useless after loading.
				PLH_INFO("adds hole >> [%ls] %s: [%I64X, %I64X) len [%I64d]\n", md->name.data(), name, begin, end, end - begin);
				md->gcs.push_back({ begin, end, 0 });
			} else {
				//reuse gap between sections if possible
				auto vsize = std::max(pSec->SizeOfRawData, pSec->Misc.VirtualSize);
				if(begin + vsize < end){
					PLH_INFO("adds hole >> [%ls] %s: [%I64X, %I64X) len [%I64d]\n", md->name.data(), name, begin + vsize, end, end - begin -vsize);
					md->gcs.push_back({
						begin + vsize, end, 0
					});
				}
			}
		}
		return true;
	}

	void initModuleList(){
		if(!modules.empty()) return; //already initialized

		PEB* peb = (PPEB)__readgsqword(0x60);

		PEB_LDR_DATA* ldr = (PPEB_LDR_DATA)peb->Ldr;

		// find loaded module from peb
		for (auto* dte = (LDR_DATA_TABLE_ENTRY*)ldr->InLoadOrderModuleList.Flink;
			dte->DllBase != NULL;
			dte = (LDR_DATA_TABLE_ENTRY*)dte->InLoadOrderLinks.Flink) {
				uint64_t dllBase = (uint64_t)dte->DllBase;
				std::wstring_view nm(dte->BaseDllName.Buffer, dte->BaseDllName.Length);
				auto module = std::make_shared<module_t>(nm, dllBase, dllBase + dte->SizeOfImage);
				if(parseModule(module))
					modules.push_back(module);
		}

		int N = modules.size();
		int sum = 0;
		PLH_INFO("******** GC Sumamry ********\n");
		PLH_INFO("Total modules: %d\n\n", N);
		for(int i = 0; i < N; i++){
			const auto& md = *modules[i];
			int j = 0;
			for(const auto& gc: md.gcs){
				j += (gc.end - gc.pos - gc.begin);
			}
			sum += j;
			PLH_INFO("[%d/%d] [%I64X, %I64X) %ls: total free bytes = %d\n", i, N, md.begin, md.end, md.name.data(), j);
		}
		PLH_INFO("\nTotal free bytes: %d\n\n", sum);
	}

	uint64_t findCodeCaveInModule(uint64_t addr, uint16_t size){
		initModuleList();

		//try allocating in the hosting module 
		//PE32+ images allow for a 64-bit address space while limiting the image size to 2 gigabytes.
		for(auto& m: modules){
			if(m->has(addr)){
				if(auto found = m->alloc(size); found)
					return found;
			}
		}
		//try allocating in nearby modules
		for(auto& m: modules){
			if(auto found = m->allocWithin2G(addr, size); found)
				return found;
		}
		return 0;
	}
}

template<uint16_t SIZE>
std::optional<uint64_t> PLH::x64Detour::findNearestCodeCave(uint64_t addr) {
	//First search in loaded PE modules.
	if(auto found = findCodeCaveInModule(addr, SIZE); found)
		return found;

	const uint64_t chunkSize = 64000;
	unsigned char* data = new unsigned char[chunkSize];
	auto delete_data = finally([=]() {
		delete[] data;
	});

	// RPM so we don't pagefault, careful to check for partial reads
	
	// these patterns are listed in order of most accurate to least accurate with size taken into account
	// simple c3 ret is more accurate than c2 ?? ?? and series of CC or 90 is more accurate than complex multi-byte nop
	std::string CC_PATTERN_RET = "c3 " + repeat_n("cc", SIZE, " ");
	std::string NOP1_PATTERN_RET = "c3 " + repeat_n("90", SIZE, " ");

	std::string CC_PATTERN_RETN = "c2 ?? ?? " + repeat_n("cc", SIZE, " ");
	std::string NOP1_PATTERN_RETN = "c2 ?? ?? " + repeat_n("90", SIZE, " ");

	const char* NOP2_RET = "c3 0f 1f 44 00 00";
	const char* NOP3_RET = "c3 0f 1f 84 00 00 00 00 00";
	const char* NOP4_RET = "c3 66 0f 1f 84 00 00 00 00 00";
	const char* NOP5_RET = "c3 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP6_RET = "c3 cc cc cc cc cc cc 66 0f 1f 44 00 00";
	const char* NOP7_RET = "c3 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP8_RET = "c3 cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
	const char* NOP9_RET = "c3 cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP10_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP11_RET = "c3 cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	
	const char* NOP2_RETN = "c2 ?? ?? 0f 1f 44 00 00";
	const char* NOP3_RETN = "c2 ?? ?? 0f 1f 84 00 00 00 00 00";
	const char* NOP4_RETN = "c2 ?? ?? 66 0f 1f 84 00 00 00 00 00";
	const char* NOP5_RETN = "c2 ?? ?? 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP6_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 44 00 00";
	const char* NOP7_RETN = "c2 ?? ?? 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP8_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 0f 1f 84 00 00 00 00 00";
	const char* NOP9_RETN = "c2 ?? ?? cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP10_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";
	const char* NOP11_RETN = "c2 ?? ?? cc cc cc cc cc cc cc 66 66 0f 1f 84 00 00 00 00 00";

	// Scan in same order as listing above
	const char* PATTERNS_OFF1[] = {
		CC_PATTERN_RET.c_str(), NOP1_PATTERN_RET.c_str(),
		NOP2_RET, NOP3_RET, NOP4_RET, NOP5_RET,NOP6_RET,
		NOP7_RET, NOP8_RET, NOP9_RET, NOP10_RET, NOP11_RET
	};

	const char* PATTERNS_OFF3[] = {
		CC_PATTERN_RETN.c_str(), NOP1_PATTERN_RETN.c_str(),
		NOP2_RETN, NOP3_RETN, NOP4_RETN, NOP5_RETN,NOP6_RETN,
		NOP7_RETN, NOP8_RETN, NOP9_RETN, NOP10_RETN, NOP11_RETN,
	};

	// Most common:
	// https://gist.github.com/stevemk14ebr/d117e8d0fd1432fb2a92354a034ce5b9
	// We check for rets to verify it's not like like a mid function or jmp table pad
	// [0xc3 | 0xC2 ? ? ? ? ] & 6666666666660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 0f1f440000
	// [0xc3 | 0xC2 ? ? ? ? ] & 0f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f440000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccccccccccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & cccccccccccc66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 66660f1f840000000000
	// [0xc3 | 0xC2 ? ? ? ? ] & 660f1f840000000000

	// Search 2GB below
	for (uint64_t search = addr - chunkSize; (search + chunkSize) >= calc_2gb_below(addr); search -= chunkSize) {
		size_t read = 0;
		if (safe_mem_read(search, (uint64_t)data, chunkSize, read)) {
			assert(read <= chunkSize);
			if (read == 0 || read < SIZE)
				continue;

			auto finder = [&](const char* pattern, const uint64_t offset) -> std::optional<uint64_t> {
				if (auto found = (uint64_t)findPattern_rev((uint64_t)data, read, pattern)) {
					return search + (found + offset - (uint64_t)data);
				}
				return {};
			};

			for (const char* pat : PATTERNS_OFF1) {
				if(getPatternSize(pat) - 1 < SIZE) 
					continue;

				if (auto found = finder(pat, 1)) {
					return found;
				}
			}

			for (const char* pat : PATTERNS_OFF3) {
				if(getPatternSize(pat) - 3 < SIZE) 
					continue;

				if (auto found = finder(pat, 3)) {
					return found;
				}
			}
		}
	}

	// Search 2GB above
	for (uint64_t search = addr; (search + chunkSize) < calc_2gb_above(addr); search += chunkSize) {
		size_t read = 0;
		if (safe_mem_read(search, (uint64_t)data, chunkSize, read)) {
			uint32_t contiguousInt3 = 0;
			uint32_t contiguousNop = 0;

			assert(read <= chunkSize);
			if (read == 0 || read < SIZE)
				continue;

			auto finder = [&](const char* pattern, const uint64_t offset) -> std::optional<uint64_t> {
				if (auto found = (uint64_t)findPattern((uint64_t)data, read, pattern)) {
					return search + (found + offset - (uint64_t)data);
				}
				return {};
			};

			for (const char* pat : PATTERNS_OFF1) {
				if(getPatternSize(pat) - 1 < SIZE) 
					continue;

				if (auto found = finder(pat, 1)) {
					return found;
				}
			}

			for (const char* pat : PATTERNS_OFF3) {
				if(getPatternSize(pat) - 3 < SIZE) 
					continue;

				if (auto found = finder(pat, 3)) {
					return found;
				}
			}
		}
	}
	return {};
}

namespace {

#pragma pack(push, 1)

//13 bytes (mov r10, dest; push r10; ret)
struct InplaceDetour {
	uint16_t mov_r10 { 0xba49 };
	uint64_t target;
	uint16_t push_r10 { 0x5241 };
	uint8_t ret {0xc3};
};

//14 bytes (jmp [rip + 0], (dest) )
struct InplaceDetour_Jmp {
	uint16_t jmp { 0x25ff };//2
	uint32_t zero {0};      // 4
	uint64_t target;        //8
};

#pragma pack(pop)

template<typename T>
PLH::insts_t makeInplaceDetour(const uint64_t address, const uint64_t destination){
	PLH::Instruction::Displacement disp { 0 };

	T dt;
	dt.target = destination;

	std::vector<uint8_t> destBytes;
	destBytes.resize(sizeof(T));
	memcpy(destBytes.data(), &dt, sizeof(T));
	return { PLH::Instruction(address, disp, 0, false, false, destBytes, "inplace-detour", "", PLH::Mode::x64) };
}

PLH::insts_t makeInplaceDetour(PLH::x64Detour::detour_scheme_t scheme, const uint64_t address, const uint64_t destination){
	switch(scheme){
		case PLH::x64Detour::detour_scheme_t::INPLACE:
			return makeInplaceDetour<InplaceDetour>(address, destination);
		case PLH::x64Detour::detour_scheme_t::INPLACE_JMP:
			return makeInplaceDetour<InplaceDetour_Jmp>(address, destination);
		default:
			return {};
	}
}

}

uint8_t PLH::x64Detour::getMinPrologueSize() const {
	switch(_detourScheme){
		case PLH::x64Detour::detour_scheme_t::INPLACE: return sizeof(InplaceDetour);
		case PLH::x64Detour::detour_scheme_t::INPLACE_JMP: return sizeof(InplaceDetour_Jmp);
		default:
			return getMinJmpSize();
	}
}


bool PLH::x64Detour::hook() {
	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
	if (insts.empty()) {
		Log::log("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
		return false;
	}

	uint64_t minProlSz = getMinPrologueSize();  // min size of patches that may split instructions

	if (!followJmp(insts, minProlSz)) {
		Log::log("Prologue jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn address to resolved one
	m_fnAddress = insts.front().getAddress();

	// --------------- END RECURSIVE JMP RESOLUTION ---------------------
	Log::log("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

	
	uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	std::optional<PLH::insts_t> prologueOpt;
	insts_t prologue;
	{
		// find the prologue section we will overwrite with jmp + zero or more nops
		prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
		if (!prologueOpt) {
			Log::log("Function too small to hook safely!", ErrorLevel::SEV);
			return false;
		}

		assert(roundProlSz >= minProlSz);
		prologue = *prologueOpt;

		if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
			Log::log("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
			return false;
		}
	}

	m_originalInsts = prologue;
	Log::log("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);
	
	{   // copy all the prologue stuff to trampoline
		insts_t jmpTblOpt;
		if (!makeTrampoline(prologue, jmpTblOpt)) {
			return false;
		}

		Log::log("Trampoline:\n" + instsToStr(m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this)) + "\n", ErrorLevel::INFO);
		if (!jmpTblOpt.empty())
			Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
	}

	*m_userTrampVar = m_trampoline;
	m_hookSize = (uint32_t)roundProlSz;
	m_nopProlOffset = (uint16_t)minProlSz;

	MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	if (_detourScheme == detour_scheme_t::VALLOC2 || (_detourScheme == detour_scheme_t::VALLOC2_FALLBACK_CODE_CAVE && boundedAllocSupported())) {
		// TODO: We wast a whole page, put this in the PageAllocator instead
		uint64_t max = (uint64_t)AlignDownwards(calc_2gb_above(m_fnAddress), 0x10000);
		uint64_t min = (uint64_t)AlignDownwards(calc_2gb_below(m_fnAddress), 0x10000);
		uint64_t region = (uint64_t)m_allocator.allocate(min, max);
		if (!region) {
			Log::log("VirtualAlloc2 failed to find a region near function", ErrorLevel::SEV);
			return false;
		}

		m_valloc2_region = region;

		MemoryProtector holderProt(region, 8, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
		m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, region);
	} else if(_detourScheme == detour_scheme_t::CODE_CAVE || _detourScheme == detour_scheme_t::VALLOC2_FALLBACK_CODE_CAVE){
		// we're really space constrained, try to do some stupid hacks like checking for 0xCC's near us
		auto cave = findNearestCodeCave<8>(m_fnAddress);
		if (!cave) {
			Log::log("No code caves found near function", ErrorLevel::SEV);
			return false;
		}

		MemoryProtector holderProt(*cave, 8, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);
		m_hookInsts = makex64MinimumJump(m_fnAddress, m_fnCallback, *cave);
	} else {
		//inplace scheme. This is more stable than the cave finder since that may potentially find a region of unstable memory. 
		// However, this INPLACE scheme may only be done for functions with a large enough prologue, otherwise this will overwrite adjacent bytes
		m_hookInsts = makeInplaceDetour(_detourScheme, m_fnAddress, m_fnCallback);
		if(m_hookInsts.empty()){
			PLH::Log::log("Unknown inplace detour scheme: " + std::to_string((int)_detourScheme), PLH::ErrorLevel::SEV);
			return false;
		}
	}
	m_disasm.writeEncoding(m_hookInsts, *this);

	// Nop the space between jmp and end of prologue
	assert(m_hookSize >= m_nopProlOffset);
	m_nopSize = (uint16_t)(m_hookSize - m_nopProlOffset);
	writeNop(m_fnAddress + m_nopProlOffset, m_nopSize);

	m_hooked = true;
	return true;
}

bool PLH::x64Detour::unHook()
{
	bool status = PLH::Detour::unHook();
	if (m_valloc2_region) {
		m_allocator.deallocate(*m_valloc2_region);
		m_valloc2_region = {};
	}
	return status;
}


PLH::insts_t PLH::makeJmpX64(uint64_t& jmpEntryAddr, PLH::Instruction &inst, uint64_t &captureAddress, uint8_t jmpEntrySz, uint8_t destHldrSz, uint64_t trampoline, size_t trampolineSz, int64_t delta, const PLH::MemAccessor& ma) {
    using namespace PLH;
    captureAddress -= destHldrSz;
    assert(captureAddress > (uint64_t)trampoline && (captureAddress + destHldrSz) < (trampoline + trampolineSz));

    // move inst to trampoline and point instruction to entry
    auto oldDest = inst.getDestination();
    inst.setAddress(inst.getAddress() + delta);

    bool destHolderOnly = inst.m_isIndirect; //re-use the call instrunction's own displacement storage, no need for extra JMP [xxx]
    inst.setDisplacementByDestination(destHolderOnly ? captureAddress : jmpEntryAddr);

    const auto& result = destHolderOnly ? makex64DestHolder(oldDest, captureAddress) : makex64MinimumJump(jmpEntryAddr, oldDest, captureAddress);

	if(!destHolderOnly) jmpEntryAddr += jmpEntrySz;
	return result;
};

bool PLH::x64Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
	assert(!prologue.empty());
	assert(m_trampoline == NULL);

	const uint64_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);
	const uint8_t destHldrSz = 8;

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works
	
	The relocation could also because of data operations too. But that's specific to the function and can't
	work again on a retry (same function, duh). Return immediately in that case.**/
	uint8_t neededEntryCount = 0;
	PLH::insts_t instsNeedingEntry;
	PLH::insts_t instsNeedingReloc;
	uint8_t retries = 0;

	bool good = false;
	do {
		neededEntryCount = std::max((uint8_t)instsNeedingEntry.size(), (uint8_t)5);
		
		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t)(prolSz + (getMinJmpSize() + destHldrSz) +
			(getMinJmpSize() + destHldrSz)* neededEntryCount +
			7); //extra bytes for dest-holders 8 bytes alignment 

		// allocate new trampoline before deleting old to increase odds of new mem address
		uint64_t tmpTrampoline = (uint64_t)new unsigned char[m_trampolineSz];
		if (m_trampoline != NULL) {
			delete[](unsigned char*)m_trampoline;
		}

		m_trampoline = tmpTrampoline;
		const int64_t delta = m_trampoline - prolStart;

		//buildRelocationList expects empty vectors.
		instsNeedingEntry.clear();
		instsNeedingReloc.clear();
		
		if (!buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc))
			continue;

		good = true;
	} while (retries++ < 5 && !good);

	if (!good) {
		return false;
	}

	const int64_t delta = m_trampoline - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + prolSz;
	const uint64_t jmpHolderCurAddr = (m_trampoline + m_trampolineSz - destHldrSz) & ~0x7; //8 bytes align for performance.
	{
		const auto jmpToProl = makex64MinimumJump(jmpToProlAddr, prologue.front().getAddress() + prolSz, jmpHolderCurAddr);

		Log::log("Jmp To Prol:\n" + instsToStr(jmpToProl) + "\n", ErrorLevel::INFO);
		m_disasm.writeEncoding(jmpToProl, *this);
	}

	// each jmp tbl entries holder is one slot down from the previous (lambda holds state)
	const auto makeJmpFn = std::bind(PLH::makeJmpX64, _1, _2, jmpHolderCurAddr, getMinJmpSize(), destHldrSz, m_trampoline, m_trampolineSz, delta, this->memAccesor());

	const uint64_t jmpTblStart = jmpToProlAddr + getMinJmpSize();
	trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry);

	return true;
}
