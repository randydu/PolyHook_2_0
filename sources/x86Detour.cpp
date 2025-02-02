//
// Created by steve on 7/5/17.
//
#include "polyhook2/Detour/x86Detour.hpp"

PLH::x86Detour::x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis) {

}

PLH::x86Detour::x86Detour(const char* fnAddress, const char* fnCallback, uint64_t* userTrampVar, PLH::ADisassembler& dis) : PLH::Detour(fnAddress, fnCallback, userTrampVar, dis) {

}

PLH::Mode PLH::x86Detour::getArchType() const {
	return PLH::Mode::x86;
}

uint8_t PLH::x86Detour::getJmpSize() const {
	return 5;
}

bool PLH::x86Detour::hook() {
	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
	if (insts.size() <= 0) {
		Log::log("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
		return false;
	}

	uint64_t minProlSz = getJmpSize(); // min size of patches that may split instructions

	if (!followJmp(insts, minProlSz)) {
		Log::log("Prologue jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn address to resolved one
	m_fnAddress = insts.front().getAddress();

	// --------------- END RECURSIVE JMP RESOLUTION ---------------------

	Log::log("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

	uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	insts_t prologue;
	{
		// find the prologue section we will overwrite with jmp + zero or more nops
		auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
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
		if (!makeTrampoline(prologue, jmpTblOpt))
			return false;

		Log::log("Trampoline:\n" + instsToStr(m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this)) + "\n", ErrorLevel::INFO);
		if (!jmpTblOpt.empty())
			Log::log("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n", ErrorLevel::INFO);
	}

	*m_userTrampVar = m_trampoline;
	m_hookSize = (uint32_t)roundProlSz;
	m_nopProlOffset = (uint16_t)minProlSz;

	MemoryProtector prot(m_fnAddress, m_hookSize, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this);
	m_hookInsts = makex86Jmp(m_fnAddress, m_fnCallback);
	m_disasm.writeEncoding(m_hookInsts, *this);

	// Nop the space between jmp and end of prologue
	assert(m_hookSize >= m_nopProlOffset);
	m_nopSize = (uint16_t)(m_hookSize - m_nopProlOffset);
	writeNop(m_fnAddress + m_nopProlOffset, m_nopSize);

	m_hooked = true;
	return true;
}

bool PLH::x86Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
	assert(!prologue.empty());
	const uint64_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);

	/** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	address will change each attempt, which changes delta, which changes the number of needed entries. So
	we just try until we hit that lucky number that works.
	
	The relocation could also because of data operations too. But that's specific to the function and can't
	work again on a retry (same function, duh). Return immediately in that case.
	**/
	uint8_t neededEntryCount = 5;
	PLH::insts_t instsNeedingEntry;
	PLH::insts_t instsNeedingReloc;

	const auto jmpSz = getJmpSize();

	uint8_t retries = 0;
	do {
		if (retries++ > 4) {
			Log::log("Failed to calculate trampoline information", ErrorLevel::SEV);
			return false;
		}

		if (m_trampoline != NULL) {
			delete[](unsigned char*)m_trampoline;
			neededEntryCount = (uint8_t)instsNeedingEntry.size();
		}

		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t)(prolSz + jmpSz + jmpSz * neededEntryCount);
		m_trampoline = (uint64_t) new unsigned char[m_trampolineSz];

		const int64_t delta = m_trampoline - prolStart;

		if (!buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc))
			return false;
	} while (instsNeedingEntry.size() > neededEntryCount);

	const int64_t delta = m_trampoline - prolStart;
	MemoryProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uint64_t jmpToProlAddr = m_trampoline + prolSz;
	{
		const auto jmpToProl = makex86Jmp(jmpToProlAddr, prologue.front().getAddress() + prolSz);
		m_disasm.writeEncoding(jmpToProl, *this);
	}

	const auto makeJmpFn = [=](uint64_t& a, PLH::Instruction& inst) {
		// move inst to trampoline and point instruction to entry
		auto oldDest = inst.getDestination();
		inst.setAddress(inst.getAddress() + delta);
		inst.setDisplacementByDestination(a);

		const auto& result = makex86Jmp(a, oldDest);
		a += jmpSz;
		return result;
	};

	const uint64_t jmpTblStart = jmpToProlAddr + jmpSz;
	trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry);
	return true;
}