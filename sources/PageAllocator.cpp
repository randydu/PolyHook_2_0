#include "polyhook2/PageAllocator.hpp"

// Stolen from ms detours: https://github.com/microsoft/Detours/blob/64ec135a509884aa60ac6c19b59564f1da9cb2fa/src/detours.cpp#L1197
// this controls the size of allocated pages. We re-use pages for multiple trampolines when possible

static PLH::PDETOUR_REGION s_pRegions = NULL;            // List of all regions.
static PLH::PDETOUR_REGION s_pRegion = NULL;             // Default region.

uint64_t PLH::detour_alloc_round_down_to_region(uint64_t pbTry)
{
	// WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
	uint64_t extra = pbTry & (DETOUR_REGION_SIZE - 1);
	if (extra != 0) {
		pbTry -= extra;
	}
	return pbTry;
}

inline uint64_t PLH::detour_alloc_round_up_to_region(uint64_t pbTry)
{
	// WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
	uint64_t extra = pbTry & (DETOUR_REGION_SIZE - 1);
	if (extra != 0) {
		uint64_t adjust = DETOUR_REGION_SIZE - extra;
		pbTry += adjust;
	}
	return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.
inline uint64_t PLH::detour_alloc_region_from_lo(uint64_t pbLo, uint64_t pbHi)
{
	uint64_t pbTry = detour_alloc_round_up_to_region(pbLo);

	for (; pbTry < pbHi;) {
		MEMORY_BASIC_INFORMATION mbi;

		if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
			// Skip region reserved for system DLLs, but preserve address space entropy.
			pbTry += 0x08000000;
			continue;
		}

		ZeroMemory(&mbi, sizeof(mbi));
		if (!VirtualQuery((char*)pbTry, &mbi, sizeof(mbi))) {
			break;
		}

		if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

			uint64_t pv = (uint64_t)VirtualAlloc((char*)pbTry,
				DETOUR_REGION_SIZE,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
			if (pv != NULL) {
				return pv;
			}
			pbTry += DETOUR_REGION_SIZE;
		}
		else {
			pbTry = detour_alloc_round_up_to_region((uint64_t)mbi.BaseAddress + mbi.RegionSize);
		}
	}
	return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.
inline uint64_t PLH::detour_alloc_region_from_hi(uint64_t pbLo, uint64_t pbHi)
{
	uint64_t pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);

	for (; pbTry > pbLo;) {
		MEMORY_BASIC_INFORMATION mbi;

		if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
			// Skip region reserved for system DLLs, but preserve address space entropy.
			pbTry -= 0x08000000;
			continue;
		}

		ZeroMemory(&mbi, sizeof(mbi));
		if (!VirtualQuery((char*)pbTry, &mbi, sizeof(mbi))) {
			break;
		}

		if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

			uint64_t pv = (uint64_t)VirtualAlloc((char*)pbTry,
				DETOUR_REGION_SIZE,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
			if (pv != NULL) {
				return pv;
			}
			pbTry -= DETOUR_REGION_SIZE;
		}
		else {
			pbTry = detour_alloc_round_down_to_region((uint64_t)mbi.AllocationBase
				- DETOUR_REGION_SIZE);
		}
	}
	return NULL;
}

inline uint64_t PLH::detour_alloc_trampoline_allocate_new(uint64_t pbTarget,
	uint64_t pLo,
	uint64_t pHi)
{
	uint64_t pbTry = NULL;

	// NB: We must always also start the search at an offset from pbTarget
	//     in order to maintain ASLR entropy.

	// Try looking 1GB below or lower.
	if (pbTry == NULL && pbTarget > (uint64_t)0x40000000) {
		pbTry = detour_alloc_region_from_hi((uint64_t)pLo, pbTarget - 0x40000000);
	}

	// Try looking 1GB above or higher.
	if (pbTry == NULL && pbTarget < (uint64_t)0xffffffff40000000) {
		pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, (uint64_t)pHi);
	}

	// Try looking 1GB below or higher.
	if (pbTry == NULL && pbTarget > (uint64_t)0x40000000) {
		pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
	}

	// Try looking 1GB above or lower.
	if (pbTry == NULL && pbTarget < (uint64_t)0xffffffff40000000) {
		pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
	}

	// Try anything below.
	if (pbTry == NULL) {
		pbTry = detour_alloc_region_from_hi((uint64_t)pLo, pbTarget);
	}

	// try anything above.
	if (pbTry == NULL) {
		pbTry = detour_alloc_region_from_lo(pbTarget, (uint64_t)pHi);
	}

	return pbTry;
}

uint64_t detour_2gb_below(uint64_t address)
{
	return (address > (uint64_t)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

uint64_t detour_2gb_above(uint64_t address)
{
	return (address < (uint64_t)0xffffffff80000000) ? address + 0x7ff80000 : (uint64_t)0xfffffffffff80000;
}

PLH::DETOUR_TRAMPOLINE* PLH::detour_alloc_trampoline(uint64_t pbTarget, uint64_t min, uint64_t max)
{
	// We have to place trampolines within +/- 2GB of target.
	DETOUR_TRAMPOLINE* pTrampoline = NULL;
	if (min == 0) {
		min = detour_2gb_below(pbTarget);
	}

	if (max == 0) {
		max = detour_2gb_above(pbTarget);
	}

	// Insure that there is a default region.
	if (s_pRegion == NULL && s_pRegions != NULL) {
		s_pRegion = s_pRegions;
	}

	// First check the default region for an valid free block.
	if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
		(uint64_t)s_pRegion->pFree >= min && (uint64_t)s_pRegion->pFree <= max) {

	found_region:
		pTrampoline = (DETOUR_TRAMPOLINE*)s_pRegion->pFree;
		// do a last sanity check on region.
		if ((uint64_t)pTrampoline < min || (uint64_t)pTrampoline > max) {
			return NULL;
		}
		s_pRegion->pFree = (DETOUR_TRAMPOLINE*)pTrampoline->pbRemain;

		memset(pTrampoline, 0xcc, sizeof(*pTrampoline));
		return pTrampoline;
	}

	// Then check the existing regions for a valid free block.
	for (s_pRegion = s_pRegions; s_pRegion != NULL; s_pRegion = s_pRegion->pNext) {
		if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
			(uint64_t)s_pRegion->pFree >= min && (uint64_t)s_pRegion->pFree <= max) {
			goto found_region;
		}
	}

	// We need to allocate a new region.

	// Round pbTarget down to 64KB block.
	pbTarget = pbTarget - (pbTarget & 0xffff);

	uint64_t pbNewlyAllocated =
		detour_alloc_trampoline_allocate_new(pbTarget, min, max);
	if (pbNewlyAllocated != NULL) {
		s_pRegion = (DETOUR_REGION*)pbNewlyAllocated;
		s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
		s_pRegion->pFree = NULL;
		s_pRegion->pNext = s_pRegions;
		s_pRegions = s_pRegion;

		// Put everything but the first trampoline on the free list.
		PBYTE pFree = NULL;
		pTrampoline = ((DETOUR_TRAMPOLINE*)s_pRegion) + 1;
		for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--) {
			pTrampoline[i].pbRemain = (uint64_t)pFree;
			pFree = (PBYTE)&pTrampoline[i];
		}
		s_pRegion->pFree = (DETOUR_TRAMPOLINE*)pFree;
		goto found_region;
	}

	return NULL;
}

void PLH::detour_free_trampoline(DETOUR_TRAMPOLINE* pTrampoline)
{
	PDETOUR_REGION pRegion = (PDETOUR_REGION)
		((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);

	memset(pTrampoline, 0, sizeof(*pTrampoline));
	pTrampoline->pbRemain = (uint64_t)pRegion->pFree;
	pRegion->pFree = pTrampoline;
}

BOOL PLH::detour_is_region_empty(PDETOUR_REGION pRegion)
{
	// Stop if the region isn't a region (this would be bad).
	if (pRegion->dwSignature != DETOUR_REGION_SIGNATURE) {
		return FALSE;
	}

	uint64_t pbRegionBeg = (uint64_t)pRegion;
	uint64_t pbRegionLim = pbRegionBeg + DETOUR_REGION_SIZE;

	// Stop if any of the trampolines aren't free.
	DETOUR_TRAMPOLINE* pTrampoline = ((DETOUR_TRAMPOLINE*)pRegion) + 1;
	for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGION; i++) {
		if (pTrampoline[i].pbRemain != NULL &&
			(pTrampoline[i].pbRemain < pbRegionBeg ||
				pTrampoline[i].pbRemain >= pbRegionLim)) {
			return FALSE;
		}
	}

	// OK, the region is empty.
	return TRUE;
}

void PLH::detour_free_unused_trampoline_regions()
{
	PDETOUR_REGION* ppRegionBase = &s_pRegions;
	PDETOUR_REGION pRegion = s_pRegions;

	while (pRegion != NULL) {
		if (detour_is_region_empty(pRegion)) {
			*ppRegionBase = pRegion->pNext;

			VirtualFree(pRegion, 0, MEM_RELEASE);
			s_pRegion = NULL;
		}
		else {
			ppRegionBase = &pRegion->pNext;
		}
		pRegion = *ppRegionBase;
	}
}


