#ifndef POLYHOOK_2_PAGEALLOCATOR_HPP
#define POLYHOOK_2_PAGEALLOCATOR_HPP

#include <stdint.h>
#include <cassert>
#include <algorithm>
#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

namespace PLH {
	// Stolen from ms detours: https://github.com/microsoft/Detours/blob/64ec135a509884aa60ac6c19b59564f1da9cb2fa/src/detours.cpp#L1197
	// this controls the size of allocated pages. We re-use pages for multiple trampolines when possible
	const uint64_t DETOUR_REGION_SIZE = 0x10000;
	const uint64_t DETOUR_TRAMPOLINE_DATA_SIZE = 0xF8;
	struct DETOUR_TRAMPOLINE
	{
		uint64_t pbRemain;  // [free list]
		char data[DETOUR_TRAMPOLINE_DATA_SIZE]; // data
	};

	const uint64_t DETOUR_TRAMPOLINE_SIZE = sizeof(DETOUR_TRAMPOLINE);

	struct DETOUR_REGION
	{
		ULONG dwSignature;
		DETOUR_REGION* pNext;  // Next region in list of regions.
		DETOUR_TRAMPOLINE* pFree;  // List of free trampolines in this region.
	};

	typedef DETOUR_REGION* PDETOUR_REGION;
	const ULONG DETOUR_TRAMPOLINES_PER_REGION = (DETOUR_REGION_SIZE
		/ DETOUR_TRAMPOLINE_SIZE) - 1;

	const ULONG DETOUR_REGION_SIGNATURE = 'Ylop';

	// Region reserved for system DLLs, which cannot be used for trampolines.
	static uint64_t    s_pSystemRegionLowerBound = 0x70000000;
	static uint64_t    s_pSystemRegionUpperBound = 0x80000000;

	uint64_t detour_alloc_round_down_to_region(uint64_t pbTry);

	uint64_t detour_alloc_round_up_to_region(uint64_t pbTry);

	// Starting at pbLo, try to allocate a memory region, continue until pbHi.
	uint64_t detour_alloc_region_from_lo(uint64_t pbLo, uint64_t pbHi);

	// Starting at pbHi, try to allocate a memory region, continue until pbLo.
	uint64_t detour_alloc_region_from_hi(uint64_t pbLo, uint64_t pbHi);

	uint64_t detour_alloc_trampoline_allocate_new(uint64_t pbTarget, uint64_t pLo, uint64_t pHi);

	DETOUR_TRAMPOLINE* detour_alloc_trampoline(uint64_t pbTarget, uint64_t min = 0, uint64_t max = 0);

	void detour_free_trampoline(DETOUR_TRAMPOLINE* pTrampoline);

	BOOL detour_is_region_empty(PDETOUR_REGION pRegion);

	void detour_free_unused_trampoline_regions();
}
#endif
