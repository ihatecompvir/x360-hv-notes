// 17559 RETAIL
// Address: 000005c0
// ------------------------------------------
// gets the address to something related to page table entries?
unsigned long long GetPTEAddress2()
{
	return 0x6a01f6c000;
}

// 17559 RETAIL
// Address: 0000057c
// ------------------------------------------
// gets the address to a page table entry for the given base address
// should always return a range of 0x6801f50000 through 0x6801f53ffc
unsigned long long GetPageTableEntryAddress(unsigned int base_address)
{
	// check that the supplied base address is valid (aka within the base address range of 0x80000000<-->0x90000000)
	// if not return null
	if((1 < (base_address >> 0x1c) - 8)
	{
		return 0;
	}
	
	return (base_address >> 0xe & 0x7ffc) | 0x6801f50000;
}

// 17559 RETAIL
// Address: 00029eb0
// ------------------------------------------
// disables, but does not delete, all the page table entries for a given base address
bool HvxUnmapImagePages(unsigned int base_address)
{
	unsigned long long hrmor = 0x0000010000000000ULL; // hashed + encrypted memory
	HvpAcquireSpinLock(hrmor + 0x16920);

	// make sure base address is aligned
	if (base_address & 0xFFFF)
		== 0
		{
			// base address 0x80000000 is always mapped to start of HV space (0x0 physical), so check we aren't trying to unmap that
			if (base_address & 0xFFFFFFFF) != 0x80000000)
				{
					unsigned long long pageTableEntry = GetPageTableEntryAddress(base_address);

					// make sure the PTE exists
					if (pageTableEntry != NULL)
					{
						// make sure the PTE is actually mapped
						if ((*pageTableEntry & 0x10) != 0)
						{
							// loop through every page table entry for the given base address
							while ((*pageTableEntry >> 5 & 1) == 0)
							{
								*pageTableEntry = *pageTableEntry & 0xFFFFFFF0 | 7; // disable the PTE, but do not delete it
								pageTableEntry = pageTableEntry + 4;				// go to next PTE
							}
							return TRUE;
						}
					}
				}
		}
	HvpReleaseSpinLock(hrmor + 0x16920);

	return FALSE;
}

// 17559 RETAIL
// Address: 0002ae18
// ------------------------------------------
// unmaps all the page table entries for a given range
bool HvxUnmapImageRange(unsigned int base_address_start, unsigned int base_address_end)
{
	unsigned long long hrmor = 0x0000010000000000ULL;
	HvpAcquireSpinLock(hrmor + 0x16920);

	unsigned long long pteAddress = GetPTEAddress2();

	HvpSetRMCI(0);

	// ensure the addresses are actually the addresses of a page table entry
	if (((base_address_start & 0xFFFF) == 0) && ((base_address_end) & 0xFFFF) == 0)
	{
		// make sure the end of the range is not before the start
		if (base_address_start < base_address_end)
		{
			if (((base_address_end - 1 ^ base_address_start) & 0xF0000000) == 0)
			{
				unsigned int startPageTableEntry = GetPageTableEntryAddress(base_address_start);

				// ensure the PTE actually exists
				if (startPageTableEntry != NULL)
				{
					if((*(unsigned long long*)startPageTableEntry == 0 || ((*(unsigned long long*)startPageTableEntry & 0x10) != 0))
					{
						unsigned int endPageTableEntry = GetPageTableEntryAddress(base_address_end - 0x10000);

						// ensure the PTE actually exists
						if (endPageTableEntry != NULL)
						{
							if((*(unsigned long long*)endPageTableEntry == 0 || ((*(unsigned long long*)endPageTableEntry & 0x20) != 0))
							{
								while (startPageTableEntry <= endPageTableEntry)
								{
									// if the memory page is encrypted
									if ((*(unsigned long long *)startPageTableEntry & 0xC0000000) != 0)
									{
										HvpInvalidateCacheLines((*(unsigned long long *)startPageTableEntry & 0xFFFFFFC0) << 10, 0x10000);
									}

									if ((*(unsigned long long *)startPageTableEntry & 0xFFFC0) != 0)
									{
										unsigned short uVar1 = *(unsigned long long *)startPageTableEntry >> 5 & 0x7ffe;
										*(unsigned short *)(uVar1 + pteAddress) = *(ushort *)(uVar1 + pteAddress) & 0xf7ff;
									}

									*(unsigned long long *)startPageTableEntry = 0;
									startPageTableEntry = startPageTableEntry + 1;
								}
							}
						}
					}
				}
			}
		}
	}

	HvpSetRMCI(1);
	HvpReleaseSpinLock(hrmor + 0x16920);
	return FALSE;
}
