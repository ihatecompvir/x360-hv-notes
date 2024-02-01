// 17559 RETAIL
// Address: 00003280
// ------------------------------------------
// relocates a physical cacheline to encrypted, with a random encryption key
// used for allocating encrypted memory
void HvpRelocatePhysicalToEncrypted(unsigned long long physAddress, unsigned long long size)
{
    // ensure address and size are aligned to cache lines (0x80 bytes)
    // run a sanity check on size to ensure it isn't 0
    // ensure the upper-32 bits of the address are 0x800003 (indicating that the MMU should not apply the HRMOR and that it is an encrypted address)
    if (((physAddress & 0x7F) == 0) && ((size & 0xFFFFFFFF) != 0) && ((size & 0x7F) == 0))
    {
        // ensure the address is not in hypervisor space (0x0<-->0x40000) and that it is not beyond the end of physical memory
        // ensure that the size is not large enough to exceed physical memory
        if (((physAddress - 0x40000 & 0xFFFFFFFF) < 0x1FFC0000) && ((size & 0xFFFFFFFF) <= (0x20000000 - physAddress & 0xFFFFFFFF)))
        {
            // generate the random encryption key
            unsigned char *key;
            XeCryptRandom(&key, 8);

            // build the final encrypted address
            unsigned long long encryptedAddress = key & 0xFFC0000000 | physAddress & 0x3FFFFF80 | 0x8000030000000000;

            // relocate the cache lines from decrypted memory to encrypted memory
            HvpRelocateCacheLines(physAddress & 0xFFFFFFFF | 0x8000000000000000, encryptedAddress, (size << 0x20) >> 0x27);
        }
        _v_MACHINE_CHECK();
    }
    _v_MACHINE_CHECK();
}

// 17559 RETAIL
// Address: 00003358
// ------------------------------------------
// relocates an encrypted cacheline to physical (decrypted)
void HvpRelocateEncryptedToPhysical(unsigned long long encryptedAddress, unsigned long long size)
{
    // ensure address and size are aligned to cache lines (0x80 bytes)
    // run a sanity check on size to ensure it isn't 0
    // ensure the upper-32 bits of the address are 0x800003 (indicating that the MMU should not apply the HRMOR and that it is an encrypted address)
    if (((encryptedAddress & 0x7F) == 0) && ((size & 0xFFFFFFFF) != 0) && ((size & 0x7F) == 0) && ((encryptedAddress >> 0x28) == 0x800003))
    {
        unsigned long long physAddress = encryptedAddress & 0x3FFFFFFF;

        // ensure the address is not in hypervisor space (0x0<-->0x40000) and that it is not beyond the end of physical memory
        // ensure that the size is not large enough to exceed physical memory
        if (((encryptedAddress - 0x40000 & 0xFFFFFFFF) < 0x1FFC0000) && ((size & 0xFFFFFFFF) <= (0x20000000 - encryptedAddress & 0xFFFFFFFF)))
        {
            // relocate the cache lines from encrypted memory to decrypted memory
            HvpRelocateCacheLines(encryptedAddress, physAddress | 0x8000000000000000, (size << 0x20) >> 0x27);
            return;
        }
        _v_MACHINE_CHECK();
    }
    _v_MACHINE_CHECK();
}