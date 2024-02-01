// I will not be including any HDCP keys or anything like that in this file or helping anyone break HDCP, you will need to find them yourself
// this is simply a reverse engineering of the HDCP functions in the HV
// and by "reverse-engineering" I mean "copy-paste from Ghidra's decomp" since these functions are all extremely simple, just math operations and bit shifting

// 17559 RETAIL
// Address: 00029648
// ------------------------------------------
// calculates the HDCP Mi (?)
unsigned long long HdcpCalculateMi(unsigned long long r3, unsigned long long r4, unsigned long long r5)
{
    unsigned long long hrmor = 0x0000010000000000ULL;
    return *(unsigned long long *)(0x00016AC0 + hrmor) ^ r3 ^ r4 ^ r5;
}

// 17559 RETAIL
// Address: 00023698
// ------------------------------------------
// calculates the HDCP AKsv signature (transmitter Ksv)
unsigned long long HdcpCalculateAKsvSignature(unsigned long long r3, unsigned long long r4, unsigned long long r5)
{
    return (r3 >> 0x11 & 0x80 | r3 >> 0x19 & 0x7f) +
                   (r3 >> 0x25 & 7 | r3 >> 0x1d & 0xf8) +
                   (r3 >> 0x16 & 3 | r3 >> 0xe & 0xfc) +
                   (r3 >> 0xb & 0x1f | r3 >> 3 & 0xe0) + (r3 >> 7 & 1 | (r3 & 0x7f) << 1) &
               0xff ^
           r4 & 0xff ^ r5 & 0xff ^ 0x3a;
}

// 17559 RETAIL
// Address: 00023718
// ------------------------------------------
// calculates the HDCP BKsv signature (receiver Ksv)
unsigned long long HdcpCalculateBKsvSignature(unsigned long long r3, unsigned long long r4, unsigned long long r5)
{
    return (r3 >> 0x27 & 1 | r3 >> 0x1f & 0xfe) +
                   (r3 >> 0x1b & 0x1f | r3 >> 0x13 & 0xe0) +
                   (r3 >> 10 & 0x3f | r3 >> 2 & 0xc0) +
                   (r3 >> 0x14 & 0xf | r3 >> 0xc & 0xf0) + (r3 & 0xff) &
               0xff ^
           r4 >> 8 & 0xff ^ r5 >> 8 & 0xff ^ 0x72;
}