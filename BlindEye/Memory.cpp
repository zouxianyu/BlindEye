#include "Memory.h"

namespace Memory
{
    void WriteProtectOff()
    {
        auto cr0 = __readcr0();
        cr0 &= 0xfffffffffffeffff;
        __writecr0(cr0);
        _disable();
    }

    void WriteProtectOn()
    {
        auto cr0 = __readcr0();
        cr0 |= 0x10000;
        _enable();
        __writecr0(cr0);
    }
}