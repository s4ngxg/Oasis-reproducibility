#ifndef PARI_COMPAT_H
#define PARI_COMPAT_H

/* CMake defines this only when the linked PARI has removed qfi(). */
#if defined(PARI_NEEDS_QFI_COMPAT)
#define qfi(a, b, c) Qfb0((a), (b), (c))
#endif

#endif
