#ifndef __KSU_TOOLKIT_H
#define __KSU_TOOLKIT_H

#include <linux/types.h>

void ksu_toolkit_init(void);
void ksu_toolkit_exit(void);
u32 ksu_toolkit_version_override(void);
u32 ksu_toolkit_flags_override(void);

#endif
