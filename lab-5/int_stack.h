#ifndef INT_STACK_H
#define INT_STACK_H

#include <linux/ioctl.h>

#define INT_STACK_MAGIC 'i'

#define INT_STACK_SET_SIZE _IOW(INT_STACK_MAGIC, 0, int)

#endif
