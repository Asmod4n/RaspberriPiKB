#pragma once
#include <pthread.h>
#include <liburing.h>

#include <sys/ioctl.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "gadget-hid.h"

int pikb_initUSB();
int main();
void sendHIDReport();

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)