#pragma once
#include <linux/usb/ch9.h>
#include <stdint.h>
#include <usbg/usbg.h>
#include <usbg/function/hid.h>

//#define KEYBOARD_VID             0x04d9
//#define KEYBOARD_PID             0x0007
//#define KEYBOARD_DEV             "/dev/input/by-id/usb-_Raspberry_Pi_Internal_Keyboard-event-kbd"
#define KEYBOARD_HID_REPORT_SIZE 8

struct hid_buf {
    uint8_t report_id;
    unsigned char data[64];
}  __attribute__ ((aligned (1)));

int pikb_initUSB();
int pikb_cleanupUSB();
