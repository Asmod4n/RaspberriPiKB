#include "PiKb.h"

enum running_op {
    GRAB,
    UNGRAB,
    READ_KEY,
    WRITE_KEY,
    EMPTY_HID_REPORT,
    CLOSE_HID
};

#ifndef HOOK_PATH
#define HOOK_PATH "~/hook.sh"
#endif

#define EVIOC_GRAB 1
#define EVIOC_UNGRAB 0

static int hid_output = -1;
static volatile bool grabbed = false;

static int ret = -1;
static int keyboard_fd = -1;
static int uinput_keyboard_fd = -1;
static struct hid_buf **keyboard_buf = NULL;

static struct io_uring ring = {0};

static unsigned int wait_nr = 0;
static int efd = -1;
static pthread_t thread = 0;

_Noreturn static void pikb_fatal_error(const char *message);

static struct io_uring_sqe *
pikb_io_uring_get_sqe()
{
  struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  if (unlikely(!sqe)) {
    pikb_fatal_error("SQ ring is currently full and entries must be submitted for processing before new ones can get allocated");
  }
  wait_nr++;
  return sqe;
}

static struct io_uring_cqe *
pikb_io_uring_submit_and_wait_timeout()
{
    struct io_uring_cqe *cqe = NULL;
    ret = io_uring_submit_and_wait_timeout(&ring, &cqe, wait_nr, NULL, NULL);
    return cqe;
}

static void
pikb_trigger_hook()
{
    eventfd_write(efd, 1);
}

#ifdef DEBUG
static void
printhex(unsigned char *buf, size_t len)
{
    for(int x = 0; x < len; x++)
    {
        printf("%x ", buf[x]);
    }
    printf("\n");
}
#endif

static void
pikb_grab_keyboard()
{
#ifdef DEBUG
    puts("Grabbing: keyboard");
#endif
    if (likely(keyboard_fd > -1)) {
        struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
        sqe->user_data = GRAB;
        sqe->flags = IOSQE_IO_LINK;
        io_uring_prep_open(sqe, KEYBOARD_DEV, O_RDONLY | O_NONBLOCK | O_DIRECT, 0);
    }
}

static void
pikb_ungrab_keyboard()
{
#ifdef DEBUG
    puts("Releasing Keyboard");
#endif
    if (likely(uinput_keyboard_fd > -1)) {
        ret = ioctl(uinput_keyboard_fd, EVIOCGRAB, EVIOC_UNGRAB);
        if (unlikely(ret == -1)) {
            pikb_fatal_error("can't ungrab keyboard");
        }
        struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
        sqe->user_data = UNGRAB;
        sqe->flags = IOSQE_IO_LINK;
        io_uring_prep_close(sqe, uinput_keyboard_fd);
    }
}

static void
pikb_send_empty_hid_reports_keyboard()
{
    if (likely(hid_output > -1)) {
        struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
        sqe->user_data = EMPTY_HID_REPORT;
        sqe->flags = IOSQE_IO_LINK;
        io_uring_prep_write_fixed(sqe, hid_output, keyboard_buf[1], KEYBOARD_HID_REPORT_SIZE + 1, 0, 1);
    }
}

static void
pikb_cleanup()
{
#ifdef DEBUG
    puts("cleanup");
#endif
    if (uinput_keyboard_fd > -1) {
        ioctl(uinput_keyboard_fd, EVIOCGRAB, EVIOC_UNGRAB);
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (unlikely(!sqe)) {
            goto cantclean;
        }
        sqe->user_data = UNGRAB;
        io_uring_prep_close(sqe, uinput_keyboard_fd);
        wait_nr++;
    }

    if (hid_output > -1) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (unlikely(!sqe)) {
            goto cantclean;
        }
        sqe->user_data = EMPTY_HID_REPORT;
        sqe->flags = IOSQE_IO_LINK;
        io_uring_prep_write_fixed(sqe, hid_output, keyboard_buf[1], KEYBOARD_HID_REPORT_SIZE + 1, 0, 1);
        wait_nr++;
        sqe = io_uring_get_sqe(&ring);
        if (unlikely(!sqe)) {
            goto cantclean;
        }
        sqe->user_data = CLOSE_HID;
        io_uring_prep_close(sqe, hid_output);
        wait_nr++;
    }

    struct io_uring_cqe *cqe = NULL;
    struct __kernel_timespec ts = {
        .tv_sec = 1
    };
    ret = io_uring_submit_and_wait_timeout(&ring, &cqe, wait_nr, &ts, NULL);
    if (unlikely(ret < 0)) {
        goto cantclean;
    }
    unsigned int nr = 0;
    unsigned head;
    io_uring_for_each_cqe(&ring, head, cqe) {
        nr++;
        wait_nr--;
    }
    io_uring_cq_advance(&ring, nr);

    grabbed = false;
    eventfd_write(efd, 0);
    close(efd);
    pthread_join(thread, NULL);

    pikb_cleanupUSB();
    free(keyboard_buf);
    io_uring_queue_exit(&ring);
    return;

cantclean:
    err(EXIT_FAILURE, "can't clean up, you have to reboot your system.");
}

_Noreturn static void
pikb_fatal_error(const char *message)
{
    pikb_cleanup();
    err(EXIT_FAILURE, "%s", message);
}

static void
setup_io_uring()
{
    struct io_uring_params params = {
        .flags = IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_COOP_TASKRUN|IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_SQPOLL,
        .sq_thread_idle = 500
    };

    ret = io_uring_queue_init_params(128, &ring, &params);
    if (unlikely(ret != 0)) {
        errno = -ret;
        pikb_fatal_error("can't setup io_uring");
    }

    keyboard_buf = (struct hid_buf **) calloc(2, sizeof(struct hid_buf));
    if (unlikely(!keyboard_buf)) {
        pikb_fatal_error("can't allocate keyboard buffer");
    }
    struct iovec iovecs[2];
    iovecs[0].iov_base = keyboard_buf[0];
    iovecs[0].iov_len = sizeof(struct hid_buf);
    iovecs[1].iov_base = keyboard_buf[1];
    iovecs[1].iov_len = sizeof(struct hid_buf);
    ret = io_uring_register_buffers(&ring, iovecs, 2);
    if (unlikely(ret != 0)) {
        errno = -ret;
        pikb_fatal_error("can't register keyboard buffer with io_uring");
    }

    keyboard_buf[0]->report_id = 1;
    keyboard_buf[1]->report_id = 1;
}

static int
pikb_find_hidraw_device(char *device_type, int16_t vid, int16_t pid)
{
    int fd;
    struct hidraw_devinfo hidinfo = {0};
    char path[14];

    for (unsigned char x = 0; x < 16; x++) {
        sprintf(path, "/dev/hidraw%hhu", x);

        if ((fd = open(path, O_RDONLY | O_NONBLOCK | O_DIRECT)) == -1) {
            continue;
        }

        (void) ioctl(fd, HIDIOCGRAWINFO, &hidinfo);

        if (hidinfo.vendor == vid && hidinfo.product == pid) {
#ifdef DEBUG
            printf("Found %s at: %s\n", device_type, path);
#endif
            return fd;
        }

        close(fd);
    }

   pikb_fatal_error("can't open keyboard device");
}

static void*
hook_thread(void* arg)
{
    eventfd_t value;
    do {
        value = 0;
        eventfd_read(efd, &value);

        char command[PATH_MAX + 3];
        snprintf(command, sizeof(command), "%s %d", HOOK_PATH, grabbed);
        system(command);
    } while (likely(value == 1));

    return NULL;
}


static void
pikb_setup()
{
    system("/usr/sbin/modprobe libcomposite");

    efd = eventfd(0, 0);
    if (unlikely(efd == -1)) {
        pikb_fatal_error("can't create eventfd");
    }

    if (unlikely(pthread_create(&thread, NULL, hook_thread, NULL) != 0)) {
        pikb_fatal_error("can't create thread");
    }

    keyboard_fd = pikb_find_hidraw_device("keyboard", KEYBOARD_VID, KEYBOARD_PID);

    ret = pikb_initUSB();
    if (unlikely(ret != USBG_SUCCESS && ret != USBG_ERROR_EXIST)) {
        pikb_fatal_error("can't setup USB");
    }

    do {
        hid_output = open("/dev/hidg0", O_WRONLY | O_NONBLOCK | O_SYNC | O_DIRECT);
    } while (hid_output == -1 && errno == EINTR);

    if (unlikely(hid_output == -1)) {
        pikb_fatal_error("can't open USB Device");
    }

    setup_io_uring();
}

int main()
{
#ifdef DEBUG
    puts("Running...");
#endif
    pikb_setup();
    struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
    sqe->user_data = READ_KEY;
    io_uring_prep_read_fixed(sqe, keyboard_fd, keyboard_buf[0]->data, KEYBOARD_HID_REPORT_SIZE, 0, 0);
    struct io_uring_cqe *cqe = pikb_io_uring_submit_and_wait_timeout();

    while (ret > 0) {
        unsigned int nr = 0;
        unsigned head;

        io_uring_for_each_cqe(&ring, head, cqe) {
            wait_nr--;
            if (unlikely(cqe->res < 0)) {
                goto cleanup;
            }
            switch (cqe->user_data) {
                case GRAB: {
                    uinput_keyboard_fd = cqe->res;
                    ret = ioctl(uinput_keyboard_fd, EVIOCGRAB, EVIOC_GRAB);
                    if (unlikely(ret == -1)) {
                        pikb_fatal_error("can't grab keyboard");
                    }
                    grabbed = true;
                    pikb_trigger_hook();
                } break;
                case UNGRAB: {
                    uinput_keyboard_fd = -1;
                    grabbed = false;
                    pikb_trigger_hook();
                } break;
                case READ_KEY: {
                    if (likely(cqe->res == KEYBOARD_HID_REPORT_SIZE)) {
#ifdef DEBUG
                        printf("K:");
                        printhex(keyboard_buf[0]->data, KEYBOARD_HID_REPORT_SIZE);
#endif
                        if (grabbed) {
                            struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
                            sqe->user_data = WRITE_KEY;
                            sqe->flags = IOSQE_IO_LINK;
                            io_uring_prep_write_fixed(sqe, hid_output, keyboard_buf[0], KEYBOARD_HID_REPORT_SIZE + 1, 0, 0);
                        }

                        // Trap Ctrl + Raspberry and toggle capture on/off
                        if (keyboard_buf[0]->data[0] == 0x09) {
                            if (grabbed) {
                                pikb_ungrab_keyboard();
                                pikb_send_empty_hid_reports_keyboard();
                            } else {
                                pikb_grab_keyboard();
                            }
                        }
                        // Trap Ctrl + Shift + Raspberry and exit
                        if (keyboard_buf[0]->data[0] == 0x0b) {
                            goto cleanup;
                        }
                    } else {
                        pikb_fatal_error("can't read correct size from keyboard");
                    }

                    struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
                    sqe->user_data = READ_KEY;
                    io_uring_prep_read_fixed(sqe, keyboard_fd, keyboard_buf[0]->data, KEYBOARD_HID_REPORT_SIZE, 0, 0);
                } break;
                case WRITE_KEY:
                case EMPTY_HID_REPORT: {
                    assert(cqe->res == KEYBOARD_HID_REPORT_SIZE + 1);
                } break;
            }

            nr++;
        }
        io_uring_cq_advance(&ring, nr);

        cqe = pikb_io_uring_submit_and_wait_timeout();
    }

cleanup:
    pikb_cleanup();

    return EXIT_SUCCESS;
}
