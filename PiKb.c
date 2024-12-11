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

static void
pikb_trigger_hook()
{
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s %u", HOOK_PATH, grabbed ? 1u : 0u);
    system(buf);
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
        ioctl(uinput_keyboard_fd, EVIOCGRAB, EVIOC_UNGRAB);
        struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
        sqe->user_data = UNGRAB;
        sqe->flags = IOSQE_IO_LINK;
        io_uring_prep_close(sqe, uinput_keyboard_fd);
    }

    //pikb_trigger_hook();
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
    if (likely(uinput_keyboard_fd > -1)) {
        ioctl(uinput_keyboard_fd, EVIOCGRAB, EVIOC_UNGRAB);
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            goto cantclean;
        }
        sqe->user_data = UNGRAB;
        io_uring_prep_close(sqe, uinput_keyboard_fd);
        wait_nr++;
    }

    if (likely(hid_output > -1)) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            goto cantclean;
        }
        sqe->user_data = EMPTY_HID_REPORT;
        sqe->flags = IOSQE_IO_LINK;
        io_uring_prep_write_fixed(sqe, hid_output, keyboard_buf[1], KEYBOARD_HID_REPORT_SIZE + 1, 0, 1);
        wait_nr++;
        sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            goto cantclean;
        }
        sqe->user_data = CLOSE_HID;
        io_uring_prep_close(sqe, hid_output);
        wait_nr++;
    }
    pikb_cleanupUSB();
    struct io_uring_cqe *cqe = NULL;
    ret = io_uring_submit_and_wait_timeout(&ring, &cqe, wait_nr, NULL, NULL);
    wait_nr = 0;
    if (ret > 0) {
        unsigned int nr = 0;
        unsigned head;

        io_uring_for_each_cqe(&ring, head, cqe) {
            nr++;
        }
        io_uring_cq_advance(&ring, nr);
    }

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
modprobe_libcomposite()
{
    pid_t pid;

    pid = fork();

    if (pid < 0) return;
    if (pid == 0) {
        char* const argv[] = {"modprobe", "libcomposite", NULL};
        execv("/usr/sbin/modprobe", argv);
        exit(0);
    }
    waitpid(pid, NULL, 0);
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
        pikb_fatal_error("cannot setup io_uring");
    }

    keyboard_buf = (struct hid_buf **) calloc(2, sizeof(struct hid_buf));
    if (unlikely(!keyboard_buf)) {
        pikb_fatal_error("buffer allocation failed");
    }
    struct iovec iovecs[2];
    iovecs[0].iov_base = keyboard_buf[0];
    iovecs[0].iov_len = sizeof(struct hid_buf);
    iovecs[1].iov_base = keyboard_buf[1];
    iovecs[1].iov_len = sizeof(struct hid_buf);
    ret = io_uring_register_buffers(&ring, iovecs, 2);
    if (unlikely(ret != 0)) {
        errno = -ret;
        pikb_fatal_error("cannot register buffer with io_uring");
    }

    keyboard_buf[0]->report_id = 1;
    keyboard_buf[1]->report_id = 1;
}

static int
pikb_find_hidraw_device(char *device_type, int16_t vid, int16_t pid)
{
    int fd;
    struct hidraw_devinfo hidinfo = {0};
    char path[20];

    for (int x = 0; x < 16; x++) {
        sprintf(path, "/dev/hidraw%d", x);

        if ((fd = open(path, O_RDWR | O_NONBLOCK | O_DIRECT)) == -1) {
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

   pikb_fatal_error("Failed to open keyboard device");
}

static void
pikb_setup()
{
    modprobe_libcomposite();
    setup_io_uring();

    keyboard_fd = pikb_find_hidraw_device("keyboard", KEYBOARD_VID, KEYBOARD_PID);

    ret = pikb_initUSB();
    if (unlikely(ret != USBG_SUCCESS && ret != USBG_ERROR_EXIST)) {
        pikb_fatal_error("cannot setup USB");
    }

    do {
        hid_output = open("/dev/hidg0", O_WRONLY | O_NONBLOCK | O_SYNC | O_DIRECT);
    } while (hid_output == -1 && errno == EINTR);

    if (hid_output == -1) {
        pikb_fatal_error("cannot open USB Device");
    }
}


int main()
{
#ifdef DEBUG
    printf("Running...\n");
#endif
    pikb_setup();
    struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
    sqe->user_data = READ_KEY;
    io_uring_prep_read_fixed(sqe, keyboard_fd, keyboard_buf[0]->data, KEYBOARD_HID_REPORT_SIZE, 0, 0);
    struct io_uring_cqe *cqe = NULL;
    ret = io_uring_submit_and_wait_timeout(&ring, &cqe, wait_nr, NULL, NULL);
    wait_nr = 0;

    while (ret > 0) {
        unsigned int i = 0;
        unsigned head;

        io_uring_for_each_cqe(&ring, head, cqe) {
            if (unlikely(cqe->res < 0)) {
                goto cleanup;
            }
            switch (cqe->user_data) {
                case GRAB: {
                    grabbed = true;
                    uinput_keyboard_fd = cqe->res;
                    ioctl(uinput_keyboard_fd, EVIOCGRAB, EVIOC_GRAB);
                } break;
                case UNGRAB: {
                    grabbed = false;
                    uinput_keyboard_fd = -1;
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
                    }

                    struct io_uring_sqe *sqe = pikb_io_uring_get_sqe();
                    sqe->user_data = READ_KEY;
                    io_uring_prep_read_fixed(sqe, keyboard_fd, keyboard_buf[0]->data, KEYBOARD_HID_REPORT_SIZE, 0, 0);
                } break;
                case WRITE_KEY: {

                } break;
                case EMPTY_HID_REPORT: {

                } break;
            }

            i++;
        }
        io_uring_cq_advance(&ring, i);

        ret = io_uring_submit_and_wait_timeout(&ring, &cqe, wait_nr, NULL, NULL);
        wait_nr = 0;
    }

cleanup:
    pikb_cleanup();

    return EXIT_SUCCESS;
}
