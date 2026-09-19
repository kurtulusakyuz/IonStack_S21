/* dev_mfc: enumerate V4L2 nodes from shell. Open each /dev/videoN,
 * VIDIOC_QUERYCAP, print driver/card/caps + open errno. */
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
    int nodes[] = {10, 11, 101, 102, 103, 104, 105};
    alarm(30);
    printf("dev_mfc: V4L2 node probe\n");
    for (unsigned i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        char path[32];
        struct v4l2_capability cap;
        snprintf(path, sizeof(path), "/dev/video%d", nodes[i]);
        errno = 0;
        int fd = open(path, O_RDWR);
        if (fd < 0) {
            printf("%s: open errno=%d\n", path, errno);
            continue;
        }
        memset(&cap, 0, sizeof(cap));
        errno = 0;
        int r = ioctl(fd, VIDIOC_QUERYCAP, &cap);
        printf("%s: querycap ret=%d errno=%d driver=%.15s card=%.31s caps=%x\n",
               path, r, errno, cap.driver, cap.card,
               r == 0 ? cap.device_caps : 0);
        close(fd);
    }
    printf("dev_mfc: done\n");
    return 0;
}
