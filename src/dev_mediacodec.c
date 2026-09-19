/* dev_mediacodec: can shell drive the HW encoder? Create AVC encoder,
 * configure 320x240, start, dequeue one output buffer, stop/release.
 * Prints each step errno. Proves MediaCodec Binder reachability. */
#include <errno.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaFormat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    alarm(60);
    printf("dev_mediacodec: HW encoder reachability probe\n");
    AMediaCodec *c = AMediaCodec_createEncoderByType("video/avc");
    printf("createEncoder: %p errno=%d\n", (void *)c, errno);
    if (!c) {
        printf("dev_mediacodec: NO encoder (route dead)\n");
        return 2;
    }
    AMediaFormat *f = AMediaFormat_new();
    AMediaFormat_setString(f, "mime", "video/avc");
    AMediaFormat_setInt32(f, "width", 320);
    AMediaFormat_setInt32(f, "height", 240);
    AMediaFormat_setInt32(f, "frame-rate", 30);
    AMediaFormat_setInt32(f, "color-format", 21);
    AMediaFormat_setInt32(f, "bitrate", 64000);
    AMediaFormat_setInt32(f, "i-frame-interval", 1);
    media_status_t s = AMediaCodec_configure(c, f, NULL, NULL, 1);
    printf("configure: %d\n", (int)s);
    s = AMediaCodec_start(c);
    printf("start: %d\n", (int)s);
    if (s == 0) {
        AMediaCodecBufferInfo info;
        ssize_t idx = AMediaCodec_dequeueOutputBuffer(c, &info, 500000);
        printf("dequeueOutput: %zd\n", idx);
        if (idx >= 0)
            AMediaCodec_releaseOutputBuffer(c, (size_t)idx, 0);
        AMediaCodec_stop(c);
    }
    AMediaCodec_delete(c);
    AMediaFormat_delete(f);
    printf("dev_mediacodec: ENCODER WORKS from shell\n");
    return 0;
}
