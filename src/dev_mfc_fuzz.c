/* dev_mfc_fuzz v1: MFC encoder error-path hammer (CVE-2026-23789 hunt).
 * Each round: create AVC encoder, configure odd params, start, queue a
 * few garbage input buffers, then an error injection (variant by round):
 * 0=flush-during-encode, 1=stop-during-encode, 2=EOS+flush race,
 * 3=release-while-queued, 4=reconfigure race, 5=garbage crop/scale.
 * argv[1]=rounds (default 60), argv[2]=seed. Watch logcat for MFC oops.
 * Worst case: mediaserver restart or kernel panic (reboot). */
#include <errno.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaFormat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int R;

static int rnd(int n)
{
    R = R * 1103515245 + 12345;
    return (unsigned)(R >> 16) % (unsigned)n;
}

static void one_round(int variant, int iter)
{
    AMediaCodec *c = AMediaCodec_createEncoderByType("video/avc");
    if (!c)
        return;
    AMediaFormat *f = AMediaFormat_new();
    int w = 320, h = 240;
    if (variant == 5) {
        w = 16 + rnd(4000);
        h = 16 + rnd(4000);
    }
    AMediaFormat_setString(f, "mime", "video/avc");
    AMediaFormat_setInt32(f, "width", w);
    AMediaFormat_setInt32(f, "height", h);
    AMediaFormat_setInt32(f, "frame-rate", 30);
    AMediaFormat_setInt32(f, "color-format", 21);
    AMediaFormat_setInt32(f, "bitrate", 64000);
    AMediaFormat_setInt32(f, "i-frame-interval", 1);
    if (AMediaCodec_configure(c, f, NULL, NULL, 1) != 0) {
        AMediaCodec_delete(c);
        AMediaFormat_delete(f);
        return;
    }
    if (AMediaCodec_start(c) != 0) {
        AMediaCodec_delete(c);
        AMediaFormat_delete(f);
        return;
    }
    for (int i = 0; i < 4; i++) {
        ssize_t idx = AMediaCodec_dequeueInputBuffer(c, 20000);
        if (idx < 0)
            break;
        size_t sz = 0;
        uint8_t *b = AMediaCodec_getInputBuffer(c, (size_t)idx, &sz);
        if (b && sz) {
            size_t fill = sz;
            if (variant == 5)
                fill = sz + (size_t)rnd(4096);
            memset(b, 0x41 + (iter & 7), sz);
            uint32_t flags = 0;
            if (variant == 2 && i == 3)
                flags = 4;
            AMediaCodec_queueInputBuffer(c, (size_t)idx, 0, fill, 0,
                                         flags);
        }
        if (variant == 0 && i == 2)
            AMediaCodec_flush(c);
        if (variant == 1 && i == 2) {
            AMediaCodec_stop(c);
            AMediaCodec_start(c);
        }
        if (variant == 4 && i == 2) {
            AMediaFormat_setInt32(f, "width", 640);
            AMediaCodec_configure(c, f, NULL, NULL, 1);
        }
    }
    if (variant == 2)
        AMediaCodec_flush(c);
    AMediaCodec_stop(c);
    AMediaCodec_delete(c);
    AMediaFormat_delete(f);
}

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 60;
    R = argc > 2 ? atoi(argv[2]) : 12345;
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(600);
    printf("dev_mfc_fuzz: %d rounds error-path hammer\n", rounds);
    for (int i = 0; i < rounds; i++) {
        one_round(i % 6, i);
        if ((i + 1) % 10 == 0)
            printf("dev_mfc_fuzz: progress %d/%d\n", i + 1, rounds);
    }
    printf("dev_mfc_fuzz: done, quiet\n");
    return 0;
}
