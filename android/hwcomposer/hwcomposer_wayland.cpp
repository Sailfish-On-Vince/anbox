/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hardware/hardware.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>

#include <cutils/log.h>
#include <cutils/atomic.h>

#include <time.h>

#include <hardware/hwcomposer.h>

#include <linux/fb.h>

#include <EGL/egl.h>

/*****************************************************************************/

struct hwc_context_t {
    hwc_composer_device_1_t device;
    hwc_procs_t const* procs;

    /* our private state goes below here */
    int fd;
};

static int hwc_device_open(const struct hw_module_t* module, const char* name,
        struct hw_device_t** device);

static struct hw_module_methods_t hwc_module_methods = {
    open: hwc_device_open
};

hwc_module_t HAL_MODULE_INFO_SYM = {
    common: {
        tag: HARDWARE_MODULE_TAG,
        version_major: 1,
        version_minor: 0,
        id: HWC_HARDWARE_MODULE_ID,
        name: "Sample hwcomposer module",
        author: "The Android Open Source Project",
        methods: &hwc_module_methods,
    }
};

/*****************************************************************************/

static void dump_layer(hwc_layer_1_t const* l) {
    ALOGD("\ttype=%d, flags=%08x, handle=%p, tr=%02x, blend=%04x, {%d,%d,%d,%d}, {%d,%d,%d,%d}",
            l->compositionType, l->flags, l->handle, l->transform, l->blending,
            l->sourceCrop.left,
            l->sourceCrop.top,
            l->sourceCrop.right,
            l->sourceCrop.bottom,
            l->displayFrame.left,
            l->displayFrame.top,
            l->displayFrame.right,
            l->displayFrame.bottom);
}

static int hwc_prepare(hwc_composer_device_1_t *dev,
        size_t numDisplays, hwc_display_contents_1_t** displays) {
    if (displays && (displays[0]->flags & HWC_GEOMETRY_CHANGED)) {
        for (size_t i=0 ; i<displays[0]->numHwLayers ; i++) {
            //dump_layer(&displays[0]->hwLayers[i]);
            displays[0]->hwLayers[i].compositionType = HWC_FRAMEBUFFER;
        }
    }
    if (displays[0]->flags & HWC_GEOMETRY_CHANGED) {
        const size_t& num_hw_layers = displays[0]->numHwLayers;
        size_t i = 1;
        bool visible = (num_hw_layers == 1);

        // Iterate backwards and skip the first (end) layer, which is the
        // framebuffer target layer. According to the SurfaceFlinger folks, the
        // actual location of this layer is up to the HWC implementation to
        // decide, but is in the well know last slot of the list. This does not
        // imply that the framebuffer target layer must be topmost.
        for (; i < num_hw_layers; i++) {
          hwc_layer_1_t* layer = &displays[0]->hwLayers[num_hw_layers - 1 - i];

#if 0
          dump_layer(layer);
#endif

          if (layer->flags & HWC_SKIP_LAYER) {
            // All layers below and including this one will be drawn into the
            // framebuffer. Stop marking further layers as HWC_OVERLAY.
            visible = true;
            break;
          }

          switch (layer->compositionType) {
            case HWC_OVERLAY:
            case HWC_FRAMEBUFFER:
              layer->compositionType = HWC_OVERLAY;
              break;
            case HWC_BACKGROUND:
              break;
            default:
              ALOGE("hwcomposor: Invalid compositionType %d",
                      layer->compositionType);
              break;
          }
       }
    }
    return 0;
}

static int hwc_set(hwc_composer_device_1_t *dev,
        size_t numDisplays, hwc_display_contents_1_t** displays)
{
    //for (size_t i=0 ; i<list->numHwLayers ; i++) {
    //    dump_layer(&list->hwLayers[i]);
    //}

    EGLBoolean sucess = eglSwapBuffers((EGLDisplay)displays[0]->dpy,
            (EGLSurface)displays[0]->sur);
    if (!sucess) {
        return HWC_EGL_ERROR;
    }

    return 0;
}

static int hwc_device_close(struct hw_device_t *dev)
{
    struct hwc_context_t* ctx = (struct hwc_context_t*)dev;
    if (ctx) {
        free(ctx);
    }
    return 0;
}

static int hwc_blank(struct hwc_composer_device_1* dev, int dpy, int blank)
{
    ALOGD("blank");
    return 0;
}

static int hwc_query(struct hwc_composer_device_1* dev,
int param, int* value)
{
    ALOGD("query");
    return 0;
}

static void hwc_registerProcs(struct hwc_composer_device_1* dev,
hwc_procs_t const* procs)
{
    ALOGD("%s", __FUNCTION__);

    hwc_context_t* ctx = (hwc_context_t*)(dev);

    ctx->procs = procs;
};

static int hwc_getDisplayConfigs(struct hwc_composer_device_1* dev, int disp,
uint32_t* configs, size_t* numConfigs) {
    ALOGD("%s", __FUNCTION__);

    int ret = 0;

    if(*numConfigs == 1) {
        *configs = 0;
    }

    *numConfigs = 1;

    switch(disp) {
        case HWC_DISPLAY_PRIMARY:
            ret = 0;
            break;
        case HWC_DISPLAY_EXTERNAL:
            ret = -1;
            break;
    };

    return ret;
}

static bool info_initialized = false;
static struct fb_fix_screeninfo finfo;
struct fb_var_screeninfo info;

static int initialize_info(void)
{
    char const * const device_template[] = {
            "/dev/graphics/fb%u",
            "/dev/fb%u",
            0 };

    int fd = -1;
    int i=0;
    char name[64];

    while ((fd==-1) && device_template[i]) {
        snprintf(name, 64, device_template[i], 0);
        fd = open(name, O_RDWR, 0);
        i++;
    }
    if (fd < 0)
        return -errno;

    if (ioctl(fd, FBIOGET_FSCREENINFO, &finfo) == -1)
        return -errno;

    if (ioctl(fd, FBIOGET_VSCREENINFO, &info) == -1)
        return -errno;

    info.reserved[0] = 0;
    info.reserved[1] = 0;
    info.reserved[2] = 0;
    info.xoffset = 0;
    info.yoffset = 0;
    info.activate = FB_ACTIVATE_NOW;

    /*
     * Request NUM_BUFFERS screens (at lest 2 for page flipping)
     */
#if 0
    info.yres_virtual = info.yres * NUM_BUFFERS;
#if USE_PAN_DISPLAY
    if (ioctl(fd, FBIOPAN_DISPLAY, &info) == -1) {
        ALOGW("FBIOPAN_DISPLAY failed, page flipping not supported");
#else
    if (ioctl(fd, FBIOPUT_VSCREENINFO, &info) == -1) {
        ALOGW("FBIOPUT_VSCREENINFO failed, page flipping not supported");
#endif
        info.yres_virtual = info.yres;
    }

    if (info.yres_virtual < info.yres * 2) {
        // we need at least 2 for page-flipping
        info.yres_virtual = info.yres;
        ALOGW("page flipping not supported (yres_virtual=%d, requested=%d)",
                info.yres_virtual, info.yres*2);
    }

    if (ioctl(fd, FBIOGET_VSCREENINFO, &info) == -1)
        return -errno;

    uint64_t  refreshQuotient =
    (
            uint64_t( info.upper_margin + info.lower_margin + info.yres )
            * ( info.left_margin  + info.right_margin + info.xres )
            * info.pixclock
    );

    /* Beware, info.pixclock might be 0 under emulation, so avoid a
     * division-by-0 here (SIGFPE on ARM) */
    int refreshRate = refreshQuotient > 0 ? (int)(1000000000000000LLU / refreshQuotient) : 0;

    if (refreshRate == 0) {
        // bleagh, bad info from the driver
        refreshRate = 60*1000;  // 60 Hz
    }

    if (int(info.width) <= 0 || int(info.height) <= 0) {
        // the driver doesn't return that information
        // default to 160 dpi
        info.width  = ((info.xres * 25.4f)/160.0f + 0.5f);
        info.height = ((info.yres * 25.4f)/160.0f + 0.5f);
    }
#endif
    close(fd);

    return 0;
}

static int hwc_getDisplayAttributes(struct hwc_composer_device_1* dev, int disp,
uint32_t config, const uint32_t* attributes, int32_t* values) {
    ALOGD("%s", __FUNCTION__);

    if(!info_initialized) {
        initialize_info();
        info_initialized = true;
    }

    if (int(info.width) <= 0 || int(info.height) <= 0) {
        // the driver doesn't return that information
        // default to 160 dpi
        info.width  = ((info.xres * 25.4f)/160.0f + 0.5f);
        info.height = ((info.yres * 25.4f)/160.0f + 0.5f);
    }

    float xdpi = ((float)info.xres * 25.4f) / (float)info.width;
    float ydpi = ((float)info.yres * 25.4f) / (float)info.height;

    hwc_context_t* ctx = (hwc_context_t*)(dev);

    static const uint32_t DISPLAY_ATTRIBUTES[] = {
        HWC_DISPLAY_VSYNC_PERIOD,
        HWC_DISPLAY_WIDTH,
        HWC_DISPLAY_HEIGHT,
        HWC_DISPLAY_DPI_X,
        HWC_DISPLAY_DPI_Y,
        HWC_DISPLAY_NO_ATTRIBUTE,
    };

    const int NUM_DISPLAY_ATTRIBUTES = (sizeof(DISPLAY_ATTRIBUTES) /
            sizeof(DISPLAY_ATTRIBUTES)[0]);

    for (size_t i = 0; i < NUM_DISPLAY_ATTRIBUTES - 1; i++) {
        switch (attributes[i]) {
        case HWC_DISPLAY_VSYNC_PERIOD:
            values[i] = 16666666;
            break;
        case HWC_DISPLAY_WIDTH:
            values[i] = info.xres;
            break;
        case HWC_DISPLAY_HEIGHT:
            values[i] = info.yres;
            break;
        case HWC_DISPLAY_DPI_X:
            values[i] = (int32_t) (xdpi * 1000.0);
            break;
        case HWC_DISPLAY_DPI_Y:
            values[i] = (int32_t) (ydpi * 1000.0);
            break;
        default:
            ALOGE("Unknown display attribute %d",
                    attributes[i]);
            return -EINVAL;
        }
    }

    return 0;
}

// TODO: move to ctx?
static int vsync_enabled = false;

static bool created = false;

static uint64_t tm = 0;

static int64_t systemTime()
{
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)(t.tv_sec)*1000000000LL + t.tv_nsec;
}

static void *vsync_loop(void *param) {
    uint64_t cur_timestamp;
    int dpy = HWC_DISPLAY_PRIMARY;
    hwc_context_t * ctx = reinterpret_cast<hwc_context_t *>(param);

    do {
        cur_timestamp = systemTime();

        if (vsync_enabled) {
            ctx->procs->vsync(ctx->procs, dpy, cur_timestamp);
        }

        usleep(16666);
    }
    while (true);

    return NULL;
}

static int hwc_eventControl(struct hwc_composer_device_1* dev, int dpy,
int event, int enable)
{
    pthread_t vsync_thread;

    hwc_context_t* ctx = (hwc_context_t*)(dev);

    if (event == HWC_EVENT_VSYNC) {
        vsync_enabled = enable;

        if (!created) {
            created = true;
            pthread_create(&vsync_thread, NULL, vsync_loop, (void*) ctx);
        }
    }
    return 0;
}

/*****************************************************************************/

static int hwc_device_open(const struct hw_module_t* module, const char* name,
        struct hw_device_t** device)
{
    int status = -EINVAL;
    if (!strcmp(name, HWC_HARDWARE_COMPOSER)) {
        struct hwc_context_t *dev;
        dev = (hwc_context_t*)malloc(sizeof(*dev));

        /* initialize our state here */
        memset(dev, 0, sizeof(*dev));

        dev->fd = -1;

        /* initialize the procs */
        dev->device.common.tag = HARDWARE_DEVICE_TAG;
        dev->device.common.version = HWC_DEVICE_API_VERSION_1_1;
        dev->device.common.module = const_cast<hw_module_t*>(module);
        dev->device.common.close = hwc_device_close;

        dev->device.prepare = hwc_prepare;
        dev->device.set = hwc_set;
        dev->device.blank = hwc_blank;
        dev->device.query = hwc_query;
        dev->device.eventControl = hwc_eventControl;
        dev->device.registerProcs = hwc_registerProcs;
        dev->device.getDisplayConfigs = hwc_getDisplayConfigs;
        dev->device.getDisplayAttributes = hwc_getDisplayAttributes;

        *device = &dev->device.common;
        status = 0;
    }
    return status;
}

