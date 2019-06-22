//
//  Logger.h
//
//  Created by MJ (Ruit) on 1/1/19.
//

#ifndef Logger_h
#define Logger_h

#include <jni.h>
#include <android/log.h>

enum LogType {
    oDEBUG = 3,
    oERROR = 6,
    oINFO  = 4,
    oWARN  = 5
};

#define TAG "KittyMemory"

#define LOGD(...) ((void)__android_log_print(oDEBUG, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(oERROR, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(oINFO,  TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(oWARN,  TAG, __VA_ARGS__))

#endif /* Logger_h */
