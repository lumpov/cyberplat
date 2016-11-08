#ifndef __JIPRIVPG_H
#define __JIPRIVPG_H


#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

namespace keys
{
    enum { max_keys_num=64 };
}

namespace thread_safe
{
#ifdef _WIN32
    typedef CRITICAL_SECTION jni_mutex_t;
#else
    typedef pthread_mutex_t jni_mutex_t;
#endif /* _WIN32 */

    extern jni_mutex_t jni_mutex;

#ifdef _WIN32
    inline void init(void) {InitializeCriticalSection(&jni_mutex);}
    inline void done(void) {DeleteCriticalSection(&jni_mutex);}
    inline void enter(void){EnterCriticalSection(&jni_mutex);}
    inline void leave(void){LeaveCriticalSection(&jni_mutex);}
#else
    inline void init(void) {pthread_mutex_init(&jni_mutex,0);}
    inline void done(void) {pthread_mutex_destroy(&jni_mutex);}
    inline void enter(void){pthread_mutex_lock(&jni_mutex);}
    inline void leave(void){pthread_mutex_unlock(&jni_mutex);}
#endif /* _WIN32 */
}

namespace thread_unsafe
{
    inline void init(void) {}
    inline void done(void) {}
    inline void enter(void){}
    inline void leave(void){}
}

#ifdef THREAD_SAFE
#define JNI_THREAD_SAFE
#endif /* THREAD_SAFE */

#ifdef JNI_THREAD_SAFE
namespace thread_model=thread_safe;
#else
namespace thread_model=thread_unsafe;
#endif /* JNI_THREAD_SAFE */

#endif /* __JIPRIVPG_H */
