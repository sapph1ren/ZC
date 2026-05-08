#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H
#define WOLFSSL_NO_DEF_TM_RESIST
#include <wolfssl/wolfcrypt/settings.h>
#define WOLFSSL_MINGW
#define WOLFSSL_ANY_RECENT_WINDOWS
/* Это самое важное — заставляет wolfSSL работать */
#define OPENSSL_EXTRA 
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_KEY_GEN
#define HAVE_AESGCM
#define HAVE_HASHDRBG
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define NO_PSK

#endif
