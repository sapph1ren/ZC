#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <process.h>

#define WOLFSSL_USER_SETTINGS
#define OPENSSL_EXTRA
#define HAVE_AESGCM
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_TLS13
#define HAVE_ECC
#define HAVE_DH
#define HAVE_RSA
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_NO_DEF_TM_RESIST
#define WOLFSSL_MINGW
#define WOLFSSL_ANY_RECENT_WINDOWS
#define OPENSSL_EXTRA 
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_KEY_GEN
#define HAVE_AESGCM
#define HAVE_HASHDRBG
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define NO_PSK
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/asn.h"

#include "zlib/zlib.h"
#include "zlib/zconf.h"

#include "opus/opus.h"
#define MINIAUDIO_IMPLEMENTATION
#include "other/miniaudio.h"

#include "sqlite3.h"

#include <d3d11.h>      
#include <d3dcompiler.h>

#include "dcimgui/dcimgui.h"
#include "dcimgui/dcimgui_impl_win32.h"
#include "dcimgui/dcimgui_impl_dx11.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <tchar.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")



#define ITID ImTextureID
// #define ImVec2_t(x, y) ((ImVec2_t){x, y})
#define ImVec2(x, y) ((ImVec2){x, y})

static ID3D11Device*            g_pd3dDevice           = NULL;
static ID3D11DeviceContext*     g_pd3dDeviceContext    = NULL;
static IDXGISwapChain*          g_pSwapChain           = NULL;
static ID3D11RenderTargetView*  g_mainRenderTargetView = NULL;
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern LRESULT cImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

extern char _binary_museo_ttf_start[];
extern char _binary_museo_ttf_end[];


typedef struct {
	uint32_t mid;        // айди сообщения
	uint16_t cid;        // айди чата
	uint16_t uid;        // айди юзера
	bool dost;           // доставлено ли сообщение
	char time[16];       // время с датой
	union{               // тут может быть только одна из трех строк, шоб меньше памяти жрало
		char text[4096]; // текст до 4кб 
		ITID* img_ptr;   // указатель на фото
		char* path;      // путь до документа на отправку/просмотр
	} ctnt;
	uint8_t type;        // тип сообщения, чтобы правильно и быстро извлекать содержимое 
} msg;

typedef struct {
	uint16_t cid;        // айди чата
	char name[32];       // название чата
	ITID* ava_ptr;       // указатель на аватарку чата
	uint32_t ns;         // кол-во непрочитанных
	char buf[4096];      // буффер для ввода сообщения (шоб сохранялось между чатами)
	uint32_t lmid;	     // айди последнего сообщения
} chat;

typedef struct {
	char name[32];       // имя юзера
	uint16_t uid;        // айди юзера
	bool ver;            // важный бумажный
	ITID* ava_ptr;       //	указатель на аватарку
} user; 

typedef struct {
	char name[32];       // имя
	uint16_t uid;        // айди юзера
	uint64_t* hash;      // хэш пароля
	ITID* ava_ptr;       // указатель на аватарку
	bool ver;            // важный бумажный
	char obn[16];        // дата и время синхронизации с сервером
	/*
надо:
	сокеты
	ссл
	аудио
	и прочее глобальное, что будет передаваться, как указатель на одну структуру в main
	*/
	
} me;

static const char* SERVER_IP_POOL[] = {
    "95.163.249.123", 
    "185.215.4.56",    
    "45.138.201.12"    
};
#define IP_POOL_SIZE    3
#define SERVER_PORT     "443"
#define SERVER_SNI      "ozon.ru"
#define CHUNK_SIZE      16384
#define AUDIO_RATE_HQ   48000
#define AUDIO_RATE_LQ   16000
#define POOL_RESERVE    256
#define MAX_POOL_SIZE   65536 
#define DISK_QUEUE_MAX  128
#define POOL_RESERVE    256
#define MAX_POOL_SIZE   65536 
#define DISK_QUEUE_MAX  128
#define MAX_AUDIO_PKTS  128


typedef enum { SOCK_TEXT, SOCK_SYSTEM, SOCK_MEDIA, SOCK_AUDIO, SOCK_MAX } SocketType;

typedef enum {
    CONN_STATE_DISCONNECTED,
    CONN_STATE_CONNECTING_NET,
    CONN_STATE_TLS_HANDSHAKE,
    CONN_STATE_CONNECTED
} ConnState;

typedef struct {
    uint8_t data[MAX_POOL_SIZE];
    uint32_t len;
    uint32_t sent;
    volatile LONG in_use;
} zc_packet_t;

typedef struct {
    uint8_t data[512];
    uint32_t len;
} zc_audio_tx_pkt_t;

typedef struct {
    SOCKET fd; 
    WOLFSSL* ssl;
    ConnState state;
    uint64_t next_retry_time;
    uint32_t backoff_ms;
    uint32_t current_ip_idx; 
    CRITICAL_SECTION tx_lock;

    int tx_pool_indexes[64];
    uint32_t tx_head;
    uint32_t tx_tail;

    uint32_t expected_header_len;
    uint32_t target_payload_len;
    uint32_t text_orig_len;
    int rx_pool_idx;
    uint32_t payload_bytes_read;
    uint32_t header_bytes_read;
    uint8_t header_buf[8];
    bool reading_payload;
} zc_connection_t;

typedef struct {
    char file_path[MAX_PATH];
    bool is_write; 
    int pool_idx;  
    bool is_eof;
} zc_disk_task_t;

typedef struct {
    zc_connection_t conns[SOCK_MAX];
    WOLFSSL_CTX* ctx_tls;
    volatile bool running;
    bool is_legacy_cpu;
    uint32_t audio_sample_rate;
    uint32_t audio_rb_size;

    HANDLE worker_thread;
    HANDLE disk_thread;

    zc_packet_t pkt_pool[POOL_RESERVE];
    CRITICAL_SECTION pool_lock;

    zc_disk_task_t disk_queue[DISK_QUEUE_MAX];
    volatile LONG disk_q_write;
    volatile LONG disk_q_read;
    HANDLE disk_semaphore;

    ma_device audio_dev;
    bool audio_dev_init;
    OpusEncoder* enc;
    OpusDecoder* dec;

    float* audio_rb;
    volatile LONG rb_write;
    volatile LONG rb_read;

    zc_audio_tx_pkt_t audio_tx_queue[MAX_AUDIO_PKTS];
    volatile LONG audio_tx_write;
    volatile LONG audio_tx_read;
    
    volatile LONG64 file_counter; 
    uint64_t last_app_ping_time;

	    // Callback для доставки полученных сообщений (вызывается из сетевого потока)
    void (*on_message)(SocketType channel, uint8_t* data, uint32_t len, uint32_t orig_len);
} zc_engine_t;

static void ZC_ForceDisconnect(zc_engine_t* eng, SocketType t);

// ==============================================================================
// 1. СТАТИЧЕСКИЙ ПУЛ ПАКЕТОВ
// ==============================================================================

static int ZC_Pool_Acquire(zc_engine_t* eng) {
    EnterCriticalSection(&eng->pool_lock);
    for (int i = 0; i < POOL_RESERVE; i++) {
        if (InterlockedCompareExchange(&eng->pkt_pool[i].in_use, 1, 0) == 0) {
            eng->pkt_pool[i].len = 0;
            eng->pkt_pool[i].sent = 0;
            LeaveCriticalSection(&eng->pool_lock);
            return i;
        }
    }
    LeaveCriticalSection(&eng->pool_lock);
    return -1; 
}

static void ZC_Pool_Release(zc_engine_t* eng, int idx) {
    if (idx < 0 || idx >= POOL_RESERVE) return;
    InterlockedExchange(&eng->pkt_pool[idx].in_use, 0);
}

// ==============================================================================
// 2. I/O КОЛБЭКИ С ФРАГМЕНТАЦИЕЙ (ИСПРАВЛЕННЫЕ КОНСТАНТЫ)
// ==============================================================================

static int MyIOSend(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    if (!ctx) return WOLFSSL_CBIO_ERR_GENERAL;
    SOCKET s = *(SOCKET*)ctx;
    if (s == INVALID_SOCKET) return WOLFSSL_CBIO_ERR_CONN_RST;  // было CONN_RESET
    
    if (sz > 5 && (uint8_t)buf[0] == 0x16 && (uint8_t)buf[1] == 0x03 && (uint8_t)buf[5] == 0x01) {
        int chunk1 = 5 + (rand() % 11); 
        if (sz > chunk1) {
            int sent1 = 0, retry_count = 0;
            while (sent1 < chunk1) {
                int r1 = send(s, buf + sent1, chunk1 - sent1, 0);
                if (r1 < 0) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) {
                        fd_set wfds; struct timeval tv = {0, 0}; FD_ZERO(&wfds); FD_SET(s, &wfds);
                        if (select((int)s + 1, NULL, &wfds, NULL, &tv) <= 0) {
                            if (++retry_count > 2000) return WOLFSSL_CBIO_ERR_WANT_WRITE;
                            SwitchToThread(); continue;
                        }
                        continue;
                    }
                    return WOLFSSL_CBIO_ERR_CONN_RST;
                }
                sent1 += r1;
            }
            
            SwitchToThread();
            
            int remaining = sz - chunk1;
            int chunk2 = remaining / 2;
            int chunk3 = remaining - chunk2;
            int stages[2] = { chunk2, chunk3 };
            int offset = chunk1;

            for (int st = 0; st < 2; st++) {
                int target = stages[st];
                int sent_stage = 0;
                retry_count = 0;
                while (sent_stage < target) {
                    int r2 = send(s, buf + offset + sent_stage, target - sent_stage, 0);
                    if (r2 < 0) {
                        int err = WSAGetLastError();
                        if (err == WSAEWOULDBLOCK) {
                            fd_set wfds; struct timeval tv = {0, 0}; FD_ZERO(&wfds); FD_SET(s, &wfds);
                            if (select((int)s + 1, NULL, &wfds, NULL, &tv) <= 0) {
                                if (++retry_count > 2000) return WOLFSSL_CBIO_ERR_WANT_WRITE;
                                SwitchToThread(); continue;
                            }
                            continue;
                        }
                        return WOLFSSL_CBIO_ERR_CONN_RST;
                    }
                    sent_stage += r2;
                }
                offset += target;
                if (st == 0) SwitchToThread();
            }
            return sz;
        }
    }

    int r = send(s, buf, sz, 0);
    if (r < 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return WOLFSSL_CBIO_ERR_WANT_WRITE;
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    return r;
}

static int MyIORecv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    if (!ctx) return WOLFSSL_CBIO_ERR_GENERAL;
    SOCKET s = *(SOCKET*)ctx;
    if (s == INVALID_SOCKET) return WOLFSSL_CBIO_ERR_CONN_RST;

    int r = recv(s, buf, sz, 0);
    if (r < 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return WOLFSSL_CBIO_ERR_WANT_READ;
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    if (r == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return r;
}

// ==============================================================================
// 3. АСИНХРОННЫЙ ДИСКОВЫЙ ПОТОК (без изменений)
// ==============================================================================

static void ZC_PushDiskTask(zc_engine_t* eng, const char* path, bool is_write, int pool_idx, bool is_eof) {
    LONG w = InterlockedAdd(&eng->disk_q_write, 0);
    LONG r = InterlockedAdd(&eng->disk_q_read, 0);
    LONG next_w = (w + 1) % DISK_QUEUE_MAX;

    if (next_w != r) {
        if (path) strcpy_s(eng->disk_queue[w].file_path, MAX_PATH, path);
        else eng->disk_queue[w].file_path[0] = '\0';
        eng->disk_queue[w].is_write = is_write;
        eng->disk_queue[w].pool_idx = pool_idx;
        eng->disk_queue[w].is_eof = is_eof;
        MemoryBarrier();
        InterlockedExchange(&eng->disk_q_write, next_w);
        ReleaseSemaphore(eng->disk_semaphore, 1, NULL);
    } else {
        if (pool_idx != -1) ZC_Pool_Release(eng, pool_idx);
    }
}

DWORD WINAPI ZC_DiskWorker(LPVOID p) {
    zc_engine_t* eng = (zc_engine_t*)p;
    z_stream inflate_strm = {0};
    z_stream deflate_strm = {0};
    FILE* current_rx_file = NULL;
    FILE* current_tx_file = NULL;
    bool inf_init = false, def_init = false;

    while (eng->running) {
        WaitForSingleObject(eng->disk_semaphore, 100);
        if (!eng->running) break;

        LONG r = InterlockedAdd(&eng->disk_q_read, 0);
        LONG w = InterlockedAdd(&eng->disk_q_write, 0);

        while (r != w) {
            zc_disk_task_t task = eng->disk_queue[r];
            
            if (task.is_write) { 
                if (!current_rx_file && task.file_path[0] != '\0') {
                    current_rx_file = fopen(task.file_path, "wb");
                    if (current_rx_file) inf_init = (inflateInit(&inflate_strm) == Z_OK);
                }
                if (current_rx_file && inf_init && task.pool_idx != -1) {
                    zc_packet_t* pkt = &eng->pkt_pool[task.pool_idx];
                    inflate_strm.avail_in = pkt->len;
                    inflate_strm.next_in = pkt->data;
                    uint8_t out_buf[CHUNK_SIZE];
                    do {
                        inflate_strm.avail_out = CHUNK_SIZE;
                        inflate_strm.next_out = out_buf;
                        if (inflate(&inflate_strm, Z_NO_FLUSH) < 0) break;
                        fwrite(out_buf, 1, CHUNK_SIZE - inflate_strm.avail_out, current_rx_file);
                    } while (inflate_strm.avail_out == 0);
                }
                if (task.is_eof && current_rx_file) {
                    if (inf_init) inflateEnd(&inflate_strm);
                    fclose(current_rx_file); current_rx_file = NULL; inf_init = false;
                }
                if (task.pool_idx != -1) ZC_Pool_Release(eng, task.pool_idx);
            } 
            else { 
                if (!current_tx_file && task.file_path[0] != '\0') {
                    current_tx_file = fopen(task.file_path, "rb");
                    if (current_tx_file) def_init = (deflateInit(&deflate_strm, Z_BEST_SPEED) == Z_OK);
                }
                if (current_tx_file && def_init) {
                    uint8_t in_buf[CHUNK_SIZE];
                    uint8_t out_buf[CHUNK_SIZE + 4];
                    while (!feof(current_tx_file) && eng->running) {
                        if (InterlockedAdd(&eng->audio_tx_write, 0) != InterlockedAdd(&eng->audio_tx_read, 0)) {
                            SwitchToThread(); continue;
                        }
                        
                        size_t read_bytes = fread(in_buf, 1, CHUNK_SIZE, current_tx_file);
                        deflate_strm.avail_in = (uInt)read_bytes;
                        deflate_strm.next_in = in_buf;
                        deflate_strm.avail_out = CHUNK_SIZE;
                        deflate_strm.next_out = out_buf + 4;
                        
                        deflate(&deflate_strm, feof(current_tx_file) ? Z_FINISH : Z_NO_FLUSH);
                        uint32_t compressed = CHUNK_SIZE - deflate_strm.avail_out;
                        if (compressed > 0) {
                            *(uint32_t*)out_buf = htonl(compressed);
                            
                            EnterCriticalSection(&eng->conns[SOCK_MEDIA].tx_lock);
                            uint32_t next = (eng->conns[SOCK_MEDIA].tx_head + 1) % 64;
                            if (next != eng->conns[SOCK_MEDIA].tx_tail) {
                                int p_idx = ZC_Pool_Acquire(eng);
                                if (p_idx != -1) {
                                    memcpy(eng->pkt_pool[p_idx].data, out_buf, compressed + 4);
                                    eng->pkt_pool[p_idx].len = compressed + 4;
                                    eng->conns[SOCK_MEDIA].tx_pool_indexes[eng->conns[SOCK_MEDIA].tx_head] = p_idx;
                                    eng->conns[SOCK_MEDIA].tx_head = next;
                                }
                            }
                            LeaveCriticalSection(&eng->conns[SOCK_MEDIA].tx_lock);
                        }
                    }
                    deflateEnd(&deflate_strm); fclose(current_tx_file); current_tx_file = NULL; def_init = false;
                    
                    uint32_t eof_m = 0;
                    EnterCriticalSection(&eng->conns[SOCK_MEDIA].tx_lock);
                    uint32_t next = (eng->conns[SOCK_MEDIA].tx_head + 1) % 64;
                    if (next != eng->conns[SOCK_MEDIA].tx_tail) {
                        int p_idx = ZC_Pool_Acquire(eng);
                        if (p_idx != -1) {
                            memcpy(eng->pkt_pool[p_idx].data, &eof_m, 4);
                            eng->pkt_pool[p_idx].len = 4;
                            eng->conns[SOCK_MEDIA].tx_pool_indexes[eng->conns[SOCK_MEDIA].tx_head] = p_idx;
                            eng->conns[SOCK_MEDIA].tx_head = next;
                        }
                    }
                    LeaveCriticalSection(&eng->conns[SOCK_MEDIA].tx_lock);
                }
            }

            r = (r + 1) % DISK_QUEUE_MAX;
            InterlockedExchange(&eng->disk_q_read, r);
        }
    }
    if (current_rx_file) { if (inf_init) inflateEnd(&inflate_strm); fclose(current_rx_file); }
    if (current_tx_file) { if (def_init) deflateEnd(&deflate_strm); fclose(current_tx_file); }
    return 0;
}

// ==============================================================================
// 4. СЕТЕВОЙ МУЛЬТИПЛЕКСОР (ИСПРАВЛЕННЫЕ ВЫЗОВЫ WOLFSSL)
// ==============================================================================

void ZC_Send(zc_engine_t* eng, SocketType t, const void* data, uint32_t len) {
    zc_connection_t* c = &eng->conns[t];
    if (t == SOCK_MEDIA) {
        ZC_PushDiskTask(eng, (const char*)data, false, -1, false);
    } 
    else if (t == SOCK_AUDIO) {
        EnterCriticalSection(&c->tx_lock);
        uint32_t next = (c->tx_head + 1) % 64;
        if (next != c->tx_tail) {
            int p_idx = ZC_Pool_Acquire(eng);
            if (p_idx != -1) {
                *(uint32_t*)eng->pkt_pool[p_idx].data = htonl(len);
                memcpy(eng->pkt_pool[p_idx].data + 4, data, len);
                eng->pkt_pool[p_idx].len = len + 4;
                c->tx_pool_indexes[c->tx_head] = p_idx;
                c->tx_head = next;
            }
        }
        LeaveCriticalSection(&c->tx_lock);
    } 
    else {
        int p_idx = ZC_Pool_Acquire(eng);
        if (p_idx == -1) return;

        if (eng->is_legacy_cpu) {
            ((uint32_t*)eng->pkt_pool[p_idx].data)[0] = htonl(len);
            ((uint32_t*)eng->pkt_pool[p_idx].data)[1] = htonl(0xFFFFFFFF);
            memcpy(eng->pkt_pool[p_idx].data + 8, data, len);
            eng->pkt_pool[p_idx].len = len + 8;
        } 
        else {
            uLongf dest_len = compressBound(len);
            if (compress(eng->pkt_pool[p_idx].data + 8, &dest_len, (const Bytef*)data, len) == Z_OK) {
                ((uint32_t*)eng->pkt_pool[p_idx].data)[0] = htonl((uint32_t)dest_len);
                ((uint32_t*)eng->pkt_pool[p_idx].data)[1] = htonl(len);
                eng->pkt_pool[p_idx].len = (uint32_t)dest_len + 8;
            } else {
                ZC_Pool_Release(eng, p_idx);
                return;
            }
        }

        EnterCriticalSection(&c->tx_lock);
        uint32_t next = (c->tx_head + 1) % 64;
        if (next != c->tx_tail) {
            c->tx_pool_indexes[c->tx_head] = p_idx;
            c->tx_head = next;
        } else ZC_Pool_Release(eng, p_idx);
        LeaveCriticalSection(&c->tx_lock);
    }
}

static void ZC_ProcessRead(zc_engine_t* eng, SocketType t) {
    zc_connection_t* c = &eng->conns[t];
    while (eng->running) {
        if (!c->reading_payload) {
            uint32_t to_read = c->expected_header_len - c->header_bytes_read;
            int n = wolfSSL_read(c->ssl, c->header_buf + c->header_bytes_read, (int)to_read);
            if (n > 0) {
                c->header_bytes_read += n;
                if (c->header_bytes_read == c->expected_header_len) {
                    c->target_payload_len = (c->expected_header_len == 4) ? ntohl(*(uint32_t*)c->header_buf) : ntohl(((uint32_t*)c->header_buf)[0]);
                    c->text_orig_len = (c->expected_header_len == 8) ? ntohl(((uint32_t*)c->header_buf)[1]) : 0;
                    c->header_bytes_read = 0;

                    if (c->target_payload_len == 4 && c->text_orig_len == 0xFFFFFFFF) {
                        uint32_t pong_val = 0;
                        wolfSSL_read(c->ssl, &pong_val, 4);
                        continue;
                    }

                    if (c->target_payload_len == 0) {
                        if (t == SOCK_MEDIA) ZC_PushDiskTask(eng, NULL, true, -1, true);
                        continue;
                    }
                    if (c->target_payload_len > MAX_POOL_SIZE) { ZC_ForceDisconnect(eng, t); return; }

                    c->rx_pool_idx = ZC_Pool_Acquire(eng);
                    if (c->rx_pool_idx == -1) { ZC_ForceDisconnect(eng, t); return; } 
                    c->payload_bytes_read = 0; c->reading_payload = true;
                }
            } else {
                if (wolfSSL_get_error(c->ssl, n) == WOLFSSL_ERROR_WANT_READ) return;
                ZC_ForceDisconnect(eng, t); return;
            }
        }

        if (c->reading_payload) {
            uint32_t to_read = c->target_payload_len - c->payload_bytes_read;
            zc_packet_t* pkt = &eng->pkt_pool[c->rx_pool_idx];
            int n = wolfSSL_read(c->ssl, pkt->data + c->payload_bytes_read, (int)to_read);
            if (n > 0) {
                c->payload_bytes_read += n;
                if (c->payload_bytes_read == c->target_payload_len) {
                    pkt->len = c->target_payload_len;
                    
                    if (t == SOCK_MEDIA) {
                        char r_path[MAX_PATH]; 
                        int64_t file_id = InterlockedIncrement64(&eng->file_counter);
                        sprintf_s(r_path, MAX_PATH, "downloads/file_%llu_%lld.dat", GetTickCount64(), file_id);
                        ZC_PushDiskTask(eng, r_path, true, c->rx_pool_idx, false);
                    } 
                    else if (t == SOCK_AUDIO) {
                        opus_int16 pcm[960];
                        int frame_samples = eng->is_legacy_cpu ? 320 : 960;
                        int s = opus_decode(eng->dec, pkt->data, (int)pkt->len, pcm, frame_samples, 0);
                        if (s > 0) {
                            for (int i = 0; i < s; i++) {
                                LONG w = InterlockedAdd(&eng->rb_write, 0);
                                LONG next_w = (w + 1) % eng->audio_rb_size;
                                if (next_w != InterlockedAdd(&eng->rb_read, 0)) {
                                    eng->audio_rb[w] = pcm[i] / 32768.0f;
                                    MemoryBarrier(); InterlockedExchange(&eng->rb_write, next_w);
                                }
                            }
                        }
                        ZC_Pool_Release(eng, c->rx_pool_idx);
                    } 
                    else {
                        // Обработка текстовых/системных каналов с callback
                        if (eng->on_message) {
                            if (c->text_orig_len == 0xFFFFFFFF) {
                                // RAW режим (без сжатия)
                                eng->on_message(t, pkt->data, pkt->len, c->text_orig_len);
                            } else {
                                // Распаковываем zlib
                                uint8_t* o_buf = (uint8_t*)malloc(c->text_orig_len + 1);
                                if (o_buf) {
                                    uLongf u_len = c->text_orig_len;
                                    if (uncompress(o_buf, &u_len, pkt->data, pkt->len) == Z_OK) {
                                        eng->on_message(t, o_buf, (uint32_t)u_len, c->text_orig_len);
                                    }
                                    free(o_buf);
                                } else {
                                    // Если память не выделилась – просто освобождаем пакет
                                }
                            }
                        } else {
                            // Fallback: старый printf
                            if (c->text_orig_len == 0xFFFFFFFF) {
                                uint8_t* raw_buf = (uint8_t*)malloc(pkt->len + 1);
                                if (raw_buf) {
                                    memcpy(raw_buf, pkt->data, pkt->len);
                                    raw_buf[pkt->len] = '\0';
                                    printf("[Engine v5 RAW] Channel %d: %s\n", t, (char*)raw_buf);
                                    free(raw_buf);
                                }
                            } else {
                                uint8_t* o_buf = (uint8_t*)malloc(c->text_orig_len + 1);
                                if (o_buf) {
                                    uLongf u_len = c->text_orig_len;
                                    if (uncompress(o_buf, &u_len, pkt->data, pkt->len) == Z_OK) {
                                        o_buf[u_len] = '\0';
                                        printf("[Engine v5 ZLIB] Channel %d: %s\n", t, (char*)o_buf);
                                    }
                                    free(o_buf);
                                }
                            }
                        }
                        ZC_Pool_Release(eng, c->rx_pool_idx);
                    }
                    c->reading_payload = false;
                }
            } else {
                if (wolfSSL_get_error(c->ssl, n) == WOLFSSL_ERROR_WANT_READ) return;
                ZC_Pool_Release(eng, c->rx_pool_idx); ZC_ForceDisconnect(eng, t); return;
            }
        }
    }
}

static void ZC_ProcessWrite(zc_engine_t* eng, SocketType t) {
    zc_connection_t* c = &eng->conns[t];
    while (eng->running) {
        EnterCriticalSection(&c->tx_lock);
        if (c->tx_head == c->tx_tail) { LeaveCriticalSection(&c->tx_lock); return; }
        int p_idx = c->tx_pool_indexes[c->tx_tail];
        LeaveCriticalSection(&c->tx_lock);

        zc_packet_t* pkt = &eng->pkt_pool[p_idx];
        int n = wolfSSL_write(c->ssl, (char*)pkt->data + pkt->sent, (int)(pkt->len - pkt->sent));
        if (n > 0) {
            pkt->sent += n;
            if (pkt->sent == pkt->len) {
                ZC_Pool_Release(eng, p_idx);
                EnterCriticalSection(&c->tx_lock);
                c->tx_tail = (c->tx_tail + 1) % 64;
                LeaveCriticalSection(&c->tx_lock);
            }
        } else {
            if (wolfSSL_get_error(c->ssl, n) == WOLFSSL_ERROR_WANT_WRITE) return;
            ZC_ForceDisconnect(eng, t); return;
        }
    }
}

DWORD WINAPI ZC_Worker(LPVOID p) {
    zc_engine_t* eng = (zc_engine_t*)p;

    while (eng->running) {
        LONG ar = InterlockedAdd(&eng->audio_tx_read, 0);
        LONG aw = InterlockedAdd(&eng->audio_tx_write, 0);
        while (ar != aw) {
            ZC_Send(eng, SOCK_AUDIO, eng->audio_tx_queue[ar].data, eng->audio_tx_queue[ar].len);
            ar = (ar + 1) % MAX_AUDIO_PKTS;
            InterlockedExchange(&eng->audio_tx_read, ar);
        }

        uint64_t now = GetTickCount64();
        if (now - eng->last_app_ping_time > 30000) {
            for (int i = 0; i < SOCK_MAX; i++) {
                if (eng->conns[i].state == CONN_STATE_CONNECTED) {
                    uint32_t ping_hdr[2] = { htonl(4), htonl(0xFFFFFFFF) };
                    uint32_t ping_body = 0xDEADC0DE;
                    int p_idx = ZC_Pool_Acquire(eng);
                    if (p_idx != -1) {
                        memcpy(eng->pkt_pool[p_idx].data, ping_hdr, 8);
                        memcpy(eng->pkt_pool[p_idx].data + 8, &ping_body, 4);
                        eng->pkt_pool[p_idx].len = 12;
                        EnterCriticalSection(&eng->conns[i].tx_lock);
                        uint32_t next = (eng->conns[i].tx_head + 1) % 64;
                        if (next != eng->conns[i].tx_tail) {
                            eng->conns[i].tx_pool_indexes[eng->conns[i].tx_head] = p_idx;
                            eng->conns[i].tx_head = next;
                        } else ZC_Pool_Release(eng, p_idx);
                        LeaveCriticalSection(&eng->conns[i].tx_lock);
                    }
                }
            }
            eng->last_app_ping_time = now;
        }

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds); FD_ZERO(&write_fds);
        SOCKET max_s = 0; 

        bool audio_pending = false;
        EnterCriticalSection(&eng->conns[SOCK_AUDIO].tx_lock);
        if (eng->conns[SOCK_AUDIO].tx_head != eng->conns[SOCK_AUDIO].tx_tail) audio_pending = true;
        LeaveCriticalSection(&eng->conns[SOCK_AUDIO].tx_lock);

        LONG dq_w = InterlockedAdd(&eng->disk_q_write, 0);
        LONG dq_r = InterlockedAdd(&eng->disk_q_read, 0);
        LONG current_disk_depth = (dq_w - dq_r + DISK_QUEUE_MAX) % DISK_QUEUE_MAX;
        bool disk_overloaded = (current_disk_depth > (DISK_QUEUE_MAX - 16));

        bool global_disconnected = true;

        for (int i = 0; i < SOCK_MAX; i++) {
            zc_connection_t* c = &eng->conns[i];
            if (c->state != CONN_STATE_DISCONNECTED) global_disconnected = false;

            if (c->state == CONN_STATE_DISCONNECTED && now >= c->next_retry_time) {
                struct addrinfo *res = NULL;
                const char* target_ip = SERVER_IP_POOL[c->current_ip_idx];
                if (getaddrinfo(target_ip, SERVER_PORT, NULL, &res) == 0 && res != NULL) {
                    c->fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (c->fd != INVALID_SOCKET) {
                        u_long m = 1; ioctlsocket(c->fd, FIONBIO, &m);
                        int keepalive = 1, keepcnt = 3, keepidle = 10, keepintvl = 2;
                        setsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive));
                        connect(c->fd, res->ai_addr, (int)res->ai_addrlen);
                        c->state = CONN_STATE_CONNECTING_NET;
                        global_disconnected = false;
                    }
                    freeaddrinfo(res);
                } else {
                    c->next_retry_time = GetTickCount64() + c->backoff_ms;
                }
            }

            if (c->fd == INVALID_SOCKET) continue;
            if (c->fd > max_s) max_s = c->fd;

            if (c->state == CONN_STATE_CONNECTING_NET) FD_SET(c->fd, &write_fds);
            else if (c->state == CONN_STATE_TLS_HANDSHAKE) { FD_SET(c->fd, &read_fds); FD_SET(c->fd, &write_fds); }
            else if (c->state == CONN_STATE_CONNECTED) {
                if (!(i == SOCK_MEDIA && disk_overloaded)) FD_SET(c->fd, &read_fds);
                
                bool has_tx = false;
                EnterCriticalSection(&c->tx_lock);
                if (c->tx_head != c->tx_tail) has_tx = true;
                LeaveCriticalSection(&c->tx_lock);

                if (has_tx && !(i == SOCK_MEDIA && audio_pending)) FD_SET(c->fd, &write_fds);
            }
        }

        struct timeval tv;
        if (global_disconnected) {
            tv.tv_sec = 0; tv.tv_usec = 250000;
        } else if (eng->conns[SOCK_AUDIO].state == CONN_STATE_CONNECTED || current_disk_depth > 0) {
            tv.tv_sec = 0; tv.tv_usec = 10000;
        } else {
            tv.tv_sec = 0; tv.tv_usec = 50000;
        }

        if (select((int)max_s + 1, &read_fds, &write_fds, NULL, &tv) > 0 && eng->running) {
            for (int i = 0; i < SOCK_MAX; i++) {
                zc_connection_t* c = &eng->conns[i];
                if (c->fd == INVALID_SOCKET) continue;

                if (c->state == CONN_STATE_CONNECTING_NET && FD_ISSET(c->fd, &write_fds)) {
                    int err = 0; int len = sizeof(err); getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
                    if (err == 0) {
                        c->ssl = wolfSSL_new(eng->ctx_tls);
                        // Используем стандартный wolfSSL_set_fd вместо wolfSSL_set_IO_ctx
                        wolfSSL_set_fd(c->ssl, (int)c->fd);
                        
                        // SNI через CTX или SSL (если доступно, иначе игнорируем)
                        #ifdef WOLFSSL_SNI
                        wolfSSL_UseSNI(c->ssl, WOLFSSL_SNI_HOST_NAME, SERVER_SNI, (unsigned short)strlen(SERVER_SNI));
                        #endif
                        
                        c->state = CONN_STATE_TLS_HANDSHAKE;
                    } else ZC_ForceDisconnect(eng, (SocketType)i);
                }
                else if (c->state == CONN_STATE_TLS_HANDSHAKE && (FD_ISSET(c->fd, &read_fds) || FD_ISSET(c->fd, &write_fds))) {
                    int ret = wolfSSL_connect(c->ssl);
                    if (ret == WOLFSSL_SUCCESS) { c->state = CONN_STATE_CONNECTED; c->backoff_ms = 1000; }
                    else if (wolfSSL_get_error(c->ssl, ret) != WOLFSSL_ERROR_WANT_READ && wolfSSL_get_error(c->ssl, ret) != WOLFSSL_ERROR_WANT_WRITE) {
                        ZC_ForceDisconnect(eng, (SocketType)i);
                    }
                }
                else if (c->state == CONN_STATE_CONNECTED) {
                    if (FD_ISSET(c->fd, &read_fds)) ZC_ProcessRead(eng, (SocketType)i);
                    if (FD_ISSET(c->fd, &write_fds)) ZC_ProcessWrite(eng, (SocketType)i);
                }
            }
        }
    }
    return 0;
}

void ZC_Handler(SocketType channel, uint8_t* data, uint32_t len, uint32_t orig_len){
	
}

static void ZC_ForceDisconnect(zc_engine_t* eng, SocketType t) {
    zc_connection_t* c = &eng->conns[t];
    c->state = CONN_STATE_DISCONNECTED;
    if (c->ssl) { wolfSSL_free(c->ssl); c->ssl = NULL; }
    if (c->fd != INVALID_SOCKET) { closesocket(c->fd); c->fd = INVALID_SOCKET; }
    if (c->reading_payload) { ZC_Pool_Release(eng, c->rx_pool_idx); c->reading_payload = false; }
    c->header_bytes_read = 0; c->payload_bytes_read = 0;

    EnterCriticalSection(&c->tx_lock);
    while (c->tx_tail != c->tx_head) {
        ZC_Pool_Release(eng, c->tx_pool_indexes[c->tx_tail]);
        c->tx_tail = (c->tx_tail + 1) % 64;
    }
    LeaveCriticalSection(&c->tx_lock);
    
    c->current_ip_idx = (c->current_ip_idx + 1) % IP_POOL_SIZE;
    c->next_retry_time = GetTickCount64() + c->backoff_ms;
    c->backoff_ms = min(c->backoff_ms * 2, 30000);
}

// ==============================================================================
// 5. АУДИОКОЛБЭК (без изменений)
// ==============================================================================

void ZC_AudioCallback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 fCount) {
    zc_engine_t* eng = (zc_engine_t*)pDevice->pUserData;
    int expected_frame = eng->is_legacy_cpu ? 320 : 960;

    if (pInput && eng->conns[SOCK_AUDIO].state == CONN_STATE_CONNECTED) {
        LONG tw = InterlockedAdd(&eng->audio_tx_write, 0);
        LONG tr = InterlockedAdd(&eng->audio_tx_read, 0);
        LONG next_tw = (tw + 1) % MAX_AUDIO_PKTS;

        if (next_tw != tr) { 
            int b = opus_encode(eng->enc, (const opus_int16*)pInput, expected_frame, eng->audio_tx_queue[tw].data, 512);
            if (b > 0) {
                eng->audio_tx_queue[tw].len = (uint32_t)b;
                MemoryBarrier();
                InterlockedExchange(&eng->audio_tx_write, next_tw);
            }
        } 
    }

    float* out = (float*)pOutput;
    for (ma_uint32 i = 0; i < fCount; i++) {
        LONG r = InterlockedAdd(&eng->rb_read, 0);
        if (r != InterlockedAdd(&eng->rb_write, 0)) {
            out[i] = eng->audio_rb[r];
            InterlockedExchange(&eng->rb_read, (r + 1) % eng->audio_rb_size);
        } else out[i] = 0.0f; 
    }
}

// ==============================================================================
// 6. API ЖИЗНЕННОГО ЦИКЛА (ИСПРАВЛЕННЫЙ)
// ==============================================================================

static void CreateDirectoryRecursive(const char* path) {
    char tmp[MAX_PATH];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '\\') tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '\\') {
            *p = 0;
            CreateDirectoryA(tmp, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(tmp, NULL);
}

zc_engine_t* ZC_CreateEngine(bool enable_legacy_mode, void (*on_message)(int channel, uint8_t* data, uint32_t len, uint32_t orig_len)) {
    srand((unsigned int)GetTickCount64());
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return NULL;
    wolfSSL_Init();

    zc_engine_t* eng = (zc_engine_t*)calloc(1, sizeof(zc_engine_t));
    if (!eng) return NULL;

    eng->is_legacy_cpu = enable_legacy_mode;
    eng->audio_sample_rate = eng->is_legacy_cpu ? AUDIO_RATE_LQ : AUDIO_RATE_HQ;
    eng->audio_rb_size = eng->audio_sample_rate * 4;
    eng->last_app_ping_time = GetTickCount64();
    eng->on_message = on_message;   // ← сохраняем callback

    CreateDirectoryRecursive("downloads");

    InitializeCriticalSection(&eng->pool_lock);
    eng->disk_semaphore = CreateSemaphore(NULL, 0, DISK_QUEUE_MAX, NULL);

    #ifdef WOLFSSL_TLS13
        WOLFSSL_METHOD* method = wolfTLSv1_3_client_method();
    #else
        WOLFSSL_METHOD* method = wolfTLSv1_2_client_method();
    #endif
    eng->ctx_tls = wolfSSL_CTX_new(method);
    if (!eng->ctx_tls) { free(eng); return NULL; }
    
    wolfSSL_CTX_set_cipher_list(eng->ctx_tls, 
        "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    
    wolfSSL_CTX_set_verify(eng->ctx_tls, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_set_timeout(eng->ctx_tls, 30);

    #ifdef WOLFSSL_CALLBACKS
        wolfSSL_SetIOSend(eng->ctx_tls, MyIOSend);
        wolfSSL_SetIORecv(eng->ctx_tls, MyIORecv);
    #endif

    eng->audio_rb = (float*)calloc(eng->audio_rb_size, sizeof(float));
    eng->enc = opus_encoder_create(eng->audio_sample_rate, 1, OPUS_APPLICATION_VOIP, NULL);
    eng->dec = opus_decoder_create(eng->audio_sample_rate, 1, NULL);

    if (!eng->audio_rb || !eng->enc || !eng->dec) {
        if (eng->enc) opus_encoder_destroy(eng->enc);
        if (eng->dec) opus_decoder_destroy(eng->dec);
        free(eng->audio_rb); wolfSSL_CTX_free(eng->ctx_tls); free(eng); return NULL;
    }

    if (eng->is_legacy_cpu) {
        opus_encoder_ctl(eng->enc, OPUS_SET_COMPLEXITY(1)); 
        opus_encoder_ctl(eng->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
        opus_encoder_ctl(eng->enc, OPUS_SET_BITRATE(12000)); 
    }

    ma_device_config cfg = ma_device_config_init(ma_device_type_duplex);
    cfg.capture.format = ma_format_s16; cfg.sampleRate = eng->audio_sample_rate;
    cfg.dataCallback = ZC_AudioCallback; cfg.pUserData = eng;
    if (ma_device_init(NULL, &cfg, &eng->audio_dev) == MA_SUCCESS) {
        eng->audio_dev_init = true; ma_device_start(&eng->audio_dev);
    }

    for (int i = 0; i < SOCK_MAX; i++) {
        InitializeCriticalSection(&eng->conns[i].tx_lock);
        eng->conns[i].fd = INVALID_SOCKET;
        eng->conns[i].backoff_ms = 1000;
        eng->conns[i].current_ip_idx = i % IP_POOL_SIZE;
        eng->conns[i].expected_header_len = (i == SOCK_TEXT || i == SOCK_SYSTEM) ? 8 : 4;
    }

    eng->running = true;
    eng->worker_thread = CreateThread(NULL, 0, ZC_Worker, eng, 0, NULL);
    eng->disk_thread = CreateThread(NULL, 0, ZC_DiskWorker, eng, 0, NULL);

    return eng;
}

void ZC_DestroyEngine(zc_engine_t* eng) {
    if (!eng) return;
    eng->running = false;

    for (int i = 0; i < SOCK_MAX; i++) {
        if (eng->conns[i].fd != INVALID_SOCKET) {
            closesocket(eng->conns[i].fd);
        }
    }

    ReleaseSemaphore(eng->disk_semaphore, 1, NULL);
    
    if (eng->worker_thread) { WaitForSingleObject(eng->worker_thread, INFINITE); CloseHandle(eng->worker_thread); }
    if (eng->disk_thread) { WaitForSingleObject(eng->disk_thread, INFINITE); CloseHandle(eng->disk_thread); }
    
    CloseHandle(eng->disk_semaphore);

    if (eng->audio_dev_init) ma_device_uninit(&eng->audio_dev);
    opus_encoder_destroy(eng->enc); opus_decoder_destroy(eng->dec);

    for (int i = 0; i < SOCK_MAX; i++) {
        ZC_ForceDisconnect(eng, (SocketType)i);
        DeleteCriticalSection(&eng->conns[i].tx_lock);
    }

    DeleteCriticalSection(&eng->pool_lock);
    wolfSSL_CTX_free(eng->ctx_tls);
    free(eng->audio_rb); free(eng);
    wolfSSL_Cleanup(); WSACleanup();
}


void zc_chat(short x, short y, chat* c){
	igSetNextWindowSize((ImVec2){x*0.65, y}, NULL);
	igSetNextWindowPos((ImVec2){x*0.35, 0}, NULL);
	igBegin("c", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);
	float p_h;
	float i_h;
	ImVec2 t_s = igCalcTextSize(c->buf); 
	float l_h = igGetTextLineHeight();
	short l_c = ceil(t_s.y/l_h);
	l_c = (l_c < 5 ? l_c : 5);
	i_h = l_c*l_h + y*0.01f;
	p_h = i_h + y*0.02f;
	
	/*


	надо стили и расширение ввода сделать
	

	*/
	igSetCursorPos((ImVec2){x*0.1, y*0.96 -p_h});
    igDummy(ImVec2(0, 0));
	// style
	igPushStyleVarImVec2(ImGuiStyleVar_WindowPadding, (ImVec2){x*0.07, y*0.01});
	igPushStyleColorImVec4(ImGuiCol_ChildBg, (ImVec4){0.125f, 0.133f, 0.145f, 1.0f});
	igSetNextWindowPos((ImVec2){x*0.45, y*0.96 -p_h}, NULL);
    if(igBeginChild("##p", ImVec2(x*0.45, p_h), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar)){
		igSetNextItemWidth(x*0.4);
		float _y = (p_h - i_h) * 0.5f;
		igSetCursorPos((ImVec2){20, _y});
		
		if (igInputTextMultilineEx("##i", c->buf, 4096, ImVec2(x*0.386, i_h), ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_WordWrap, NULL, NULL)){
			c->buf[0]='\0';


		}
	}
	igEndChild();
	igPopStyleVarEx(1);
	igPopStyleColor();
	igEnd();
}

void zc_voice(short x, short y){
	igSetNextWindowSize((ImVec2){x*0.35, y*0.7}, NULL);
	igSetNextWindowPos((ImVec2){0, 0}, NULL);
	igBegin("v", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

	igTextUnformatted("войс");


	
	igEnd();
}

void zc_sw(short x, short y){
	igSetNextWindowSize((ImVec2){x*0.35, y*0.3}, NULL);
	igSetNextWindowPos((ImVec2){0, y*0.7}, NULL);
	igBegin("s", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

	igTextUnformatted("св");


	
	igEnd();
}

/*

бд функции

*/

/*

инет функци

*/



// size_t Inet::curl_write_cb(void* contents, size_t size, size_t nmemb, std::string* out) {
//     size_t total = size * nmemb;
//     out->append(static_cast<char*>(contents), total);
//     return total;
// }

// std::string Inet::fetch_server_address() {
//     CURL* curl = curl_easy_init();
//     if (!curl) return "";
//     std::string response;
//     curl_easy_setopt(curl, CURLOPT_URL, "https://api.jsonbin.io/v3/b/698b3111ae596e708f20064a");
//     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
//     curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
//     curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

//     struct curl_slist* headers = nullptr;
//     headers = curl_slist_append(headers, "x-access-key: $2a$10$h5aritiqbmvxqzitousr0e8t3zcpl.10zhkcarhjc26ju7xazkody");
//     curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

//     CURLcode res = curl_easy_perform(curl);
//     curl_slist_free_all(headers);
//     curl_easy_cleanup(curl);

//     if (res != CURLE_OK) return "";
//     try {
//         json j = json::parse(response);
//         return j["record"]["s"].get<std::string>();
//     }
//     catch (...) {
//         return "";
//     }
// }


int main(int argc, char** argv) {
	
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("Zipcord"), NULL };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, _T("Zipcord"), WS_OVERLAPPEDWINDOW, 100, 100, 1920, 1080, NULL, NULL, wc.hInstance, NULL);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    igCreateContext(NULL);
    ImGuiIO* io = igGetIO();
    io->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
	int font_data_size = (int)((intptr_t)_binary_museo_ttf_end - (intptr_t)_binary_museo_ttf_start);

	ImFontAtlas* atlas = igGetIO()->Fonts;
	const ImWchar* ranges = ImFontAtlas_GetGlyphRangesCyrillic(atlas);

	ImFont* myFont = ImFontAtlas_AddFontFromMemoryTTF(
		atlas, 
		_binary_museo_ttf_start, 
		font_data_size, 
		24.0f, 
		NULL, 
		ranges
	);
	//ImFont* font = ImFontAtlas_AddFontFromFileTTF(atlas, "C:\\Windows\\Fonts\\segoeui.ttf", 26.0f, NULL, NULL);
	
    igStyleColorsDark(NULL);

    cImGui_ImplWin32_Init(hwnd);
    cImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = { 0.45f, 0.55f, 0.60f, 1.00f };

	zc_engine_t* zc = ZC_CreateEngine(false, ZC_Handler); // false = потужный пк, true = калькулятор
	if (!zc) {
		return 12;
    }
	

	
	
	chat* chat_schas = malloc(sizeof(chat));
	user* usrs;
	chat* chats;
	uint16_t g_cid;
	
	bool done = false;
    while (!done)
    {
        if (IsIconic(hwnd)) {
            Sleep(50);
            
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) done = true;
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            continue; 
        }

        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT) done = true;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (done) break;

        cImGui_ImplDX11_NewFrame();
        cImGui_ImplWin32_NewFrame();
        igNewFrame();
		float x, y;
		x=io->DisplaySize.x;
		y=io->DisplaySize.y;

		zc_chat(x, y, chat_schas);
		zc_voice(x, y);
		zc_sw(x, y);
		
        igRender();

        g_pd3dDeviceContext->lpVtbl->OMSetRenderTargets(g_pd3dDeviceContext, 1, &g_mainRenderTargetView, NULL);
        float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->lpVtbl->ClearRenderTargetView(g_pd3dDeviceContext, g_mainRenderTargetView, clear_color_with_alpha);
        
        cImGui_ImplDX11_RenderDrawData(igGetDrawData());

        g_pSwapChain->lpVtbl->Present(g_pSwapChain, 1, 0);
        MsgWaitForMultipleObjects(0, NULL, FALSE, INFINITE, QS_ALLINPUT); 
        // if (GetForegroundWindow() != hwnd) {
        //     Sleep(100); 
        // }
    }
	// free svoe
	if(zc) {ZC_DestroyEngine(zc);}
	
	free(chat_schas);
	

	
    cImGui_ImplDX11_Shutdown();
    cImGui_ImplWin32_Shutdown();
    igDestroyContext(NULL);

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    // createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG; // ????????????????? ??? ??????
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
	
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->lpVtbl->Release(g_pSwapChain); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->lpVtbl->Release(g_pd3dDeviceContext); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->lpVtbl->Release(g_pd3dDevice); g_pd3dDevice = NULL; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->lpVtbl->GetBuffer(g_pSwapChain, 0, &IID_ID3D11Texture2D, (void**)&pBackBuffer);
    g_pd3dDevice->lpVtbl->CreateRenderTargetView(g_pd3dDevice, (ID3D11Resource*)pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->lpVtbl->Release(pBackBuffer);
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->lpVtbl->Release(g_mainRenderTargetView); g_mainRenderTargetView = NULL; }
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (cImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->lpVtbl->ResizeBuffers(g_pSwapChain, 0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) 
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
