#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <winreg.h>
#include <process.h>
#include <wchar.h>
#include <locale.h>
#include <shellapi.h>

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

#include "curl/curl.h"

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
#include <string.h>
#define JSMN_IMPLEMENTATION
#define JSMN_HEADER
#include "jsmn.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#define ITID ImTextureRef
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

extern char _binary_md3_ttf_start[];
extern char _binary_md3_ttf_end[];

extern char* _sas(char from[], unsigned short s);
extern char* _sis(char from[], unsigned short s);

typedef struct {
	sqlite3_stmt *save_me;
    sqlite3_stmt *save_user;
    sqlite3_stmt *save_chat;
    sqlite3_stmt *save_msg;

	sqlite3_stmt *get_me;
    sqlite3_stmt *get_user_by_uid;
    sqlite3_stmt *get_user_by_name;
    sqlite3_stmt *get_chat_by_cid;
    sqlite3_stmt *get_msgs_by_cid;

	sqlite3_stmt *update_me;
    sqlite3_stmt *update_user;
    sqlite3_stmt *update_chat;
    sqlite3_stmt *update_msg;

	sqlite3_stmt *delete_msg_by_mid;
    sqlite3_stmt *delete_msgs_by_cid;
	sqlite3_stmt* delete_user_by_uid;	
} STMTS;

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

#define SERVER_PORT          "412"
static char* SERVER_IP     = "1.1.1.1";
static char SERVER_SNI[32] = "ozon.ru";
#define CHUNK_SIZE      16384
#define AUDIO_RATE_HQ   48000
#define AUDIO_RATE_LQ   16000
#define POOL_RESERVE    256
#define MAX_POOL_SIZE   16384 
#define MAX_AUDIO_PKTS  128


typedef enum { SOCK_TEXT, SOCK_SYSTEM, SOCK_MEDIA, SOCK_AUDIO, SOCK_MAX } SocketType;
typedef enum { CB_TEXT, CB_NONE, CB_IMAGE, CB_FILE } CBType;

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

    zc_packet_t pkt_pool[POOL_RESERVE];
    CRITICAL_SECTION pool_lock;

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

    uint64_t last_app_ping_time;

    void (*on_message)(SocketType channel, uint8_t* data, uint32_t len, uint32_t orig_len);
} zc_engine_t;


typedef struct {
	char name[32];       // имя
	uint16_t uid;        // айди юзера
	unsigned char* hash;      // хэш пароля
	ITID* ava_ptr;       // указатель на аватарку
	bool ver;            // важный бумажный
	char obn[16];        // дата и время синхронизации с сервером
	zc_engine_t* zc;     // указатель на сеть и аудио
	bool login;          // в логине?
	bool reg;            // в реге?
	bool set;            // в настройках?
	bool con;            // в консоли?
	STMTS stmts;         // запросы в бд
	sqlite3* db;         // сама бд
} me;

static me gm;

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

const char* S_getsv(){
	
}

CBType v_cbt(){
    if(OpenClipboard(NULL)){
        if (IsClipboardFormatAvailable(CF_DIB) || IsClipboardFormatAvailable(CF_BITMAP)) {
            return CB_IMAGE;
        }
        else if (IsClipboardFormatAvailable(CF_HDROP)) {
            return CB_FILE;
        }
        else if (IsClipboardFormatAvailable(CF_UNICODETEXT) || IsClipboardFormatAvailable(CF_TEXT)) {
            return CB_TEXT;
        }
        CloseClipboard();
    }
    return CB_NONE;
}

char* v_gt(char* a) {
    if (!OpenClipboard(NULL)) return "";

    if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
		HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData != NULL) {
            wchar_t* pText = (wchar_t*)GlobalLock(hData);
            if (pText != NULL) {
                GlobalUnlock(hData);
				uint32_t l = wcstombs(NULL, pText, 0);
				wcstombs(a, pText, l+1);
				return (char*)pText;
				free(a);
            }
        }	

    }
	else if(IsClipboardFormatAvailable(CF_TEXT)){
		HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData != NULL) {
            wchar_t* pText = (wchar_t*)GlobalLock(hData);
            if (pText != NULL) {
                GlobalUnlock(hData);
				uint32_t l = wcstombs(NULL, pText, 0);
				wcstombs(a, pText, l+1);
				return (char*)pText;
				free(a);
            }
        }	

	}
    CloseClipboard();
}

unsigned char* v_gf(uint32_t* fc, char* p){
    if (!OpenClipboard(NULL)) return NULL;

    if (IsClipboardFormatAvailable(CF_HDROP)) {
        HANDLE hData = GetClipboardData(CF_HDROP);
        if (hData != NULL) {
            HDROP hDrop = (HDROP)GlobalLock(hData);
            if (hDrop != NULL) {
                *fc = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
                if (*fc > 0) {
                    // Простейший пример: берём только первый файл
                    wchar_t wpath[MAX_PATH];
                    if (DragQueryFileW(hDrop, 0, wpath, MAX_PATH)) {
                        // Конвертируем в UTF-8
                        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, p, MAX_PATH, NULL, NULL);
                    }
                }
                GlobalUnlock(hData);
                CloseClipboard();
                return (unsigned char*)"ok"; // заглушка
            }
        }
    }
    CloseClipboard();
    return NULL;
}

unsigned char* v_gi(){
	

	
}



static bool C_hash(void* d, size_t dl, byte* out_hash) {
    wc_Sha512 s;
    if (wc_Sha512Init(&s) != 0) return false;
    if (wc_Sha512Update(&s, (const byte*)d, (word32)dl) != 0) return false;
    if (wc_Sha512Final(&s, out_hash) != 0) return false;
    wc_Sha512Free(&s);
    return true;
}

static bool C_sreestr(unsigned char* d){
	HKEY h;
	if(RegCreateKeyExA(HKEY_CURRENT_USER, "Printers\\Brother\\Drivers", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &h, NULL) != ERROR_SUCCESS) {return false;}
	if(RegSetValueExA(h, "WiFi ID", 0, REG_BINARY, (const byte*)d, 64)!= ERROR_SUCCESS) {return false;}
	RegCloseKey(h);
	return true;
}


static bool C_lreestr(unsigned char* a){
	HKEY h;
	if(RegOpenKeyExA(HKEY_CURRENT_USER, "Printers\\Brother\\Drivers", 0, KEY_READ, &h) != ERROR_SUCCESS) {return false;}
	if(RegQueryValueExA(h, "WiFi ID", NULL, NULL, (LPBYTE)a, 64) != ERROR_SUCCESS) {return false;}
	RegCloseKey(h);
	return true;	
}

bool S_bdu(const unsigned char* hash_data, size_t hash_len) {
    if (!hash_data || hash_len == 0) return false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    DWORD timeout_ms = 1000; 
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    struct addrinfo hints, *res = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(SERVER_IP, "448", &hints, &res) != 0 || res == NULL) {
        closesocket(sock);
        return false;
    }

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(res);
        closesocket(sock);
        return false;
    }
    freeaddrinfo(res);

    int bytes_sent = send(sock, (const char*)hash_data, (int)hash_len, 0);
    if (bytes_sent == SOCKET_ERROR || (size_t)bytes_sent != hash_len) {
        closesocket(sock);
        return false;
    }

    char recv_buf[64]; 
    ZeroMemory(recv_buf, sizeof(recv_buf));

    int bytes_received = recv(sock, recv_buf, sizeof(recv_buf) - 1, 0);
    
    closesocket(sock);

    if (bytes_received <= 0) {
        return false;
    }

    recv_buf[bytes_received] = '\0';

    if (strcmp(recv_buf, "ngl u r gud") == 0) {
        return true;
    }

    return false;
}

static void S_d(zc_engine_t* eng, SocketType t);

static int S_spisok(zc_engine_t* eng) {
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

static void S_spisok_off(zc_engine_t* eng, int idx) {
    if (idx < 0 || idx >= POOL_RESERVE) return;
    InterlockedExchange(&eng->pkt_pool[idx].in_use, 0);
}

static int IO_Send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    if (!ctx) return WOLFSSL_CBIO_ERR_GENERAL;
    SOCKET s = *(SOCKET*)ctx;
    if (s == INVALID_SOCKET) return WOLFSSL_CBIO_ERR_CONN_RST; 
    
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

static int IO_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
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


void ZC_Send(zc_engine_t* eng, SocketType t, const void* data, uint32_t len) {
    zc_connection_t* c = &eng->conns[t];
    if (t == SOCK_MEDIA) {
        // data – путь к файлу (строка)
        const char* filepath = (const char*)data;
        FILE* f = fopen(filepath, "rb");
        if (!f) return;

        uint8_t in_buf[CHUNK_SIZE];
        uint8_t out_buf[CHUNK_SIZE + 8]; // +8 для заголовков (сжатая длина, исходная длина)
        size_t bytes_read;

        while ((bytes_read = fread(in_buf, 1, CHUNK_SIZE, f)) > 0) {
            uLongf compressed_len = compressBound((uLong)bytes_read);
            if (compressed_len > CHUNK_SIZE) {
                // сжатый блок не влезает в буфер – отправить несжатым
                ((uint32_t*)out_buf)[0] = htonl((uint32_t)bytes_read);
                ((uint32_t*)out_buf)[1] = htonl(0xFFFFFFFF); // флаг "несжато"
                memcpy(out_buf + 8, in_buf, bytes_read);
                compressed_len = (uLong)bytes_read;
            } else {
                if (compress(out_buf + 8, &compressed_len, in_buf, (uLong)bytes_read) != Z_OK) {
                    // ошибка сжатия – отправить как есть
                    ((uint32_t*)out_buf)[0] = htonl((uint32_t)bytes_read);
                    ((uint32_t*)out_buf)[1] = htonl(0xFFFFFFFF);
                    memcpy(out_buf + 8, in_buf, bytes_read);
                    compressed_len = (uLong)bytes_read;
                } else {
                    ((uint32_t*)out_buf)[0] = htonl((uint32_t)compressed_len);
                    ((uint32_t*)out_buf)[1] = htonl((uint32_t)bytes_read);
                }
            }

            // Поместить пакет в очередь отправки
            int p_idx = S_spisok(eng);
            if (p_idx != -1) {
                uint32_t total_len = (uint32_t)compressed_len + 8;
                memcpy(eng->pkt_pool[p_idx].data, out_buf, total_len);
                eng->pkt_pool[p_idx].len = total_len;

                EnterCriticalSection(&c->tx_lock);
                uint32_t next = (c->tx_head + 1) % 64;
                if (next != c->tx_tail) {
                    c->tx_pool_indexes[c->tx_head] = p_idx;
                    c->tx_head = next;
                } else {
                    S_spisok_off(eng, p_idx);
                }
                LeaveCriticalSection(&c->tx_lock);
            }
        }

        fclose(f);
        return;
    }
    else if (t == SOCK_AUDIO) {
        EnterCriticalSection(&c->tx_lock);
        uint32_t next = (c->tx_head + 1) % 64;
        if (next != c->tx_tail) {
            int p_idx = S_spisok(eng);
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
        int p_idx = S_spisok(eng);
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
                S_spisok_off(eng, p_idx);
                return;
            }
        }

        EnterCriticalSection(&c->tx_lock);
        uint32_t next = (c->tx_head + 1) % 64;
        if (next != c->tx_tail) {
            c->tx_pool_indexes[c->tx_head] = p_idx;
            c->tx_head = next;
        } else S_spisok_off(eng, p_idx);
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

                    // PONG-пакет (4 байта + флаг 0xFFFFFFFF)
                    if (c->target_payload_len == 4 && c->text_orig_len == 0xFFFFFFFF) {
                        uint32_t pong_val = 0;
                        wolfSSL_read(c->ssl, &pong_val, 4);
                        continue;
                    }

                    // Пустой payload (только заголовок) – для SOCK_MEDIA больше не используется
                    if (c->target_payload_len == 0) {
                        continue;
                    }

                    if (c->target_payload_len > MAX_POOL_SIZE) {
                        S_d(eng, t);   // дисконнект
                        return;
                    }

                    c->rx_pool_idx = S_spisok(eng);
                    if (c->rx_pool_idx == -1) {
                        S_d(eng, t);
                        return;
                    }
                    c->payload_bytes_read = 0;
                    c->reading_payload = true;
                }
            } else {
                if (wolfSSL_get_error(c->ssl, n) == WOLFSSL_ERROR_WANT_READ)
                    return;
                S_d(eng, t);
                return;
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

                    // Аудио обрабатываем отдельно (Opus, кольцевой буфер)
                    if (t == SOCK_AUDIO) {
                        opus_int16 pcm[960];
                        int frame_samples = eng->is_legacy_cpu ? 320 : 960;
                        int s = opus_decode(eng->dec, pkt->data, (int)pkt->len, pcm, frame_samples, 0);
                        if (s > 0) {
                            for (int i = 0; i < s; i++) {
                                LONG w = InterlockedAdd(&eng->rb_write, 0);
                                LONG next_w = (w + 1) % eng->audio_rb_size;
                                if (next_w != InterlockedAdd(&eng->rb_read, 0)) {
                                    eng->audio_rb[w] = pcm[i] / 32768.0f;
                                    MemoryBarrier();
                                    InterlockedExchange(&eng->rb_write, next_w);
                                }
                            }
                        }
                        S_spisok_off(eng, c->rx_pool_idx);
                    }
                    else {
                        // Для всех остальных каналов (TEXT, SYSTEM, MEDIA) – распаковка и вызов коллбэка
                        if (eng->on_message) {
                            if (c->text_orig_len == 0xFFFFFFFF) {
                                // Несжатые данные
                                eng->on_message(t, pkt->data, pkt->len, c->text_orig_len);
                            } else {
                                uint8_t* o_buf = (uint8_t*)malloc(c->text_orig_len + 1);
                                if (o_buf) {
                                    uLongf u_len = c->text_orig_len;
                                    if (uncompress(o_buf, &u_len, pkt->data, pkt->len) == Z_OK) {
                                        eng->on_message(t, o_buf, (uint32_t)u_len, c->text_orig_len);
                                    }
                                    free(o_buf);
                                }
                            }
                        }
                        S_spisok_off(eng, c->rx_pool_idx);
                    }
                    c->reading_payload = false;
                }
            } else {
                if (wolfSSL_get_error(c->ssl, n) == WOLFSSL_ERROR_WANT_READ)
                    return;
                S_spisok_off(eng, c->rx_pool_idx);
                S_d(eng, t);
                return;
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
                S_spisok_off(eng, p_idx);
                EnterCriticalSection(&c->tx_lock);
                c->tx_tail = (c->tx_tail + 1) % 64;
                LeaveCriticalSection(&c->tx_lock);
            }
        } else {
            if (wolfSSL_get_error(c->ssl, n) == WOLFSSL_ERROR_WANT_WRITE) return;
            S_d(eng, t); return;
        }
    }
}

DWORD WINAPI ZC_Worker(LPVOID p) {
    zc_engine_t* eng = (zc_engine_t*)p;

    while (eng->running) {
        // 1. Дренаж аудио-очереди из подсистемы записи звука
        LONG ar = InterlockedAdd(&eng->audio_tx_read, 0);
        LONG aw = InterlockedAdd(&eng->audio_tx_write, 0);
        while (ar != aw) {
            ZC_Send(eng, SOCK_AUDIO, eng->audio_tx_queue[ar].data, eng->audio_tx_queue[ar].len);
            ar = (ar + 1) % MAX_AUDIO_PKTS;
            InterlockedExchange(&eng->audio_tx_read, ar);
        }

        // 2. Логика автоматических пингов (раз в 30 секунд)
        uint64_t now = GetTickCount64();
        if (now - eng->last_app_ping_time > 30000) {
            for (int i = 0; i < SOCK_MAX; i++) {
                if (eng->conns[i].state == CONN_STATE_CONNECTED) {
                    uint32_t ping_hdr[2] = { htonl(4), htonl(0xFFFFFFFF) };
                    uint32_t ping_body = 0xDEADC0DE;
                    int p_idx = S_spisok(eng);
                    if (p_idx != -1) {
                        memcpy(eng->pkt_pool[p_idx].data, ping_hdr, 8);
                        memcpy(eng->pkt_pool[p_idx].data + 8, &ping_body, 4);
                        eng->pkt_pool[p_idx].len = 12;
                        EnterCriticalSection(&eng->conns[i].tx_lock);
                        uint32_t next = (eng->conns[i].tx_head + 1) % 64;
                        if (next != eng->conns[i].tx_tail) {
                            eng->conns[i].tx_pool_indexes[eng->conns[i].tx_head] = p_idx;
                            eng->conns[i].tx_head = next;
                        } else S_spisok_off(eng, p_idx);
                        LeaveCriticalSection(&eng->conns[i].tx_lock);
                    }
                }
            }
            eng->last_app_ping_time = now;
        }

        // 3. Подготовка масок для select()
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds); FD_ZERO(&write_fds);
        SOCKET max_s = 0; 

        // Дисковая подсистема удалена
		LONG current_disk_depth = 0;
		bool disk_overloaded = false;

        bool global_disconnected = true;

        for (int i = 0; i < SOCK_MAX; i++) {
            zc_connection_t* c = &eng->conns[i];
            if (c->state != CONN_STATE_DISCONNECTED) global_disconnected = false;

            // Авто-подключение дескрипторов
            if (c->state == CONN_STATE_DISCONNECTED && now >= c->next_retry_time) {
                struct addrinfo *res = NULL;
                if (getaddrinfo(SERVER_IP, SERVER_PORT, NULL, &res) == 0 && res != NULL) {
                    c->fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (c->fd != INVALID_SOCKET) {
                        u_long m = 1; ioctlsocket(c->fd, FIONBIO, &m);
                        int keepalive = 1;
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

            if (c->state == CONN_STATE_CONNECTING_NET) {
                FD_SET(c->fd, &write_fds);
            }
            else if (c->state == CONN_STATE_TLS_HANDSHAKE) { 
                FD_SET(c->fd, &read_fds); 
                FD_SET(c->fd, &write_fds); 
            }
            else if (c->state == CONN_STATE_CONNECTED) {
                // Контроль перегрузки диска оставляем (чтобы не забить ОЗУ), но от аудио больше не зависим
                if (!(i == SOCK_MEDIA && disk_overloaded)) {
                    FD_SET(c->fd, &read_fds);
                }
                
                bool has_tx = false;
                EnterCriticalSection(&c->tx_lock);
                if (c->tx_head != c->tx_tail) has_tx = true;
                LeaveCriticalSection(&c->tx_lock);

                // ИЗМЕНЕНО: Убрано условие && !(i == SOCK_MEDIA && audio_pending).
                // Теперь медиа-канал отправляет данные ВСЕГДА, когда есть что отправлять.
                if (has_tx) {
                    FD_SET(c->fd, &write_fds);
                }
            }
        }

        // Выбор адаптивного таймаута сна
        struct timeval tv;
        if (global_disconnected) {
            tv.tv_sec = 0; tv.tv_usec = 250000;
        } else if (eng->conns[SOCK_AUDIO].state == CONN_STATE_CONNECTED || current_disk_depth > 0) {
            tv.tv_sec = 0; tv.tv_usec = 10000; // Минимальный таймаут при активном звонке или дисковых операциях
        } else {
            tv.tv_sec = 0; tv.tv_usec = 50000;
        }

        // Мультиплексирование
        if (select((int)max_s + 1, &read_fds, &write_fds, NULL, &tv) > 0 && eng->running) {
            for (int i = 0; i < SOCK_MAX; i++) {
                zc_connection_t* c = &eng->conns[i];
                if (c->fd == INVALID_SOCKET) continue;

                if (c->state == CONN_STATE_CONNECTING_NET && FD_ISSET(c->fd, &write_fds)) {
                    int err = 0; int len = sizeof(err); getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
                    if (err == 0) {
                        c->ssl = wolfSSL_new(eng->ctx_tls);
                        wolfSSL_set_fd(c->ssl, (int)c->fd);
                        c->state = CONN_STATE_TLS_HANDSHAKE;
                    } else S_d(eng, (SocketType)i);
                }
                else if (c->state == CONN_STATE_TLS_HANDSHAKE && (FD_ISSET(c->fd, &read_fds) || FD_ISSET(c->fd, &write_fds))) {
                    int ret = wolfSSL_connect(c->ssl);
                    if (ret == WOLFSSL_SUCCESS) { 
                        c->state = CONN_STATE_CONNECTED; 
                        c->backoff_ms = 1000; 
                    }
                    else if (wolfSSL_get_error(c->ssl, ret) != WOLFSSL_ERROR_WANT_READ && wolfSSL_get_error(c->ssl, ret) != WOLFSSL_ERROR_WANT_WRITE) {
                        S_d(eng, (SocketType)i);
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

void ZC_Handler(SocketType k, uint8_t* d, uint32_t l, uint32_t ol){

	if(k == SOCK_TEXT){
		
	}
	
	else if(k == SOCK_SYSTEM){
		
	}
	else if(k==SOCK_MEDIA){
		
	}
	
}

void S_d(zc_engine_t* eng, SocketType t) {
    zc_connection_t* c = &eng->conns[t];
    c->state = CONN_STATE_DISCONNECTED;
    if (c->ssl) { wolfSSL_free(c->ssl); c->ssl = NULL; }
    if (c->fd != INVALID_SOCKET) { closesocket(c->fd); c->fd = INVALID_SOCKET; }
    if (c->reading_payload) { S_spisok_off(eng, c->rx_pool_idx); c->reading_payload = false; }
    c->header_bytes_read = 0; c->payload_bytes_read = 0;

    EnterCriticalSection(&c->tx_lock);
    while (c->tx_tail != c->tx_head) {
        S_spisok_off(eng, c->tx_pool_indexes[c->tx_tail]);
        c->tx_tail = (c->tx_tail + 1) % 64;
    }
    LeaveCriticalSection(&c->tx_lock);
    
    c->next_retry_time = GetTickCount64() + c->backoff_ms;
    c->backoff_ms = min(c->backoff_ms * 2, 30000);
}


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

zc_engine_t* ZC_CreateEngine(bool enable_legacy_mode, void (*on_message)(SocketType channel, uint8_t* data, uint32_t len, uint32_t orig_len)) {
    srand((unsigned int)GetTickCount64());
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return NULL;
    wolfSSL_Init();

    zc_engine_t* eng = (zc_engine_t*)calloc(1, sizeof(zc_engine_t));
    if (!eng) return NULL;

    eng->is_legacy_cpu = enable_legacy_mode;
    eng->audio_sample_rate = eng->is_legacy_cpu ? AUDIO_RATE_LQ : AUDIO_RATE_HQ;
    eng->audio_rb_size = eng->audio_sample_rate * 4;
    eng->last_app_ping_time = GetTickCount64();
    eng->on_message = on_message;  

    CreateDirectoryRecursive("C:/Downloads/Zipcord");

    InitializeCriticalSection(&eng->pool_lock);

#ifdef WOLFSSL_TLS13
    WOLFSSL_METHOD* method = wolfTLSv1_3_client_method();
#else
    WOLFSSL_METHOD* method = wolfTLSv1_2_client_method();
#endif
    eng->ctx_tls = wolfSSL_CTX_new(method);
    if (!eng->ctx_tls) {
        free(eng);
        return NULL;
    }

    wolfSSL_CTX_set_cipher_list(eng->ctx_tls,
        "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    wolfSSL_CTX_set_verify(eng->ctx_tls, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_set_timeout(eng->ctx_tls, 30);

#ifdef WOLFSSL_CALLBACKS
    wolfSSL_SetIOSend(eng->ctx_tls, IO_Send);
    wolfSSL_SetIORecv(eng->ctx_tls, IO_recv);
#endif

    eng->audio_rb = (float*)calloc(eng->audio_rb_size, sizeof(float));
    eng->enc = opus_encoder_create(eng->audio_sample_rate, 1, OPUS_APPLICATION_VOIP, NULL);
    eng->dec = opus_decoder_create(eng->audio_sample_rate, 1, NULL);

    if (!eng->audio_rb || !eng->enc || !eng->dec) {
        if (eng->enc) opus_encoder_destroy(eng->enc);
        if (eng->dec) opus_decoder_destroy(eng->dec);
        free(eng->audio_rb);
        wolfSSL_CTX_free(eng->ctx_tls);
        free(eng);
        return NULL;
    }

    if (eng->is_legacy_cpu) {
        opus_encoder_ctl(eng->enc, OPUS_SET_COMPLEXITY(1));
        opus_encoder_ctl(eng->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
        opus_encoder_ctl(eng->enc, OPUS_SET_BITRATE(12000));
    }

    ma_device_config cfg = ma_device_config_init(ma_device_type_duplex);
    cfg.capture.format = ma_format_s16;
    cfg.sampleRate = eng->audio_sample_rate;
    cfg.dataCallback = ZC_AudioCallback;
    cfg.pUserData = eng;
    if (ma_device_init(NULL, &cfg, &eng->audio_dev) == MA_SUCCESS) {
        eng->audio_dev_init = true;
        ma_device_start(&eng->audio_dev);
    }

    for (int i = 0; i < SOCK_MAX; i++) {
        InitializeCriticalSection(&eng->conns[i].tx_lock);
        eng->conns[i].fd = INVALID_SOCKET;
        eng->conns[i].backoff_ms = 1000;
        eng->conns[i].expected_header_len = (i == SOCK_TEXT || i == SOCK_SYSTEM || i == SOCK_MEDIA) ? 8 : 4;
    }

    eng->running = true;
    eng->worker_thread = CreateThread(NULL, 0, ZC_Worker, eng, 0, NULL);

    return eng;
}

void ZC_DestroyEngine(zc_engine_t* eng) {
    if (!eng) return;
    eng->running = false;

    for (int i = 0; i < SOCK_MAX; i++) {
        if (eng->conns[i].fd != INVALID_SOCKET) {
            closesocket(eng->conns[i].fd);
            eng->conns[i].fd = INVALID_SOCKET;
        }
    }

    if (eng->worker_thread) {
        WaitForSingleObject(eng->worker_thread, INFINITE);
        CloseHandle(eng->worker_thread);
    }

    if (eng->audio_dev_init) {
        ma_device_uninit(&eng->audio_dev);
    }
    opus_encoder_destroy(eng->enc);
    opus_decoder_destroy(eng->dec);

    for (int i = 0; i < SOCK_MAX; i++) {
        S_d(eng, (SocketType)i);
        DeleteCriticalSection(&eng->conns[i].tx_lock);
    }

    DeleteCriticalSection(&eng->pool_lock);
    wolfSSL_CTX_free(eng->ctx_tls);
    free(eng->audio_rb);
    free(eng);

    wolfSSL_Cleanup();
    WSACleanup();
}

void ZC_Reconnect(zc_engine_t* eng, int channel) {
    if (!eng || channel < 0 || channel >= SOCK_MAX) return;
    zc_connection_t* c = &eng->conns[channel];
    S_d(eng, channel);
    c->backoff_ms = 1000;
    c->next_retry_time = 0; 
}

static bool f = false;
static void zc_chat(short x, short y, chat* c){
    igSetNextWindowSize((ImVec2){x*0.65, y}, NULL);
    igSetNextWindowPos((ImVec2){x*0.35, 0}, NULL);
    igBegin("c", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus);
    
    ImGuiStyle* style = igGetStyle();
    float l_h = igGetTextLineHeight();
    float i_w = x * 0.386f;    
    ImVec2 t_s = igCalcTextSizeEx(c->buf, NULL, false, i_w - (style->FramePadding.x * 2.0f) - style->ScrollbarSize); 
 
    int len = strlen(c->buf);
    if (len > 0 && c->buf[len - 1] == '\n') {
        t_s.y += l_h;
    }
    
    float min_h = l_h + (style->FramePadding.y * 2.0f);        // 1 строка
    float max_h = (l_h * 8) + (style->FramePadding.y * 2.0f);  // 8 строк
    
    float i_h = t_s.y + (style->FramePadding.y * 2.0f);
    if (i_h < min_h) i_h = min_h;
    if (i_h > max_h) i_h = max_h;
    
    float p_h = i_h + y * 0.02f;
    
    igSetCursorPos((ImVec2){x*0.1, y*0.96 - p_h});
    igDummy(ImVec2(0, 0));
    
    igPushStyleVarImVec2(ImGuiStyleVar_WindowPadding, (ImVec2){x*0.07, y*0.01});
    igPushStyleColorImVec4(ImGuiCol_ChildBg, (ImVec4){0.125f, 0.133f, 0.145f, 1.0f});
    igSetNextWindowPos((ImVec2){x*0.45, y*0.96 - p_h}, NULL);
    igSetNextWindowSize(ImVec2(x*0.45, p_h), NULL);
    
    if(igBeginChild("##p", ImVec2(x*0.45, p_h), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar)){
        igSetNextItemWidth(x*0.4);
        float _y = (p_h - i_h) * 0.5f;
        igSetCursorPos((ImVec2){20, _y});
		if(f){igSetKeyboardFocusHere(); f = false;}
        if (igInputTextMultilineEx("##i", c->buf, 4096, ImVec2(i_w, i_h), ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_WordWrap, NULL, NULL)){
            c->buf[0] = '\0';
			f = true;
        }
    }
    igEndChild();
    igPopStyleVarEx(1);
    igPopStyleColor();
    igEnd();
}



static void zc_voice(short x, short y){
	igSetNextWindowSize((ImVec2){x*0.35, y*0.7}, NULL);
	igSetNextWindowPos((ImVec2){0, 0}, NULL);
	igBegin("v", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus);



	
	igEnd();
}

static void zc_sw(short x, short y){
	igSetNextWindowSize((ImVec2){x*0.35, y*0.3}, NULL);
	igSetNextWindowPos((ImVec2){0, y*0.7}, NULL);
	igBegin("s", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus);

	

	
	igEnd();
}
// Требуется глобальный или доступный ID3D11Device* g_pd3dDevice
bool LoadTextureFromFile(const char* filename, ID3D11ShaderResourceView** out_srv, int* out_width, int* out_height) 
{
    int image_width = 0, image_height = 0;
    // Загрузка RGBA данных (4 канала)
    unsigned char* image_data = stbi_load(filename, &image_width, &image_height, NULL, 4);
    if (!image_data) return false;

    // Настройка дескриптора текстуры
    D3D11_TEXTURE2D_DESC desc = {
        .Width = image_width,
        .Height = image_height,
        .MipLevels = 1,
        .ArraySize = 1,
        .Format = DXGI_FORMAT_R8G8B8A8_UNORM,
        .SampleDesc.Count = 1,
        .Usage = D3D11_USAGE_DEFAULT,
        .BindFlags = D3D11_BIND_SHADER_RESOURCE
    };

    D3D11_SUBRESOURCE_DATA subResource = {
        .pSysMem = image_data,
        .SysMemPitch = image_width * 4
    };

    ID3D11Texture2D* pTexture = NULL;
    g_pd3dDevice->lpVtbl->CreateTexture2D(g_pd3dDevice, &desc, &subResource, &pTexture);
    stbi_image_free(image_data);

    if (!pTexture) return false;

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {
        .Format = desc.Format,
        .ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D,
        .Texture2D.MipLevels = desc.MipLevels
    };
    HRESULT hr = g_pd3dDevice->lpVtbl->CreateShaderResourceView(g_pd3dDevice, (ID3D11Resource*)pTexture, &srvDesc, out_srv);
    pTexture->lpVtbl->Release(pTexture); 

    if (FAILED(hr)) return false;

    *out_width = image_width;
    *out_height = image_height;
    return true;
}

static void zc_login(short x, short y, ID3D11ShaderResourceView* my_srv){    
	static char l[32];
	static char p[32];
	igSetNextWindowSize(ImVec2(x*0.28, y), NULL);
	igSetNextWindowPos(ImVec2(x*0.36, 0), NULL);
	igBegin("##l", &gm.login, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_Modal);
	igImage((ImTextureRef){ ._TexID = (ImTextureID)my_srv, ._TexData = NULL }, ImVec2(x*0.273, x*0.049));

	ImVec2 aa = igCalcTextSize("Авторизация");
	igSetWindowFontScale(2.0f);
	igSetCursorPos(ImVec2(x*0.5 - (aa.x *0.5), x*0.06));
	igText("Авторизация");
	igSetWindowFontScale(1.0f);

	igPushItemWidth(x*0.271);
	// igSetCursorPosX(x*0.37);
	igText("Логин:");
	igInputText("##ll", &l, 32, ImGuiInputTextFlags_None);

	igSpacing();

	igText("Пароль:");
	igInputText("##lp", &p, 32, ImGuiInputTextFlags_Password);
	igPopItemWidth();
	igSpacing(); igSpacing();

	igSetCursorPos(ImVec2(x*0.46, y*0.86));
	if(igButtonEx("Войти", ImVec2(x*0.08, y*0.03))){
		// l = логин пользователя, p = пароль пользователя сначала проверить в бд, потом на сервере
		
	}

	igSetCursorPosX(x*0.37);
	igTextDisabled("*ваш аккаунт только для вас!");
		
	igEnd();
}

static void zc_register(short x, short y){ // db надо сюда
	igBegin("##r", &gm.reg, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_Modal);

	
	
	igEnd();
}



/*

смена имени
смена пароля
смена аватарки
просмотр текущей аватарки
просмотр айди
калькуляторный режим
служба поддержки
замена sni 
поменять цвета интерфейса(файлом или кнопками)
предустановленные темы
отправлять ли в чат уведомление о заходе в войс чат
синхронизировать данные


*/
static void zc_settings(short x, short y){ // db надо сюда
	igBegin("#s", &gm.set, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

	
	
	igEnd();
}

int bd_init(sqlite3* db, STMTS* stmts){
	int rc;
	sqlite3_exec(db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA synchronous = 0;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA temp_store = MEMORY;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA ignore_check_constraints = 1;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_keys = OFF;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA optimize;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA wal_autocheckpoint = 400;", NULL, NULL, NULL);
	// sqlite3_exec(db, "PRAGMA wal_checkpoint(PASSIVE);", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA mmap_size = 134217728;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA page_size = 4096;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA cache_size = 2000;", NULL, NULL, NULL);


	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS ME(NAME TEXT, PASSW BLOB, AVA BLOB, UID INTEGER, VER BOOLEAN, OBN TEXT);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS USERS(NAME TEXT, UID INTEGER, AVA BLOB, VER BOOLEAN, OBN TEXT);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS CHATS(NAME TEXT, AVA BLOB, CID INTEGER, MMBRS TEXT, LID INTEGER, OBN TEXT);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS MSGS(MID INTEGER, UID INTEGER, CID INTEGER, TEXT BLOB, MEDIA BLOB, TYPE INTEGER, TIME TEXT);", NULL, NULL, NULL);

	sqlite3_exec(db, "CREATE UNIQUE INDEX IF NOT EXISTS idx_msgs_cid ON MSGS(CID);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uid ON USERS(UID);", NULL, NULL, NULL);
	sqlite3_exec(db, "CREATE UNIQUE INDEX IF NOT EXISTS idx_chats_cid ON CHATS(CID);", NULL, NULL, NULL);


	  // Сохранение ME (с заменой при конфликте)
    rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO ME (NAME, PASSW, AVA, UID, VER, OBN) "
        "VALUES (?, ?, ?, ?, ?, ?);",
        -1, &stmts->save_me, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Сохранение пользователя
    rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO USERS (NAME, UID, AVA, VER, OBN) "
        "VALUES (?, ?, ?, ?, ?);",
        -1, &stmts->save_user, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Сохранение чата
    rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO CHATS (NAME, AVA, CID, MMBRS, LID, OBN) "
        "VALUES (?, ?, ?, ?, ?, ?);",
        -1, &stmts->save_chat, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Сохранение сообщения
    rc = sqlite3_prepare_v2(db,  "INSERT OR REPLACE INTO MSGS (MID, UID, CID, TEXT, MEDIA, TYPE, TIME) VALUES (?, ?, ?, ?, ?, ?, ?);", -1, &stmts->save_msg, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // === ИЗВЛЕЧЕНИЕ ===
    
    // Получить ME (текущего пользователя)
    rc = sqlite3_prepare_v2(db,
        "SELECT NAME, PASSW, AVA, UID, VER, OBN FROM ME LIMIT 1;", -1, &stmts->get_me, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Получить пользователя по UID
    rc = sqlite3_prepare_v2(db,
        "SELECT NAME, AVA, VER, OBN FROM USERS WHERE UID = ?;",
        -1, &stmts->get_user_by_uid, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Получить пользователя по имени
    rc = sqlite3_prepare_v2(db,
        "SELECT UID, NAME, AVA, VER, OBN FROM USERS WHERE NAME = ?;",
        -1, &stmts->get_user_by_name, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Получить чат по CID
    rc = sqlite3_prepare_v2(db,
        "SELECT NAME, AVA, MMBRS, LID, OBN FROM CHATS WHERE CID = ?;",
        -1, &stmts->get_chat_by_cid, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Получить сообщения чата (по CID, сортировка по времени)
    rc = sqlite3_prepare_v2(db,
        "SELECT MID, UID, TEXT, MEDIA, TYPE, TIME FROM MSGS "
        "WHERE CID = ? ORDER BY TIME ASC;",
        -1, &stmts->get_msgs_by_cid, NULL);
    if (rc != SQLITE_OK) return rc;
    // === ОБНОВЛЕНИЕ ===
    
    // Обновить OBN для ME
    rc = sqlite3_prepare_v2(db,
        "UPDATE ME SET OBN = ? WHERE UID = ?;",
        -1, &stmts->update_me, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Обновить пользователя
    rc = sqlite3_prepare_v2(db,
        "UPDATE USERS SET NAME = ?, AVA = ?, VER = ?, OBN = ? WHERE UID = ?;",
        -1, &stmts->update_user, NULL);
    if (rc != SQLITE_OK) return rc;
    
    // Обновить чат
    rc = sqlite3_prepare_v2(db,
        "UPDATE CHATS SET NAME = ?, AVA = ?, MMBRS = ?, OBN = ? WHERE CID = ?;",
        -1, &stmts->update_chat, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "DELETE FROM MSGS WHERE CID = ?;",
        -1, &stmts->delete_msgs_by_cid, NULL);
    if (rc != SQLITE_OK) return rc;
}

void finalize_all_statements(STMTS* stmts) {
    if (stmts->save_me) sqlite3_finalize(stmts->save_me);
    if (stmts->save_user) sqlite3_finalize(stmts->save_user);
    if (stmts->save_chat) sqlite3_finalize(stmts->save_chat);
    if (stmts->save_msg) sqlite3_finalize(stmts->save_msg);
    if (stmts->get_me) sqlite3_finalize(stmts->get_me);
    if (stmts->get_user_by_uid) sqlite3_finalize(stmts->get_user_by_uid);
    if (stmts->get_user_by_name) sqlite3_finalize(stmts->get_user_by_name);
    if (stmts->get_chat_by_cid) sqlite3_finalize(stmts->get_chat_by_cid);
    if (stmts->get_msgs_by_cid) sqlite3_finalize(stmts->get_msgs_by_cid);
    if (stmts->update_me) sqlite3_finalize(stmts->update_me);
    if (stmts->update_user) sqlite3_finalize(stmts->update_user);
    if (stmts->update_chat) sqlite3_finalize(stmts->update_chat);
    if (stmts->delete_msgs_by_cid) sqlite3_finalize(stmts->delete_msgs_by_cid);
}




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
    io->ConfigFlags &= ~ImGuiConfigFlags_NavEnableKeyboard;

    int font_data_size = (int)((intptr_t)_binary_museo_ttf_end - (intptr_t)_binary_museo_ttf_start);
    ImFontAtlas* atlas = igGetIO()->Fonts;
    const ImWchar* ranges = ImFontAtlas_GetGlyphRangesCyrillic(atlas);
    ImFontAtlas_AddFontFromMemoryTTF(atlas, _binary_museo_ttf_start, font_data_size, 24.0f, NULL, ranges);

    igStyleColorsDark(NULL);
    cImGui_ImplWin32_Init(hwnd);
    cImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = { 0.45f, 0.55f, 0.60f, 1.00f };

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        WSACleanup();
        return -1;
    }

    zc_engine_t* zc = ZC_CreateEngine(false, ZC_Handler); // false = потужни ПК
    if (!zc) {
        wolfSSL_Cleanup();
        WSACleanup();
        cImGui_ImplDX11_Shutdown();
        cImGui_ImplWin32_Shutdown();
        igDestroyContext(NULL);
        CleanupDeviceD3D();
        DestroyWindow(hwnd);
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 12;
    }

    chat* chat_schas = malloc(sizeof(chat));
    user* usrs;
    chat* chats;
    uint16_t g_cid;
	gm.login = true;
	// unsigned char* a;
	// uint16_t aa;
	// if(C_lreestr(a, aa)){
	// 	if(S_bdu(a, aa)){
	// 		gm.login = true;
	// 		gm.reg = false;
	// 		gm.set = false;
	// 		gm.con = false;
	// 	}
	// }
	ID3D11ShaderResourceView* aaa;
	int w_a, h_a;
	LoadTextureFromFile("zipcord2.png", &aaa, &w_a, &h_a);
    bool done = false;
    while (!done) {
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
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) done = true;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (done) break;

        cImGui_ImplDX11_NewFrame();
        cImGui_ImplWin32_NewFrame();
        igNewFrame();

        float x = io->DisplaySize.x;
        float y = io->DisplaySize.y;

		if(!gm.login && !gm.reg){
			zc_chat(x, y, chat_schas);
			zc_voice(x, y);
			zc_sw(x, y);
	    }
		if(gm.set){zc_settings(x, y);}
		if(gm.reg){zc_register(x, y);}
		if(gm.login){zc_login(x, y, aaa);}
        igRender();

        g_pd3dDeviceContext->lpVtbl->OMSetRenderTargets(g_pd3dDeviceContext, 1, &g_mainRenderTargetView, NULL);
        float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->lpVtbl->ClearRenderTargetView(g_pd3dDeviceContext, g_mainRenderTargetView, clear_color_with_alpha);

        cImGui_ImplDX11_RenderDrawData(igGetDrawData());

        g_pSwapChain->lpVtbl->Present(g_pSwapChain, 1, 0);
        MsgWaitForMultipleObjects(0, NULL, FALSE, INFINITE, QS_ALLINPUT);
    }

    ZC_DestroyEngine(zc);
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
    // createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG; 
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
