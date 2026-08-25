#define MINIAUDIO_IMPLEMENTATION
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <wincrypt.h>
#include <winreg.h>
#include <process.h>
#include <wchar.h>
#include <locale.h>
#include <shellapi.h>
#include <pthread.h>
#include <commdlg.h>
#include <initguid.h>
#include <shlobj.h>
#include <wchar.h>
#include <knownfolders.h>

typedef void* wolfSSL_custom_ext_add_cb;
typedef void* wolfSSL_custom_ext_free_cb;
typedef void* wolfSSL_custom_ext_parse_cb;

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/asn.h"

// #define MINIAUDIO_IMPLEMENTATION
// #include "curl/curl.h"

#include "zlib/zlib.h"
#include "zlib/zconf.h"

#include "opus/opus.h"
#include "other/miniaudio.h"

#include "sqlite3.h"

#include "other/uthash.h"

#define COBJMACROS
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
#include "other/jsmn.h"

// #include "wrslog.h"

#include "zipcord2.h"

#define STB_IMAGE_IMPLEMENTATION
#include "other/stb_image.h"

#include "icons.h"
#include "vector.h"

#include "main.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#define NICK_LEN 32
const char* BLOB_PATH = "C:\\Klei\\DoNotOpen";
const wchar_t* WCHART_PATH = L"C:\\Klei\\DoNotOpen";

#define MAX_PATH 1024
#define ITID ImTextureRef
#define ImVec2(x, y) ((ImVec2){x, y})
#define imu32(r, g, b, a) ((ImU32){r, g, b, a})
#define ImVec4(x, y, a, b) ((ImVec4){x, y, a, b})
#define IT(x) ((ImTextureRef){ ._TexID = (ImTextureID)x, ._TexData = NULL })
#define YA_LINK "https://disk.yandex.ru/d/3NUbG0QlimvqDA"

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
typedef enum { CB_TEXT, CB_NONE, CB_IMAGE, CB_FILE } CBType;
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
    sqlite3_stmt *get_chat_by_name;
    sqlite3_stmt *get_msgs_by_cid;
    sqlite3_stmt *get_msgs_by_name;
	
    sqlite3_stmt *delete_msg_by_mid;
    sqlite3_stmt *delete_msgs_by_cid;
    sqlite3_stmt *delete_user_by_uid;	
} STMTS;
STMTS stmts;

typedef enum {MT_TEXT, MT_PHOTO, MT_DOC, MT_VIDEO} MT_T;

typedef struct {
	uint32_t mid;        // айди сообщения
	uint32_t cid;        // айди чата
	uint32_t uid;        // айди юзера
	bool dost;           // доставлено ли сообщение
	char time[16];       // время с датой
	union{               // тут может быть только одна из трех строк, шоб меньше памяти жрало
		char text[4096]; // текст до 4кб 
		struct{
			ITID* img_ptr;// указатель на фото
			double w, h;
		} image;
	} ctnt;
	MT_T type;           // тип сообщения, чтобы правильно и быстро извлекать содержимое 
} msg;

typedef struct {
	uint32_t cid;        // айди чата
	char name[NICK_LEN];       // название чата
	ITID* ava_ptr;       // указатель на аватарку чата
	uint32_t* usrs;      // айди юзеров, кроме своего vec_free()
	uint32_t uc;         // колво юзеров
	size_t ns;         // кол-во непрочитанных
	char buf[4096];      // буффер для ввода сообщения (шоб сохранялось между чатами)
	uint32_t lmid;	     // айди последнего сообщения
	float offset;
	bool ls;             // это лс?
	UT_hash_handle hh;   // для хэштаблицы
	char obn[16];        // obn
} chat;

typedef struct {
	char name[NICK_LEN];       // имя юзера
	uint32_t uid;        // айди юзера
	bool ver;            // важный бумажный
	ITID* ava_ptr;       //	указатель на аватарку
	UT_hash_handle hh;   // для хэштаблицы
	char obn[16];        // obn
} user; 

typedef enum { SOCK_TEXT, SOCK_SYSTEM, SOCK_MEDIA, SOCK_AUDIO, SOCK_MAX } SocketType;

typedef struct {
	char name[NICK_LEN];       // имя
	uint32_t uid;        // айди юзера
	unsigned char* hash; // хэш пароля
	float r;             // углы
	ITID* ava_ptr;       // указатель на аватарку
	bool ver;            // важный бумажный
	char obn[16];        // дата и время синхронизации с сервером
	bool reg;            // в реге?
	bool set;            // в настройках?
	bool con;            // в консоли?
	STMTS stmts;         // запросы в бд
	sqlite3* db;         // сама бд
	int w,h;             // размеры фото
	char* bdu_uuid;      // uuid
} me;

me gm = {0};

void zcbeui_adduser(user* u, user* us){ // добавить юзера в хэштаблицу юзеров чата для быстрого поиска и использования аватарок
	HASH_ADD(hh, us, uid, sizeof(size_t), u);
}

user* zcbeui_finduser(user* u, user* us, size_t* uid){ // найти юзера в эхтаблице по айди
	HASH_FIND(hh, us, uid, sizeof(size_t), u);
	return u;
}

// надо сделать удаление юзеров из хэштаблицы

unsigned char* V_gffp(){ // получить байты файла по пути (аналог V_liff он для файлов)
	
}

char* str_replace(const char* orig, const char* rep, const char* with) {
    if (!orig || !rep) return NULL;
    if (!with) with = "";
    
    size_t len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    size_t len_with = strlen(with);
    
    // Считаем количество вхождений
    int count = 0;
    const char* ins = orig;
    while ((ins = strstr(ins, rep)) != NULL) {
        count++;
        ins += len_rep;
    }
    
    // Безопасный расчет новой длины (без ухода size_t в минус)
    size_t new_len = strlen(orig);
    if (len_with >= len_rep) {
        new_len += (len_with - len_rep) * (size_t)count;
    } else {
        new_len -= (len_rep - len_with) * (size_t)count;
    }
    
    char* result = malloc(new_len + 1);
    if (!result) return NULL;
    
    char* tmp = result;
    const char* p = orig;
    while (count--) {
        ins = strstr(p, rep);
        size_t len_front = ins - p;
        
        // Копируем текст до вхождения тега
        memcpy(tmp, p, len_front);
        tmp += len_front;
        
        // Копируем заменяющую строку
        strcpy(tmp, with);
        tmp += len_with;
        
        p = ins + len_rep;
    }
    // Копируем оставшуюся часть строки
    strcpy(tmp, p);
    
    return result;
}

char* V_lj(const char* filepath, const char* server, const char* uuid, uint32_t uid) {
    if (!filepath || !server || !uuid) return NULL;

    FILE* file = fopen(filepath, "rb");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (length <= 0) {
        fclose(file);
        return NULL;
    }

    char* template_buf = (char*)malloc(length + 1);
    if (!template_buf) { 
        fclose(file); 
        return NULL; 
    }

    size_t read_bytes = fread(template_buf, 1, length, file);
    template_buf[read_bytes] = '\0';
    fclose(file);

    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%u", uid);

    // Шаг 1: замена SERVER
    char* s1 = str_replace(template_buf, "-=SERVER=-", server);
    char* base1 = s1 ? s1 : template_buf;

    // Шаг 2: замена UUID (работаем с тем, что получилось на шаге 1)
    char* s2 = str_replace(base1, "-=UUID=-", uuid);
    char* base2 = s2 ? s2 : base1;

    // Шаг 3: замена UID
    char* result_json = str_replace(base2, "-=UID=-", uid_str);

    // Корректная очистка временной памяти
    if (s1) free(s1);
    if (s2) free(s2);
    free(template_buf);

    return result_json; // Внимание: вызывающий код должен сделать free(result_json)
}

wchar_t* V_c2w(const char* a) {
    if (!a) return NULL;
    
    int size = MultiByteToWideChar(CP_UTF8, 0, a, -1, NULL, 0);
    if (size <= 0) return NULL;
    
    wchar_t* aa = (wchar_t*)malloc(size * sizeof(wchar_t));
    if (!aa) return NULL;
    
    MultiByteToWideChar(CP_UTF8, 0, a, -1, aa, size);
    return aa;
} // free()

wchar_t* V_cibp(const uint32_t a, bool user) {
    // 11 байт под максимальный uint32 (10 знаков + '\0') + 2 байта под "\\u" или "\\c"
    size_t buf_size = strlen(BLOB_PATH) + 13; 
    char* b = (char*)malloc(buf_size);
    if (!b) return NULL;

    if (user) {
        snprintf(b, buf_size, "%s\\u%u", BLOB_PATH, a);
    } else {
        snprintf(b, buf_size, "%s\\c%u", BLOB_PATH, a);
    }

    wchar_t* bb = V_c2w(b);
    free(b); // Исправлено: освобождаем временный clean-text буфер
    return bb;
} // обязательно free()

wchar_t* V_cmc(const uint32_t a, bool image){
	// char* user_profile = getenv("USERPROFILE");
	// printf(user_profile);
	// char* b = malloc(strlen(user_profile)+16); // 1 - \0, 4 - uid/cid
	// if (image){sprintf(b, "%s\\Downloads\\i%u", user_profile, a);}
	// else {sprintf(b, "%s\\Downloads\\d%u", user_profile, a);}
    // free(user_profile);
	// wchar_t* bb = V_c2w(b);
	// return bb;

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) return L"nah";

    PWSTR path = NULL;
    wchar_t* result = NULL;

    hr = SHGetKnownFolderPath(&FOLDERID_Downloads, 0, NULL, &path);
    if (SUCCEEDED(hr)) {
        // Выделяем буфер под: путь + '\\' + 'i'/'d' + 10 знаков uint32 + '\0'
        size_t buf_size = wcslen(path) + 14; 
        result = (wchar_t*)malloc(buf_size * sizeof(wchar_t));
        
        if (result) {
            swprintf(result, buf_size, L"%s\\%c%u", path, image ? L'i' : L'd', a);
        }
        
        // Освобождаем память Windows КЛЮЧЕВОЙ моментом ПОСЛЕ копирования данных
        CoTaskMemFree(path); 
    }

    CoUninitialize();
	
	wprintf(result);
	return result;
} // обязательно free()

unsigned char* V_i2b(void* texture_handle, int* out_width, int* out_height, size_t* out_size) { // изображение в сырые байты
    if (!texture_handle) return NULL;

    ID3D11ShaderResourceView* srv = (ID3D11ShaderResourceView*)texture_handle;
    
    ID3D11Resource* res = NULL;
    ID3D11ShaderResourceView_GetResource(srv, &res);
    
    ID3D11Texture2D* texture = NULL;
    ID3D11Resource_QueryInterface(res, &IID_ID3D11Texture2D, (void**)&texture);
    ID3D11Resource_Release(res);

    D3D11_TEXTURE2D_DESC desc;
    ID3D11Texture2D_GetDesc(texture, &desc);
    *out_width = desc.Width;
    *out_height = desc.Height;

    D3D11_TEXTURE2D_DESC staging_desc = desc;
    staging_desc.Usage = D3D11_USAGE_STAGING;
    staging_desc.BindFlags = 0;
    staging_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    staging_desc.MiscFlags = 0;

    ID3D11Texture2D* staging_tex = NULL;
    ID3D11Device_CreateTexture2D(g_pd3dDevice, &staging_desc, NULL, &staging_tex); 
    ID3D11DeviceContext_CopyResource(g_pd3dDeviceContext, (ID3D11Resource*)staging_tex, (ID3D11Resource*)texture);

    D3D11_MAPPED_SUBRESOURCE mapped;
    HRESULT hr = ID3D11DeviceContext_Map(g_pd3dDeviceContext, (ID3D11Resource*)staging_tex, 0, D3D11_MAP_READ, 0, &mapped);
    
    unsigned char* clean_pixels = NULL;
	size_t total_clean_size;
    if (SUCCEEDED(hr)) {
        int bytes_per_pixel = 4; 
        size_t clean_row_pitch = desc.Width * bytes_per_pixel;
        total_clean_size = clean_row_pitch * desc.Height;

        clean_pixels = (unsigned char*)malloc(total_clean_size);

        if (clean_pixels) {
            unsigned char* src = (unsigned char*)mapped.pData;
            unsigned char* dst = clean_pixels;

            for (UINT y = 0; y < desc.Height; y++) {
                memcpy(dst, src, clean_row_pitch);
                src += mapped.RowPitch; 
                dst += clean_row_pitch; 
            }
        }
        ID3D11DeviceContext_Unmap(g_pd3dDeviceContext, (ID3D11Resource*)staging_tex, 0);
    }


    ID3D11Texture2D_Release(staging_tex);
    ID3D11Texture2D_Release(texture);
	*out_size = total_clean_size;
    return clean_pixels; 
}

// надо на wchar_t  переверсти + stbi_load_from_file сделать, чтобы киррилицу воспринимал
bool V_liff(const wchar_t* filename, ID3D11ShaderResourceView** out_srv, int* out_width, int* out_height) {
    int image_width = 0, image_height = 0;
    
    // 1. Открываем файл с поддержкой Unicode
    FILE* f = _wfopen(filename, L"rb");
    if (!f) {
        return false;
    }

    // 2. Загружаем данные. Функция stbi_load_from_file сама закроет файл 'f'!
    unsigned char* image_data = stbi_load_from_file(f, &image_width, &image_height, NULL, 4);
    if (!image_data) {
        // Файл уже закрыт внутри stbi_load_from_file, fclose(f) вызывать НЕЛЬЗЯ
        return false;
    }

    // 3. Настройка описания текстуры Direct3D11
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

    // 4. Создание текстуры
    ID3D11Texture2D* pTexture = NULL;
    HRESULT hr = g_pd3dDevice->lpVtbl->CreateTexture2D(g_pd3dDevice, &desc, &subResource, &pTexture);
    
    // Данные больше не нужны, освобождаем память
    stbi_image_free(image_data);

    if (FAILED(hr) || !pTexture) {
        return false;
    }

    // 5. Создание Shader Resource View (SRV)
    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {
        .Format = desc.Format,
        .ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D,
        .Texture2D.MipLevels = desc.MipLevels
    };

    hr = g_pd3dDevice->lpVtbl->CreateShaderResourceView(g_pd3dDevice, (ID3D11Resource*)pTexture, &srvDesc, out_srv);
    
    // Освобождаем локальную ссылку на текстуру
    pTexture->lpVtbl->Release(pTexture);

    if (FAILED(hr)) {
        return false;
    }

    // 6. Возвращаем размеры
    *out_width = image_width;
    *out_height = image_height;
    
    return true;
}

bool V_lifm(const unsigned char* data, size_t len, ID3D11ShaderResourceView** out_srv, int* out_width, int* out_height) {

    if (!data || len == 0) return false;

    int image_width = 0, image_height = 0;
    int image_channels = 0;
    
    unsigned char* image_data = stbi_load_from_memory(data, (int)len, &image_width, &image_height, &image_channels, 4);
    if (!image_data) return false;

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


char* V_rf(const char* filepath) {
	printf("v_rf nachalo");
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        printf("Ошибка: не удалось открыть файл %s\n", filepath);
        return NULL;
    }

    // Определяем размер файла
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long length = ftell(file);
    if (length < 0) {
        fclose(file);
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }

    // Выделяем память под размер файла + 1 для '\0'
    char* buffer = (char*)malloc(length + 1);
    if (!buffer) {
        printf("Ошибка: не удалось выделить память\n");
        fclose(file);
        return NULL;
    }

    // Считываем строго не больше, чем размер буфера
    size_t bytes_read = fread(buffer, 1, length, file);
    
    // Гарантируем нуль-терминатор в конце реально прочитанных данных
    buffer[bytes_read] = '\0'; 

    fclose(file);
    return buffer;
}

char* V_b64e(const unsigned char* src_bytes, size_t src_len, size_t* out_str_len) {
    if (!src_bytes || src_len == 0) return NULL;

    DWORD dest_ch_count = 0;
    
    // Флаг CRYPT_STRING_BASE64 гарантирует чистый Base64 без переносов строк (\r\n)
    DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;

    // 1. Первый вызов: узнаем необходимый размер буфера (в символах)
    if (!CryptBinaryToStringA(src_bytes, (DWORD)src_len, flags, NULL, &dest_ch_count)) {
        return NULL;
    }

    // 2. Выделяем память под строку (размер в байтах равен числу символов для ASCII)
    char* b64_str = (char*)malloc(dest_ch_count);
    if (!b64_str) return NULL;

    // 3. Второй вызов: кодируем данные в выделенный буфер
    if (!CryptBinaryToStringA(src_bytes, (DWORD)src_len, flags, b64_str, &dest_ch_count)) {
        free(b64_str);
        return NULL;
    }

    if (out_str_len) {
        *out_str_len = (size_t)dest_ch_count; // Минус завершающий '\0'
    }

    return b64_str;
} //free()

unsigned char* V_b64d(const char* b64_str, size_t* out_bytes_len) {
    if (!b64_str) return NULL;

    DWORD dest_byte_count = 0;
    DWORD skip_chars = 0;
    DWORD out_flags = 0;

    // 1. Первый вызов: узнаем необходимый размер бинарного буфера (в байтах)
    if (!CryptStringToBinaryA(b64_str, 0, CRYPT_STRING_BASE64, NULL, &dest_byte_count, &skip_chars, &out_flags)) {
        return NULL;
    }

    // 2. Выделяем память под сырые байты
    unsigned char* raw_bytes = (unsigned char*)malloc(dest_byte_count);
    if (!raw_bytes) return NULL;

    // 3. Второй вызов: декодируем строку в байты
    if (!CryptStringToBinaryA(b64_str, 0, CRYPT_STRING_BASE64, raw_bytes, &dest_byte_count, &skip_chars, &out_flags)) {
        free(raw_bytes);
        return NULL;
    }

    if (out_bytes_len) {
        *out_bytes_len = (size_t)dest_byte_count;
    }

    return raw_bytes;
} // free()

unsigned char* V_cu2c(chat* c) { // сохранить пользователей чата в бд
    size_t size = vec_size(c->usrs);
    if (!c || !c->usrs || size == 0) {
        unsigned char* empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }

  
    size_t capacity = size * 12; 
    unsigned char* result = malloc(capacity);
    if (!result) return NULL;

    result[0] = '\0'; 
    size_t current_len = 0;

    for (size_t i = 0; i < size; i++) {
        unsigned char temp[6];
        int written = snprintf(temp, sizeof(temp), (i == 0) ? "%u" : "=%u", c->usrs[i]);
        memcpy(result + current_len, temp, written);
        current_len += written;
    }

    result[current_len] = '\0';
    return result;
} // free()

uint32_t* V_luim(char* in, size_t* c){
    size_t count = 1;
    for (const char *p = in; *p != '\0'; p++) {if (*p == '=') { count++; }}

    uint32_t *arr = (uint32_t*)malloc(count * sizeof(uint32_t));
    if (!arr) return NULL;

    size_t idx = 0;
    char *endptr;
    const char *p = in;

    while (idx < count) {
        arr[idx] = (uint32_t)strtoul(p, &endptr, 10);
        idx++;
        if (*endptr == '=') {
            p = endptr + 1; 
        } else {
            break;
        }
    }

    *c = idx; 
    return arr;
} // free()

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


static char* http_get(const char* url) {
    HINTERNET hInternet = InternetOpenA("ZipcordClient/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return NULL;

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE;
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, flags, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return NULL;
    }

    size_t capacity = 2048;
    size_t total_read = 0;
    char* buffer = (char*)malloc(capacity);
    if (!buffer) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    DWORD bytes_read = 0;
    char chunk[512];

    while (InternetReadFile(hConnect, chunk, sizeof(chunk), &bytes_read) && bytes_read > 0) {
        if (total_read + bytes_read + 1 > capacity) {
            capacity *= 2;
            char* new_buf = (char*)realloc(buffer, capacity);
            if (!new_buf) {
                free(buffer);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            buffer = new_buf;
        }
        memcpy(buffer + total_read, chunk, bytes_read);
        total_read += bytes_read;
    }

    buffer[total_read] = '\0';

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return buffer; // Требует free()
}

char* V_gsip(const char* public_link) {
    char api_url[1024];
    snprintf(api_url, sizeof(api_url), 
             "https://cloud-api.yandex.net/v1/disk/public/resources/download?public_key=%s", 
             public_link);

    char* api_response = http_get(api_url);
    if (!api_response) return NULL;

    char* href_start = strstr(api_response, "\"href\":\"");
    if (!href_start) {
        free(api_response);
        return NULL;
    }
    href_start += 8;

    char* href_end = strchr(href_start, '"');

    if (!href_end) {
        free(api_response);
        return NULL;
    }

    size_t raw_len = href_end - href_start;
    char* download_url = (char*)malloc(raw_len + 1);
    if (!download_url) {
        free(api_response);
        return NULL;
    }

    // Заменяем '\/' на '/' для корректного URL
    size_t j = 0;
    for (size_t i = 0; i < raw_len; i++) {
        if (href_start[i] == '\\' && href_start[i + 1] == '/') {
            continue; // Пропускаем обратный слеш
        }
        download_url[j++] = href_start[i];
    }
    download_url[j] = '\0';
    free(api_response);

    char* config_json = http_get(download_url);
    free(download_url);

    return config_json;
}

// NET OBR 
void OnNetworkPacketReceived(uint8_t type, const uint8_t* payload, uint32_t len) {
    switch (type) {
        case 0x01: {// Текстовое сообщение
            printf("[TCP] Получен текст, размер: %zu байт\n", len);
            break;}
		case 0x02: { // Системная команда
			// тут парсинг json надо
            printf("[TCP] Получена система, размер: %zu байт\n", len);
            break;}
        case 0x03:{ // Медиа-чанк
            printf("[TCP] Получен файл-чанк, размер: %zu байт\n", len);
            break;}
        case 0x04: {// Голосовой поток (Opus/DTLS)
            printf("[UDP/DTLS] Получены голосовые данные: %zu байт\n", len);
            break;}
        default:
            printf("Неизвестный тип пакета: 0x%02X\n", type);
            break;
    }
}

int BD_init(sqlite3* db) {
    int rc;
    sqlite3_exec(db, "PRAGMA page_size = 4096;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous = 1;", NULL, NULL, NULL); 
    sqlite3_exec(db, "PRAGMA temp_store = MEMORY;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);

    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS ME(NAME TEXT DEFAULT 'zc user', PASSW BLOB, UID INTEGER DEFAULT 0, VER BOOLEAN, OBN TEXT, AVA BLOB);", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS USERS(NAME TEXT, UID INTEGER, VER BOOLEAN, AVA_PATH TEXT, OBN TEXT);", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS CHATS(NAME TEXT, CID INTEGER, MMBRS TEXT, LID INTEGER, AVA_PATH TEXT, OBN TEXT, LS BOOLEAN);", NULL, NULL, NULL);

	sqlite3_exec(db, "INSERT INTO ME (NAME, UID, VER) SELECT 'zc user', 0, 0 WHERE NOT EXISTS (SELECT 1 FROM ME);", NULL, NULL, NULL);

    // В MSGS вместо TEXT и MEDIA делим на CONTENT (текст или путь к файлу)
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS MSGS("
                     "MID INTEGER, "
                     "UID INTEGER, "
                     "CID INTEGER, "
                     "CONTENT TEXT, "   // Текст сообщения ИЛИ путь к медиафайлу
                     "TYPE INTEGER, "  // 0 - текст, 1 - фото, 2 - файл, 3 - док
                     "TIME TEXT"
                     ");", NULL, NULL, NULL);

    // Составной индекс для эффективного скролла и сортировки
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_msgs_cid_mid ON MSGS(CID, MID);", NULL, NULL, NULL);

    // === СОХРАНЕНИЕ ===
    rc = sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO ME (NAME, PASSW, UID, VER, OBN, AVA) VALUES (?, ?, ?, ?, ?, ?);", -1, &stmts.save_me, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO USERS (NAME, UID, VER, OBN) VALUES (?, ?, ?, ?);", -1, &stmts.save_user, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO CHATS (NAME, CID, MMBRS, LID, OBN, LS) VALUES (?, ?, ?, ?, ?, ?);", -1, &stmts.save_chat, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO MSGS (MID, UID, CID, CONTENT, TYPE, TIME) VALUES (?, ?, ?, ?, ?, ?);", -1, &stmts.save_msg, NULL);
    if (rc != SQLITE_OK) return rc;

    // === ИЗВЛЕЧЕНИЕ ===
    rc = sqlite3_prepare_v2(db, "SELECT NAME, PASSW, UID, VER, OBN, AVA FROM ME LIMIT 1;", -1, &stmts.get_me, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "SELECT NAME, VER, OBN FROM USERS WHERE UID = ?;", -1, &stmts.get_user_by_uid, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "SELECT UID, VER, OBN FROM USERS WHERE NAME = ?;", -1, &stmts.get_user_by_name, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "SELECT NAME, MMBRS, LID, OBN, LS FROM CHATS WHERE CID = ?;", -1, &stmts.get_chat_by_cid, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "SELECT CID, MMBRS, LID, OBN, LS FROM CHATS WHERE NAME = ?;", -1, &stmts.get_chat_by_name, NULL);
    if (rc != SQLITE_OK) return rc;
    
    rc = sqlite3_prepare_v2(db, "SELECT MID, UID, CONTENT, TYPE, TIME FROM MSGS WHERE CID = ? ORDER BY MID ASC;", -1, &stmts.get_msgs_by_cid, NULL);
    if (rc != SQLITE_OK) return rc;

    // === УДАЛЕНИЕ ===
    rc = sqlite3_prepare_v2(db, "DELETE FROM MSGS WHERE MID = ?;", -1, &stmts.delete_msg_by_mid, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "DELETE FROM MSGS WHERE CID = ?;", -1, &stmts.delete_msgs_by_cid, NULL);
    if (rc != SQLITE_OK) return rc;

    rc = sqlite3_prepare_v2(db, "DELETE FROM USERS WHERE UID = ?;", -1, &stmts.delete_user_by_uid, NULL);
    if (rc != SQLITE_OK) return rc;

    return SQLITE_OK;
}

void BD_off() {
    if (stmts.save_me) sqlite3_finalize(stmts.save_me);
    if (stmts.save_user) sqlite3_finalize(stmts.save_user);
    if (stmts.save_chat) sqlite3_finalize(stmts.save_chat);
    if (stmts.save_msg) sqlite3_finalize(stmts.save_msg);

    if (stmts.get_me) sqlite3_finalize(stmts.get_me);
    if (stmts.get_user_by_uid) sqlite3_finalize(stmts.get_user_by_uid);
    if (stmts.get_user_by_name) sqlite3_finalize(stmts.get_user_by_name);
    if (stmts.get_chat_by_cid) sqlite3_finalize(stmts.get_chat_by_cid);
    if (stmts.get_chat_by_name) sqlite3_finalize(stmts.get_chat_by_name);
    if (stmts.get_msgs_by_cid) sqlite3_finalize(stmts.get_msgs_by_cid);

    if (stmts.delete_msgs_by_cid) sqlite3_finalize(stmts.delete_msgs_by_cid);
    if (stmts.delete_user_by_uid) sqlite3_finalize(stmts.delete_user_by_uid);  
}

void build_full_path(char* out_buf, size_t buf_size, const char* base_dir, const char* relative_path) {
    snprintf(out_buf, buf_size, "%s/%s", base_dir, relative_path);
}

int bd_save_me(const me* m){
    int w, h;
    size_t a;
    unsigned char* b = V_i2b(m->ava_ptr, &w, &h, &a);
    sqlite3_bind_text(stmts.save_me, 1, m->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmts.save_me, 2, m->hash, 64, SQLITE_TRANSIENT); // Предполагается что хэш 64 байта
    sqlite3_bind_int(stmts.save_me, 3, m->uid);
    sqlite3_bind_int(stmts.save_me, 4, m->ver ? 1 : 0);
    sqlite3_bind_text(stmts.save_me, 5, m->obn, -1, SQLITE_TRANSIENT); 
    sqlite3_bind_blob(stmts.save_me, 6, b, a, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmts.save_me);
    sqlite3_reset(stmts.save_me); // Не забываем сбрасывать состояние!
    sqlite3_clear_bindings(stmts.save_me);
    if (b) free(b);
    
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bd_save_user(const user* u){
    sqlite3_bind_text(stmts.save_user, 1, u->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmts.save_user, 2, u->uid);
    sqlite3_bind_int(stmts.save_user, 3, u->ver ? 1:0);
    sqlite3_bind_text(stmts.save_user, 4, u->obn , -1, SQLITE_TRANSIENT);  
    
    int rc = sqlite3_step(stmts.save_user);
    sqlite3_reset(stmts.save_user);
    sqlite3_clear_bindings(stmts.save_user);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bd_save_msg(const msg* m){
    sqlite3_bind_int(stmts.save_msg, 1, m->mid);
    sqlite3_bind_int(stmts.save_msg, 2, m->uid);
    sqlite3_bind_int(stmts.save_msg, 3, m->cid);
    wchar_t* a = NULL;
    
    if (m->type == MT_TEXT) {
        sqlite3_bind_text(stmts.save_msg, 4, m->ctnt.text, -1, SQLITE_TRANSIENT);
    } else {
        a = V_cmc(m->mid, (m->type == MT_PHOTO) ? true : false);
        sqlite3_bind_text16(stmts.save_msg, 4, a, -1, SQLITE_TRANSIENT);
    }

    sqlite3_bind_int(stmts.save_msg, 5, m->type);
    sqlite3_bind_text(stmts.save_msg, 6, (const char*)m->time, -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmts.save_msg);
    sqlite3_reset(stmts.save_msg);
    sqlite3_clear_bindings(stmts.save_msg);
    if (a) free(a);
    
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int bd_save_chat(const chat* c) {
    sqlite3_bind_text(stmts.save_chat, 1, c->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmts.save_chat, 2, c->cid);
    char* a = V_cu2c(c);
    sqlite3_bind_text(stmts.save_chat, 3, a, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmts.save_chat, 4, c->lmid);
    sqlite3_bind_text(stmts.save_chat, 5, c->obn, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmts.save_chat, 6, (c->ls ? 1 : 0));
    
    int rc = sqlite3_step(stmts.save_chat);
    sqlite3_reset(stmts.save_chat);
    sqlite3_clear_bindings(stmts.save_chat);
    if (a) free(a);
    
    return (rc == SQLITE_DONE) ? 0 : -1;
}

me bd_get_me(me* mm) {
    me m = {0};

    // Если база пустая или нет строки
    if (sqlite3_step(stmts.get_me) != SQLITE_ROW) {
        sqlite3_reset(stmts.get_me);
        if (mm) *mm = m; 
        return m; 
    }

    // 0: NAME
    const char* name_txt = (const char*)sqlite3_column_text(stmts.get_me, 0);
    if (name_txt) {
        strncpy(m.name, name_txt, NICK_LEN - 1);
    }
    m.name[NICK_LEN - 1] = '\0'; 

    // 1: PASSW (HASH) — выделяем собственную память, чтобы указатель не валился после sqlite3_reset
    const void* hash_blob = sqlite3_column_blob(stmts.get_me, 1);
    int hash_bytes = sqlite3_column_bytes(stmts.get_me, 1);
    if (hash_blob && hash_bytes > 0) {
        m.hash = (unsigned char*)malloc(hash_bytes);
        if (m.hash) {
            memcpy(m.hash, hash_blob, hash_bytes);
        }
    } else {
        m.hash = NULL;
    }

    // 2: UID & 3: VER
    m.uid = sqlite3_column_int(stmts.get_me, 2);
    m.ver = (sqlite3_column_int(stmts.get_me, 3) == 1);

    // 4: OBN
    const char* obn_txt = (const char*)sqlite3_column_text(stmts.get_me, 4);
    if (obn_txt) {
        strncpy(m.obn, obn_txt, 15);
    }
    m.obn[15] = '\0'; 

    // 5: AVA
    const void* ava_blob = sqlite3_column_blob(stmts.get_me, 5);
    int ava_bytes = sqlite3_column_bytes(stmts.get_me, 5);
    if (ava_blob && ava_bytes > 0) {
        V_lifm((unsigned char*)ava_blob, ava_bytes, (ID3D11ShaderResourceView**)&m.ava_ptr, &m.w, &m.h);
    }

    if (mm) *mm = m; 

    sqlite3_reset(stmts.get_me);
    sqlite3_clear_bindings(stmts.get_me);
    return m;
}

user bd_get_user_uid(uint32_t uid, user* uu){
    user u = {};
    memset(&u, 0, sizeof(user));
    sqlite3_bind_int(stmts.get_user_by_uid, 1, uid);
        
    if (sqlite3_step(stmts.get_user_by_uid) != SQLITE_ROW) {
        sqlite3_reset(stmts.get_user_by_uid);
        sqlite3_clear_bindings(stmts.get_user_by_uid);
        if (uu) *uu = u;
        return u;
    }

    u.uid = uid;
    
    const char* name_txt = (const char*)sqlite3_column_text(stmts.get_user_by_uid, 0);
    if (name_txt) strncpy(u.name, name_txt, NICK_LEN - 1);
    u.name[NICK_LEN - 1] = '\0';
    
    u.ver = (sqlite3_column_int(stmts.get_user_by_uid, 1) == 1);
    
    const char* obn_txt = (const char*)sqlite3_column_text(stmts.get_user_by_uid, 2);
    if (obn_txt) strncpy(u.obn, obn_txt, 15);
    u.obn[15] = '\0';
    
    int w = 0, h = 0;
    wchar_t* a = V_cibp(uid, true);
    if (a) {
        V_liff(a, (ID3D11ShaderResourceView**)&u.ava_ptr, &w, &h);
        free(a);
    }

    if (uu) *uu = u;
    
    sqlite3_reset(stmts.get_user_by_uid);
    sqlite3_clear_bindings(stmts.get_user_by_uid);
    return u;
}


user bd_get_user_name(char* name, user* uu){
    user u = {};
    memset(&u, 0, sizeof(user));
    
    if (!name) return u; // Защита от передачи NULL-имени

    sqlite3_bind_text(stmts.get_user_by_name, 1, name, -1, SQLITE_TRANSIENT);
        
    if (sqlite3_step(stmts.get_user_by_name) != SQLITE_ROW) {
        sqlite3_reset(stmts.get_user_by_name);
        sqlite3_clear_bindings(stmts.get_user_by_name);
        if (uu) *uu = u;
        return u;
    }

    u.uid = sqlite3_column_int(stmts.get_user_by_name, 0);
    
    strncpy(u.name, name, NICK_LEN - 1);
    u.name[NICK_LEN - 1] = '\0';   
    
    u.ver = (sqlite3_column_int(stmts.get_user_by_name, 1) == 1);
    
    const char* obn_txt = (const char*)sqlite3_column_text(stmts.get_user_by_name, 2);
    if (obn_txt) strncpy(u.obn, obn_txt, 15);
    u.obn[15] = '\0';
    
    int w = 0, h = 0;
    wchar_t* a = V_cibp(u.uid, true);
    if (a) {
        V_liff(a, (ID3D11ShaderResourceView **)&u.ava_ptr, &w, &h);
        free(a);
    }

    if (uu) *uu = u;
    
    sqlite3_reset(stmts.get_user_by_name);
    sqlite3_clear_bindings(stmts.get_user_by_name);
    return u;
}

chat bd_get_chat_cid(uint32_t cid, chat* cc){
    chat c = {};
    memset(&c, 0, sizeof(chat));

    // ИСПРАВЛЕНО: Был ошибочно указан stmts.get_msgs_by_cid вместо get_chat_by_cid
    sqlite3_bind_int(stmts.get_chat_by_cid, 1, cid);
    
    if (sqlite3_step(stmts.get_chat_by_cid) != SQLITE_ROW) {
        sqlite3_reset(stmts.get_chat_by_cid);
        sqlite3_clear_bindings(stmts.get_chat_by_cid);
        if (cc) *cc = c;
        return c;
    }

    const char* name_txt = (const char*)sqlite3_column_text(stmts.get_chat_by_cid, 0);
    if (name_txt) strncpy(c.name, name_txt, NICK_LEN - 1);
    c.name[NICK_LEN - 1] = '\0';
    
    c.cid = cid;
    
    size_t ccc = 0;
    const char* mmbrs_txt = (const char*)sqlite3_column_text(stmts.get_chat_by_cid, 1);
    if (mmbrs_txt) c.usrs = V_luim((char*)mmbrs_txt, &ccc);
    c.uc = (uint32_t)ccc;
    
    c.lmid = sqlite3_column_int(stmts.get_chat_by_cid, 2);
    
    const char* obn_txt = (const char*)sqlite3_column_text(stmts.get_chat_by_cid, 3);
    if (obn_txt) strncpy(c.obn, obn_txt, 15);
    c.obn[15] = '\0';
    
    c.ls = (sqlite3_column_int(stmts.get_chat_by_cid, 4) == 1);
    
    wchar_t* a = V_cibp(c.cid, c.ls);
    if (a) {
        int w = 0, h = 0;
        V_liff(a, (ID3D11ShaderResourceView**)&c.ava_ptr, &w, &h);
        free(a); // Предполагаю, что V_cibp выделяет память, которую надо чистить
    }
    
    sqlite3_reset(stmts.get_chat_by_cid);
    sqlite3_clear_bindings(stmts.get_chat_by_cid);
    
    if (cc) *cc = c;
    return c;
}

chat bd_get_chat_name(char* name, chat* cc){
    chat c = {};
    memset(&c, 0, sizeof(chat));
    
    if (!name) return c;

    // ИСПРАВЛЕНО: Был ошибочно указан stmts.get_msgs_by_name вместо get_chat_by_name
    sqlite3_bind_text(stmts.get_chat_by_name, 1, name, -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmts.get_chat_by_name) != SQLITE_ROW) {
        sqlite3_reset(stmts.get_chat_by_name);
        sqlite3_clear_bindings(stmts.get_chat_by_name);
        if (cc) *cc = c;
        return c;
    }

    strncpy(c.name, name, NICK_LEN - 1);
    c.name[NICK_LEN - 1] = '\0';
    
    c.cid = sqlite3_column_int(stmts.get_chat_by_name, 0);
    
    size_t ccc = 0;
    const char* mmbrs_txt = (const char*)sqlite3_column_text(stmts.get_chat_by_name, 1);
    if (mmbrs_txt) c.usrs = V_luim((char*)mmbrs_txt, &ccc);
    c.uc = (uint32_t)ccc;
    
    c.lmid = sqlite3_column_int(stmts.get_chat_by_name, 2);
    
    const char* obn_txt = (const char*)sqlite3_column_text(stmts.get_chat_by_name, 3);
    if (obn_txt) strncpy(c.obn, obn_txt, 15);
    c.obn[15] = '\0';
    
    c.ls = (sqlite3_column_int(stmts.get_chat_by_name, 4) == 1);
    
    wchar_t* a = V_cibp(c.cid, c.ls);
    if (a) {
        int w = 0, h = 0;
        V_liff(a, (ID3D11ShaderResourceView**)&c.ava_ptr, &w, &h);
        free(a);
    }
    
    sqlite3_reset(stmts.get_chat_by_name);
    sqlite3_clear_bindings(stmts.get_chat_by_name);
    
    if (cc) *cc = c;
    return c;
}

int bd_get_msgs(sqlite3_stmt* stmt, uint16_t cid, msg* out_array, size_t max_count, size_t* out_count, const char* base_blob_dir) {
    if (!stmt || !out_array || !out_count) return -1;
    
    sqlite3_bind_int(stmt, 1, cid);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_count) {
        msg* m = &out_array[count];
        memset(m, 0, sizeof(msg)); // Полная очистка перед заполнением

        m->mid  = (uint32_t)sqlite3_column_int(stmt, 0);
        m->uid  = (uint16_t)sqlite3_column_int(stmt, 1);
        m->cid  = cid;
        m->dost = true;
        m->type = (uint8_t)sqlite3_column_int(stmt, 3); // В запросе TYPE - это 3-я колонка (с 0)

        const char* content = (const char*)sqlite3_column_text(stmt, 2); // В запросе CONTENT - 2-я колонка

        if (m->type == MT_TEXT) {
            if (content) {
                // Используем strncpy вместо snprintf для безопасного копирования
                strncpy((char*)m->ctnt.text, content, sizeof(m->ctnt.text) - 1);
                m->ctnt.text[sizeof(m->ctnt.text) - 1] = '\0';
            } else {
                m->ctnt.text[0] = '\0';
            }
        } 
        else if (m->type == MT_PHOTO) {
            wchar_t* a = V_cmc(m->mid, true);
            if (a) {
                ID3D11ShaderResourceView* b = NULL;
                int w = 0, h = 0;
                V_liff(a, &b, &w, &h);
                m->ctnt.image.w = w;
                m->ctnt.image.h = h;                
                free(a);                
            }
        }

        // ИСПРАВЛЕНО: Безопасное копирование времени (вместо крашащегося sprintf)
        const char* time_str = (const char*)sqlite3_column_text(stmt, 4);
        if (time_str) {
            strncpy((char*)m->time, time_str, sizeof(m->time) - 1);
            m->time[sizeof(m->time) - 1] = '\0';
        } else {
            m->time[0] = '\0';
        }
        
        count++;
    }

    *out_count = count;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    return 0;
}

unsigned char* v_gii(){
	// тут передается в буфере сырые байты фото. надо создать битмап, достать инфу и сохранить в структуру и в предпросмотр вывести

	
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

wchar_t* v_gt(wchar_t* buffer, size_t max_len) {
    if (!buffer || max_len == 0) {
        return NULL;
    }
    
    buffer[0] = L'\0';

    if (!OpenClipboard(NULL)) {
        return buffer; 
    }

    if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData != NULL) {
            wchar_t* pText = (wchar_t*)GlobalLock(hData);
            if (pText != NULL) {
                wcsncpy(buffer, pText, max_len - 1);
                buffer[max_len - 1] = L'\0';
                
                GlobalUnlock(hData);
            }
        }
    }
   
    CloseClipboard();
    
    return buffer;
}

unsigned char* v_gf(uint32_t* fc, char* p, size_t max_len){
    if (!p || max_len == 0) return NULL;
    if (!OpenClipboard(NULL)) return NULL;
    
    wchar_t wpath[MAX_PATH];
    if (IsClipboardFormatAvailable(CF_HDROP)) {
        HANDLE hData = GetClipboardData(CF_HDROP);
        if (hData != NULL) {
            HDROP hDrop = (HDROP)GlobalLock(hData);
            if (hDrop != NULL) {
                *fc = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
                if (*fc > 0) {
                    if (DragQueryFileW(hDrop, 0, wpath, MAX_PATH)) {
                        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, p, (int)max_len, NULL, NULL);
                    }
                }
                GlobalUnlock(hData);
                CloseClipboard();
                return (unsigned char*)p; 
            }
        }
    }
    CloseClipboard();
    return NULL;
}

static bool C_hash(void* d, size_t dl, byte* out_hash) {
    wc_Sha512 s;
    if (wc_InitSha512(&s) != 0) return false;
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
	DWORD len = 64;
	if(RegQueryValueExA(h, "WiFi ID", NULL, NULL, (LPBYTE)a, &len) != ERROR_SUCCESS) {return false;}
	RegCloseKey(h);
	return true;	
}

void V_pknc(chat* c, msg* msgs, uint32_t* count, user* us){
	

	
}


static bool f = false;
static uint32_t cid_schas;
uint8_t load_d;
bool r;


static void zc_chat(short x, short y, chat* c, msg* msgs, uint32_t msg_count, user* us) {
	if (cid_schas != c->cid){
		// надо вызвать функцию, чтобы она очистила и загрузила в us всех пользователей чата, а так же сообщения
				
		cid_schas = c->cid;
	}
	igSetNextWindowSize(ImVec2(x*0.65, y), ImGuiCond_None);
    igSetNextWindowPos(ImVec2(x*0.35, 0), ImGuiCond_None);
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

    // Хедер
    ImDrawList* idl = igGetWindowDrawList();
    ImVec2 window_pos = igGetWindowPos();
    ImVec2 p_min = ImVec2(window_pos.x + x*0.0085, window_pos.y + y*0.005);
    ImVec2 p_max = ImVec2(window_pos.x + x*0.64, window_pos.y + y*0.055);
    const ImU32 color_rect = igColorConvertFloat4ToU32(ImVec4(0.18f, 0.188f, 0.2f, 1.0f));
    const ImU32 color_border = 0xFFFFFFFF;
    ImDrawList_AddRectFilledEx(idl, p_min, p_max, color_rect, 0.5f, ImDrawFlags_RoundCornersAll);
    ImDrawList_AddRectEx(idl, p_min, p_max, color_border, 5.0f, ImDrawFlags_RoundCornersAll, 0.5f);
	ImVec2 s = igCalcTextSize(c->name);
	float a = x*0.31575 - (y*0.048 + x*0.005 + s.x)*0.5;

	ImDrawList_AddImage(idl, *c->ava_ptr, ImVec2(a, y*0.001), ImVec2(a+y*0.048, y*0.05));
	ImDrawList_AddTextEx(idl, ImVec2(a+y*0.049, y*0.001), 0xFFFFFFFF, c->name, NULL);

    float header_offset = y * 0.05f;
    float chat_area_h = (y * 0.96f - p_h) - header_offset - (y * 0.01f);

    igSetCursorPos(ImVec2(x * 0.02f, header_offset));
    igBeginChild("CS", ImVec2(x * 0.64f, chat_area_h), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);

    float avatarSize = x * 0.018f;
    float avatarRounding = avatarSize * 0.3f;
    const float padding = 8.0f;
    const float messageSpacing = 3.0f;

    for (int i = 0; i < msg_count; ++i) {
        msg* msgi = &msgs[i];
        
        char id_str[32];
        snprintf(id_str, sizeof(id_str), "msg_%d", msgi->mid);
        igPushID(id_str);

        ImVec2 cursorStartPos = igGetCursorPos();
		
        char header_str[128];
		user* xx = NULL;
		HASH_FIND(hh, us, &msgi->uid, sizeof(uint32_t), xx);
        snprintf(header_str, sizeof(header_str), "%s  \t\t\t %s", xx->name, msgi->time);
        ImVec2 hSize = igCalcTextSizeEx(header_str, NULL, false, x * 0.54f);
        double itemH = 0.0f;
		double w;
        if (msgi->type == 1) { 
            w = msgi->ctnt.image.w > hSize.x ? msgi->ctnt.image.w + 20 : hSize.x + 20;
            itemH = hSize.y + msgi->ctnt.image.h + 20 + hSize.y + padding * 2 + messageSpacing;
        } else if (msgi->type == 2) { 
            itemH = hSize.y + padding * 2 + y*0.06 + messageSpacing;
			w = hSize.x + padding*2 + 20;
        } else { 
            ImVec2 textSize = igCalcTextSizeEx(msgi->ctnt.text, NULL, false, x * 0.54f);
            itemH = hSize.y + textSize.y + padding * 2 + messageSpacing;
        }

        ImVec2 screenPos = igGetCursorScreenPos();
        ITID ava_tex = *msgi->ctnt.image.img_ptr; 
        ImDrawList_AddImageRounded(idl, (ITID)ava_tex, screenPos, ImVec2(screenPos.x + avatarSize, screenPos.y + avatarSize), ImVec2(0,0), ImVec2(1,1), 0xFFFFFFFF, avatarRounding, ImDrawFlags_None);

        igSetCursorPos(ImVec2(cursorStartPos.x, cursorStartPos.y));
        if (igInvisibleButton("##avatar_btn", ImVec2(avatarSize, avatarSize), ImGuiButtonFlags_None)) {
            // Клик по аватарке 
        }

        igSetCursorPos(ImVec2(cursorStartPos.x + avatarSize + padding, cursorStartPos.y));

        ImVec2 msgPos = igGetCursorScreenPos();
        ImVec2 msgEnd = ImVec2(msgPos.x + w, msgPos.y + itemH - messageSpacing);

        ImDrawList_AddRectFilledEx(idl, msgPos, msgEnd, 0xFF353535, 12.0f, ImDrawFlags_RoundCornersAll); 

        igSetCursorScreenPos(ImVec2(msgPos.x + padding, msgPos.y + padding));
        igSetWindowFontScale(0.8f);
        igTextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), header_str);
        igSetWindowFontScale(1.0f);

        // Само содержимое (Текст, Картинка или Файл)
        igSetCursorScreenPos(ImVec2(msgPos.x + padding, msgPos.y + hSize.y + padding));
        if (msgi->type == MT_PHOTO) {
            ImTextureRef img_tex = *msgi->ctnt.image.img_ptr;
			double oo = msgi->ctnt.image.w / (x*0.4);
            int ww = msgi->ctnt.image.w > x*0.4 ? x*0.4 : msgi->ctnt.image.w;
            int hh = msgi->ctnt.image.w > x*0.4 ? msgi->ctnt.image.h*oo : msgi->ctnt.image.h;
            igImage(img_tex, ImVec2(ww, hh));
        } else if (msgi->type == MT_DOC) {
            igText("Файл: %u", msgi->mid);
        } else {
            igTextWrapped("%s", msgi->ctnt.text);
        }

        igSetCursorPos(ImVec2(cursorStartPos.x, cursorStartPos.y + itemH + y * 0.01f));
        igPopID();
    }

    igEndChild();


    igSetCursorPos(ImVec2(x*0.1, y - p_h));
    igDummy(ImVec2(0, 0));
    igPushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
    igPushStyleVarImVec2(ImGuiStyleVar_WindowPadding, ImVec2(x*0.07, y*0.01));
    igPushStyleColorImVec4(ImGuiCol_ChildBg, ImVec4(0.125f, 0.133f, 0.145f, 1.0f));
    igPushStyleColorImVec4(ImGuiCol_FrameBg, ImVec4(0.125f, 0.133f, 0.145f, 1.0f));
    igSetNextWindowPos(ImVec2(x*0.45, y*0.96 - p_h), ImGuiCond_None);
    igSetNextWindowSize(ImVec2(x*0.45, p_h), ImGuiCond_None);
    
    if(igBeginChild("##p", ImVec2(x*0.45, p_h), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar)){
        igSetNextItemWidth(x*0.4);
        float _y = (p_h - i_h) * 0.5f;
        igSetCursorPos(ImVec2(20, _y));
		if(f){igSetKeyboardFocusHere(); f = false;}
        if (igInputTextMultilineEx("##i", c->buf, 4096, ImVec2(i_w, i_h), ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_WordWrap, NULL, NULL)){
            c->buf[0] = '\0';
			f = true;
        }
    }
    igEndChild();
    igPopStyleVarEx(1);
	igPopStyleVar();
    igPopStyleColor();
    igPopStyleColor();
    igEnd();
}

// static void zc_chat(short x, short y, chat* c){
//     igSetNextWindowSize((ImVec2){x*0.65, y}, NULL);
//     igSetNextWindowPos((ImVec2){x*0.35, 0}, NULL);
//     igBegin("c", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus);
    
//     ImGuiStyle* style = igGetStyle();
//     float l_h = igGetTextLineHeight();
//     float i_w = x * 0.386f;    
//     ImVec2 t_s = igCalcTextSizeEx(c->buf, NULL, false, i_w - (style->FramePadding.x * 2.0f) - style->ScrollbarSize); 
 
//     int len = strlen(c->buf);
//     if (len > 0 && c->buf[len - 1] == '\n') {
//         t_s.y += l_h;
//     }
    
//     float min_h = l_h + (style->FramePadding.y * 2.0f);        // 1 строка
//     float max_h = (l_h * 8) + (style->FramePadding.y * 2.0f);  // 8 строк
    
//     float i_h = t_s.y + (style->FramePadding.y * 2.0f);
//     if (i_h < min_h) i_h = min_h;
//     if (i_h > max_h) i_h = max_h;
    
//     float p_h = i_h + y * 0.02f;


// 	// хедер
// 	ImDrawList* idl = igGetWindowDrawList();
// 	ImVec2 window_pos = igGetWindowPos();
// 	ImVec2 p_min = { window_pos.x + y*0.005,  window_pos.y + y*0.005 };
// 	ImVec2 p_max = { window_pos.x + x*0.06, window_pos.y + y*0.04 };
// 	const ImU32 color_rect = 0xFF2CC2FC;
// 	const ImU32 color_border = 0xFFFFFFFF;
// 	ImDrawList_AddRectFilledEx(idl, p_min, p_max, color_rect, 5.0f, ImDrawFlags_RoundCornersAll);
// 	ImDrawList_AddRectEx(idl, p_min, p_max, color_border, 5.0f, ImDrawFlags_RoundCornersAll, 2.0f);
	



	
//     igSetCursorPos((ImVec2){x*0.1, y*0.96 - p_h});
//     igDummy(ImVec2(0, 0));
    
//     igPushStyleVarImVec2(ImGuiStyleVar_WindowPadding, (ImVec2){x*0.07, y*0.01});
//     igPushStyleColorImVec4(ImGuiCol_ChildBg, (ImVec4){0.125f, 0.133f, 0.145f, 1.0f});
//     igSetNextWindowPos((ImVec2){x*0.45, y*0.96 - p_h}, NULL);
//     igSetNextWindowSize(ImVec2(x*0.45, p_h), NULL);
    
//     if(igBeginChild("##p", ImVec2(x*0.45, p_h), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar)){
//         igSetNextItemWidth(x*0.4);
//         float _y = (p_h - i_h) * 0.5f;
//         igSetCursorPos((ImVec2){20, _y});
// 		if(f){igSetKeyboardFocusHere(); f = false;}
//         if (igInputTextMultilineEx("##i", c->buf, 4096, ImVec2(i_w, i_h), ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_WordWrap, NULL, NULL)){
//             c->buf[0] = '\0';
// 			f = true;
//         }
//     }
//     igEndChild();
//     igPopStyleVarEx(1);
//     igPopStyleColor();
//     igEnd();
// }



static void zc_voice(short x, short y){
	igSetNextWindowSize((ImVec2){x*0.35, y*0.7}, 0);
	igSetNextWindowPos((ImVec2){0, 0}, 0);
	igBegin("v", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus);



	
	igEnd();
}

static void zc_sw(short x, short y){
	igSetNextWindowSize((ImVec2){x*0.35, y*0.3}, 0);
	igSetNextWindowPos((ImVec2){0, y*0.7}, 0);
	igBegin("s", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus);

	

	
	igEnd();
}


// // если будут сертификаты, то логин не нужон, тк нужно просто проверить сертификат и усе
// static void zc_login(short x, short y, ID3D11ShaderResourceView* my_srv){    
// 	static char l[32];
// 	static char p[32];
// 	igSetNextWindowSize(ImVec2(x*0.28, y), 0);
// 	igSetNextWindowPos(ImVec2(x*0.36, 0), 0);
// 	igBegin("##l", &gm.login, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_Modal);
// 	igImage((ImTextureRef){ ._TexID = (ImTextureID)my_srv, ._TexData = NULL }, ImVec2(x*0.273, x*0.049));

// 	ImVec2 aa = igCalcTextSize("Авторизация");
// 	igSetWindowFontScale(2.0f);
// 	igSetCursorPos(ImVec2(x*0.5 - (aa.x *0.5), x*0.06));
// 	igText("Авторизация");
// 	igSetWindowFontScale(1.0f);

// 	igPushItemWidth(x*0.271);
// 	// igSetCursorPosX(x*0.37);
// 	igText("Логин:");
// 	igInputText("##ll", l, 32, ImGuiInputTextFlags_None);

// 	igSpacing();

// 	igText("Пароль:");
// 	igInputText("##lp", p, 32, ImGuiInputTextFlags_Password);
// 	igPopItemWidth();
// 	igSpacing(); igSpacing();

// 	igSetCursorPos(ImVec2(x*0.46, y*0.86));
// 	if(igButtonEx("Войти", ImVec2(x*0.08, y*0.03))){
// 		// l = логин пользователя, p = пароль пользователя сначала проверить в бд, потом на сервере
		
// 	}

// 	igSetCursorPosX(x*0.37);
// 	igTextDisabled("*ваш аккаунт только для вас!");
		
// 	igEnd();
// }

// сюда надо бы добавить генерацию ключей

#define TO_IMGUI_COLOR(R, G, B, A) \
		(((ImU32)((A)*255.0f)) << 24) | \
		(((ImU32)((B)*255.0f)) << 16) | \
		(((ImU32)((G)*255.0f)) << 8)  | \
		((ImU32)((R)*255.0f))

char* srat = "{\n"
  "  \"log\": { \"loglevel\": \"error\" },\n"
  "  \"inbounds\": [\n"
  "    {\n"
  "      \"tag\": \"socks-in\",\n"
  "      \"port\": 10808,\n"
  "      \"listen\": \"127.0.0.1\",\n"
  "      \"protocol\": \"socks\",\n"
  "      \"settings\": { \"udp\": true }\n"
  "    }\n"
  "  ],\n"
  "  \"outbounds\": [\n"
  "    {\n"
  "      \"protocol\": \"vless\",\n"
  "      \"settings\": {\n"
  "        \"vnext\": [{\n"
  "          \"address\": \"localhost\",\n"
  "          \"port\": 443,\n"
  "          \"users\": [\n"
  "            { \n"
  "              \"id\": \"f0c5dc91-281c-4238-90d6-4f9e000f0422\", \n"
  "              \"email\": \"FFFFFFFF\",\n"
  "              \"encryption\": \"none\" \n"
  "            }\n"
  "          ]\n"
  "        }]\n"
  "      },\n"
  "      \"streamSettings\": {\n"
  "        \"network\": \"tcp\",\n"
  "        \"security\": \"reality\",\n"
  "        \"realitySettings\": {\n"
  "          \"show\": false,\n"
  "          \"fingerprint\": \"chrome\",\n"
  "          \"serverName\": \"ozon.ru\",\n"
  "          \"publicKey\": \"J4NnJ0pVn8f8Q1VhplGvuw8kUciKh6GWJECW-DMaXTg\",\n"
  "          \"shortId\": \"f875f93a20c13555\",\n"
  "          \"spiderX\": \"/\"\n"
  "        }\n"
  "      }\n"
  "    },\n"
  "    { \"protocol\": \"blackhole\", \"tag\": \"block\" }\n"
  "  ],\n"
  "  \"routing\": {\n"
  "    \"domainStrategy\": \"IPIfNonMatch\",\n"
  "    \"rules\": [\n"
  "      { \"type\": \"field\", \"ip\": [\"geoip:private\"], \"outboundTag\": \"block\" }\n"
  "    ]\n"
  "  }\n"
"}";
		
static void zc_register(short x, short y, ID3D11ShaderResourceView* my_srv){ // db надо сюда
	static char l[33];
	static char p[33];
	static char b[64];
	static ID3D11ShaderResourceView* i = {0};
	static bool ok = false;
	static bool ii = false;
	igSetNextWindowSize(ImVec2(x*0.28, y), 0);
	igSetNextWindowPos(ImVec2(x*0.36, 0), 0);
	igPushStyleColor(ImGuiCol_WindowBg, (ImU32){0.1f, 0.1f, 0.12f, 1.0f });
	igPushStyleColor(ImGuiCol_Border, (ImU32){ 0.137f, 0.153f, 0.165f, 1.000f });
	igPushStyleVar(ImGuiStyleVar_FrameRounding, gm.r);
	
	if(igBegin("##r", &gm.reg, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_Modal)){
	
		igImage((ImTextureRef){ ._TexID = (ImTextureID)my_srv, ._TexData = NULL }, ImVec2(x*0.273, x*0.049));


		// ImVec2 aa = igCalcTextSize("Авторизация");
		igSetWindowFontScale(2.0f);
		// igSetCursorPos(ImVec2(x*0.5 - (aa.x *0.5), x*0.06));
		igText("Регистрация");
		igSetWindowFontScale(1.0f);
		igSpacing();

		if(ii && i){
			igImage(IT(i), ImVec2(x*0.12, x*0.12));
		}
		igSameLine();

		int w, h;		
		if (igButton("Выбрать аватарку")) {
			OPENFILENAMEW ofn;
			wchar_t szFile[260] = { 0 };
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = NULL;
			ofn.lpstrFile = szFile;
			ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
			ofn.lpstrFilter = L"Images\0*.jpg;*.jpeg;*.png;*.bmp\0";
			ofn.nFilterIndex = 1;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileNameW(&ofn) == TRUE) {
				if (i) {
					i->lpVtbl->Release(i);
					i = NULL; 
				}

				if (!V_liff(ofn.lpstrFile, &i, &w, &h)) {
					ok = false;
					ii = false;
				} else {
					ok = true;
					ii = true;
				}
			}
		}

		igPushItemWidth(x*0.271);
		// igSetCursorPosX(x*0.37);
		igText("Ваше имя:");
		igInputText("##rl", l, IM_ARRAYSIZE(l), ImGuiInputTextFlags_None);

		igText("Ваш BDU ключ:");
		igInputText("##rb", b, IM_ARRAYSIZE(b), ImGuiInputTextFlags_None);

		ImU32 m1;
		ImU32 m2;
		ImU32 m3;
		// тут менять цвет при правильности данных
		if (strlen(l) > 0 && strlen(b) == 36 && ok && ii) {
			m1 = TO_IMGUI_COLOR(0.0f, 0.729f, 0.133f,   1.0f); // Button
			m2 = TO_IMGUI_COLOR(0.004f, 0.8f, 0.149f, 1.0f);   // ButtonHovered
			m3 = TO_IMGUI_COLOR(0.106f, 0.929f, 0.255f, 1.0f); // ButtonActive
		}
		else {
			m1 = TO_IMGUI_COLOR(0.361f, 0.125f, 0.125f, 1.0f);
			m2 = TO_IMGUI_COLOR(0.361f, 0.125f, 0.125f, 1.0f);
			m3 = TO_IMGUI_COLOR(0.361f, 0.125f, 0.125f, 1.0f);
		}

		igPushStyleColor(ImGuiCol_Button, m1);
		igPushStyleColor(ImGuiCol_ButtonHovered, m2);
		igPushStyleColor(ImGuiCol_ButtonActive, m3);

		igSetCursorPosY(y*0.94);

		if (igButtonEx("Зарегистрироваться", ImVec2(x*0.271, y*0.045))) {
			if(strlen(l) > 0 && strlen(b) == 36 && ok && ii){
				char* s =/* "localhost";*/V_gsip(YA_LINK);
				if (s == NULL) {
					printf("ploho delo");
				}
				printf("%s\n\n", s);
				printf("%s\n\n", s);
				printf("%s\n\n", s);
				printf("%s\n\n", s);


				// char* srat = V_lj("config.json", s, b, 0);
				// if (srat == NULL) {
				// 	fputs("ERROR: V_lj returned NULL!\n", log);
				// 	fflush(log);
				// 	fclose(log);
				// 	//free(s);
				// }

				HANDLE hFile = CreateFileW(
					L"C:/Temp/cfg.json",               // Путь к файлу ("cfg.json")
					GENERIC_READ,            // Запрашиваем доступ только на чтение
					FILE_SHARE_READ,         // Разрешаем другим программам тоже читать файл (исключает блокировку)
					NULL,                    // Атрибуты безопасности по умолчанию
					OPEN_EXISTING,           // Открываем только если файл уже существует
					FILE_ATTRIBUTE_NORMAL,   // Стандартные атрибуты файла
					NULL                     // Шаблонный файл не используется
				);

				if (hFile == INVALID_HANDLE_VALUE) {
					DWORD err = GetLastError();
					printf("[Win32 ERROR] Не удалось открыть '%s'. Код ошибки: %lu\n", "cfg.json", err);
				}

				// 2. Получаем точный размер файла в байтах
				DWORD file_size = GetFileSize(hFile, NULL);
				if (file_size == INVALID_FILE_SIZE) {
					CloseHandle(hFile);
				}

				// 3. Выделяем память под буфер JSON (+1 байт под нуль-терминатор '\0')
				char* json_buffer = (char*)malloc(file_size + 1);
				if (!json_buffer) {
					CloseHandle(hFile);
				}

				// 4. Читаем данные из файла в буфер
				DWORD bytes_read = 0;
				BOOL read_success = ReadFile(
					hFile,           // Дескриптор открытого файла
					json_buffer,     // Буфер, куда читать данные
					file_size,       // Сколько байт прочитать
					&bytes_read,     // Переменная, куда запишется реальное кол-во прочитанных байт
					NULL             // Асинхронный режим не используется
				);


				CloseHandle(hFile);
				// char* a = V_rf("cfg.json");
				if (zn_Init(json_buffer, s, 443, 444, 0)) {
					char* abv = malloc(128);
					size_t s, s2;
					char* aa = V_b64e(V_i2b(i, &w, &h, &s), s, &s2);
					sprintf_s(abv, 128, "{\"t\":\"r\", \"u\":\"%s\", \"n\":\"%s\", \"i\":[\"%s\", %zu]}", b, l, aa, s);

					zn_SendSystem(abv);
					free(abv);
					free(aa);

				} else {
					printf("kal");
				}

				if (json_buffer) free(json_buffer);
				// if (srat) free(srat);
				if (s) free(s);
			}
		}

		igPopItemWidth();
		igPopStyleColor(); igPopStyleColor(); igPopStyleColor();

		igPopStyleColor();
		igPopStyleColor();
		igPopStyleVar();
		igEnd();

	}
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
	igBegin("##s", &gm.set, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

	
	
	igEnd();
}

int main(int argc, char** argv) {
	// Динамическое включение четкости прямо в коде (замена манифесту)
	void* hUser32 = GetModuleHandleA("user32.dll");
	if (hUser32) {
		BOOL(WINAPI* pSetProcessDpiAwarenessContext)(void*) = 
			(BOOL(WINAPI*)(void*))GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
		if (pSetProcessDpiAwarenessContext) {
			// -4 это значение DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
			pSetProcessDpiAwarenessContext((void*)-4); 
		} else {
			// Если Windows старая, используем базовый вариант
			BOOL(WINAPI* pSetProcessDPIAware)(void) = 
				(BOOL(WINAPI*)(void))GetProcAddress(hUser32, "SetProcessDPIAware");
			if (pSetProcessDPIAware) pSetProcessDPIAware();
		}
	}
	

	// SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, _T("Zipcord"), NULL };
    RegisterClassEx(&wc);
    HWND hwnd = CreateWindow(wc.lpszClassName, _T("Zipcord"), WS_OVERLAPPEDWINDOW, 100, 100, 1920, 1080, NULL, NULL, wc.hInstance, NULL);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
		
    }
	SHCreateDirectoryExW(NULL, WCHART_PATH, NULL);
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);
    igCreateContext(NULL);
    ImGuiIO* io = igGetIO();
    io->ConfigFlags &= ~ImGuiConfigFlags_NavEnableKeyboard;
    static const ImWchar mdi_ranges[] = { ICON_MIN_MD, ICON_MAX_MD, 0 };  

	ImFontConfig icons_config ={0};
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.GlyphMinAdvanceX = 24.0f;
    icons_config.GlyphOffset = ImVec2(-1.0f, -1.0f);
	
    int font_data_size = (int)((intptr_t)_binary_museo_ttf_end - (intptr_t)_binary_museo_ttf_start);
    ImFontAtlas* atlas = igGetIO()->Fonts;
    const ImWchar* ranges = ImFontAtlas_GetGlyphRangesCyrillic(atlas);
    // ImFontAtlas_AddFontFromMemoryTTF(atlas, _binary_museo_ttf_start, font_data_size, 24.0f, NULL, ranges);

	ImFontAtlas_AddFontFromFileTTF(atlas, "C:\\Windows\\Fonts\\arial.ttf", 24.0f, NULL, ImFontAtlas_GetGlyphRangesCyrillic(atlas));


	// int font_md3_size = (int)((intptr_t)_binary_md3_ttf_end - (intptr_t)_binary_md3_ttf_start);
	// if (font_md3_size != 0){
	// 	ImFontAtlas_AddFontFromMemoryTTF(atlas, _binary_md3_ttf_start, font_md3_size, 24.0f, &icons_config, mdi_ranges);	
	// }
	
	ImGuiStyle* s = igGetStyle();
	s->Colors[ImGuiCol_Button] = ImVec4(0.18f, 0.19f, 0.21f, 1.0f);
	s->Colors[ImGuiCol_ButtonHovered] = ImVec4(0.094f, 0.094f, 0.094f, 1.0f);
	s->Colors[ImGuiCol_ButtonActive] = ImVec4(0.0f, 0.45f, 0.82f, 1.0f);
	s->Colors[ImGuiCol_WindowBg] = ImVec4(0.18f, 0.19f, 0.21f, 1.0f);
	s->Colors[ImGuiCol_FrameBgActive] = ImVec4(0.13f, 0.14f, 0.15f, 1.0f);
	s->Colors[ImGuiCol_FrameBg] = ImVec4(0.18f, 0.19f, 0.21f, 1.0f);
	s->Colors[ImGuiCol_CheckMark] = ImVec4(0.13f, 0.14f, 0.15f, 1.0f);
	s->Colors[ImGuiCol_SliderGrab] = ImVec4(0.13f, 0.14f, 0.15f, 1.0f);
	s->Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.13f, 0.14f, 0.15f, 1.0f);

	s->Colors[ImGuiCol_NavHighlight] = ImVec4(0.31f, 0.31f, 0.35f, 1.0f);
	
    cImGui_ImplWin32_Init(hwnd);
    cImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = {0.1f, 0.1f, 0.12f, 1.0f};
 
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        WSACleanup();
        return -1;
    }
	sqlite3_open("C:/Temp/db.db", &gm.db);
	BD_init(gm.db);
	
	//gm = bd_get_me(&gm);


	
	// ВРЕМЕННО
    // 
	//
	
	me m = {
		.name = "kopatyc",
		.uid = 0,
		.hash = NULL,
		.r = 8.0f,
		.ava_ptr = NULL,
		.ver = false,
		.obn = "25.08.2026-11:51",
		.bdu_uuid = "aaaa",
		
	};
	gm = m;
	
	
	zn_SetMicrophoneMute(false);
	
	if (gm.uid != 0 && gm.bdu_uuid != NULL && strlen(gm.bdu_uuid) ==36 ) {
		gm.reg = false;
		char* server_ip = V_gsip(YA_LINK);
		char* srat = V_lj("config.json", server_ip, gm.bdu_uuid, gm.uid);
		zn_Init(srat, server_ip, 443, 444, gm.uid);
		free(srat);
		free(server_ip);
		
	} else {
		gm.reg = true;
	}
	
	
    chat* chat_schas = NULL;
    user* usrs = NULL;
    chat* chats = NULL;
    uint16_t g_cid;
	msg msgs = {0};
	gm.r = 8.0f;
	ID3D11ShaderResourceView* aaa;
	int w_a, h_a;
	V_lifm(zipcord2, 52228, &aaa, &w_a, &h_a);
	// int w_a, h_a;
	// V_liff("zipcord2.png", &aaa, &w_a, &h_a);
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

		if(!gm.reg){
			zc_chat(x, y, chat_schas, &msgs, 0, usrs);
			zc_voice(x, y);
			zc_sw(x, y);
	    }
		if(gm.set){zc_settings(x, y);}
		if(gm.reg){zc_register(x, y, aaa);}
        igRender();

        g_pd3dDeviceContext->lpVtbl->OMSetRenderTargets(g_pd3dDeviceContext, 1, &g_mainRenderTargetView, NULL);
        float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->lpVtbl->ClearRenderTargetView(g_pd3dDeviceContext, g_mainRenderTargetView, clear_color_with_alpha);

        cImGui_ImplDX11_RenderDrawData(igGetDrawData());

        g_pSwapChain->lpVtbl->Present(g_pSwapChain, 1, 0);
        MsgWaitForMultipleObjects(0, NULL, FALSE, INFINITE, QS_ALLINPUT);
    }

    free(chat_schas);
	zn_Shutdown();
    cImGui_ImplDX11_Shutdown();
    cImGui_ImplWin32_Shutdown();
    igDestroyContext(NULL);
	BD_off();
	sqlite3_close(gm.db);
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
