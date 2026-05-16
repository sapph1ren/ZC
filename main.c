#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>

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

unsigned char* SERVER_IP;
#define SERVER_PORT    "65000"
#define SERVER_SNI     "ozon.ru"
#define REG_PATH       "Software\\CoreMessenger"
#define CHUNK_SIZE     16384         
#define AUDIO_RB_SIZE  48000 * 4


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

// -------- структуы --------
typedef enum { SOCK_TEXT, SOCK_SYSTEM, SOCK_MEDIA, SOCK_AUDIO } SocketType;

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

typedef struct {
    struct {
        SOCKET fd;
        WOLFSSL* ssl;
        bool active;
    } conn[SOCK_MAX];

    WOLFSSL_CTX* ssl_ctx;
    volatile bool running;
    
    ma_device audio_dev;
    OpusEncoder* enc;
    OpusDecoder* dec;
    float* ring_buffer;
    volatile int rb_write, rb_read;

    FILE* incoming_file;
    uint32_t file_bytes_left;
} ZC_Context;

static ZC_Context g_me = {0};

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
