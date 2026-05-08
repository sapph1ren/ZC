#include <windows.h>
#include <d3d11.h>      
#include <d3dcompiler.h>
#include "dcimgui.h"
#include "dcimgui_impl_win32.h"
#include "dcimgui_impl_dx11.h"
#include <stdio.h>
#include <Windows.h>
#include <stdbool.h>

#include <tchar.h>
#include <tchar.h>

static ID3D11Device*            g_pd3dDevice = NULL;
static ID3D11DeviceContext*     g_pd3dDeviceContext = NULL;
static IDXGISwapChain*          g_pSwapChain = NULL;
static ID3D11RenderTargetView*  g_mainRenderTargetView = NULL;
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern LRESULT cImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void zc_chat(){
	
}

void zc_voice(){
	
}

void zc_sw(){
	
}

/*

бд функции

*/

/*

инет функци

*/




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

    igStyleColorsDark(NULL);

    cImGui_ImplWin32_Init(hwnd);
    cImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ImVec4 clear_color = { 0.45f, 0.55f, 0.60f, 1.00f };
	
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
