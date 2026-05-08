# ZC
fast and private messenger in pure C with imgui

## `this version is Windows-only!`

Zipcord is a lightweight and private messenger written in pure C using Dear ImGui for the graphical interface. The project is focused on maximum performance, minimal resource consumption, and cryptographic data protection.

## Tech stack 

* Language: C17 / C++ (for ImGui bindings)
* GUI: Dear ImGui (DirectX 11 backend)
* Cryptography: wolfSSL & SHA-512 
* Database: SQLite3 
* Utilities: STB (image, resize, write) for working with images.
* Audio: miniaudio

## Get started

1. Clone the repo
   
   `git clone https://github.com/sapph1ren/ZC cd ZC`
   
2. Compile it (Windows-only)

  `make -s run`

3.  Enjoy

## Smth

.exe is ~500kb (strip&upx)

.exe in RAM: ~30Mb

   
