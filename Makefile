TARGET = Zipcord.exe
CC = ccache gcc

WOLFSSL_INC = -I. 
WOLFSSL_LIB = libwolfssl.a
DCIMGUI_LIB = libdcig.a
GLFW_LIB = libglfw3.a

CFLAGS = -std=c17 -O3 -s -flto -fno-plt -ffunction-sections -fdata-sections -fno-ident -fstack-protector-strong -DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DWOLFSSL_USER_SETTINGS $(WOLFSSL_INC)
		
SRC = main.c sqlite3.c SHA512.c
OBJS = $(SRC:.c=.o) 5.obj 4.obj

LIBS = $(DCIMGUI_LIB) $(WOLFSSL_LIB) -ld3d11 -ld3dcompiler -ldxgi -ldxguid -luser32 -lgdi32 -lshell32 -lws2_32 -lmsimg32 -lsetupapi -limm32 -lssp -lcrypt32 -ldwmapi -lstdc++


LDFLAGS = -Wl,--gc-sections -Wl,--as-needed -static-libgcc -static-libstdc++ -mwindows -flto

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)
	strip $(TARGET)
	upx --best --ultra-brute $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	@if exist $(TARGET) del /q $(TARGET)
	@if exist *.o del /q *.o

.PHONY: all run clean
