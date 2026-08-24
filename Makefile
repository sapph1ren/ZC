TARGET = Zipcord.exe
CC = gcc

CFLAGS = -std=c17 -O3 -flto=8 -fno-plt -ffunction-sections -fdata-sections -fno-ident -fstack-protector-strong -DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -Wimplicit-function-declaration -Wincompatible-pointer-types -w -DNDEBUG -I. -I./wolfssl -DWOLFSSL_USER_SETTINGS


SRC = main.c

STATIC_OBJS =  md3.o museo.o 5.obj 4.obj sqlite3.o r.o

OBJS = $(SRC:.c=.o)

LIBS = -L./a -ldcig -lzipnet -lwolfssl -lopus -lz -ld3d11 -ld3dcompiler -ldxgi -ldxguid \
       -luser32 -lgdi32 -lshell32 -lws2_32 -ladvapi32 -lmsimg32 -lsetupapi -limm32 -lm -lssp \
       -lcrypt32 -ldwmapi -lstdc++ -lpthread -lm -ldl -lwinmm -lole32 -luuid

LDFLAGS = -w -flto=8 -Wl,--gc-sections -Wl,--as-needed -static-libgcc -static-libstdc++ -mwindows


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(STATIC_OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)
	strip $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)


clean:
	del /q $(TARGET)
	del /q $(OBJS)

.PHONY: all run clean
