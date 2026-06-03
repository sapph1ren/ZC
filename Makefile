TARGET = Zipcord.exe
CC = ccache gcc

A_INC = /a/ 
WOLFSSL_LIB = wolfssl
DCIMGUI_LIB = dcig
ZLIB_LIB = z
# -flto
CFLAGS = -std=c17 -O3 -s -fno-plt -ffunction-sections -fdata-sections -fno-ident -fstack-protector-strong -DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DNDEBUG -I.

SRC = main.c sqlite3.c
OBJS = $(SRC:.c=.o) museo.o 5.obj 4.obj

LIBS = -L./a/ -ldcig -lwolfssl -lopus -lz -ld3d11 -ld3dcompiler -ldxgi -ldxguid \
       -luser32 -lgdi32 -lshell32 -lws2_32 -lmsimg32 -lsetupapi -limm32 -lm -lssp \
       -lcrypt32 -ldwmapi -lstdc++ -lwinmm -lole32


LDFLAGS = -Wl,--gc-sections -Wl,--as-needed -static-libgcc -static-libstdc++ -mwindows # -flto

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)
	strip $(TARGET)
#	upx --best --ultra-brute $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	del /q $(TARGET)
	del /q *.o

.PHONY: all run clean
