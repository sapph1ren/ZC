TARGET = Zipcord.exe
CC = ccache gcc

CFLAGS = -std=c17 -O3 -fno-plt -ffunction-sections -fdata-sections -fno-ident -fstack-protector-strong -DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -w -DNDEBUG -I.

SRC = main.c sqlite3.c
OBJS = main.o sqlite3.o

STATIC_OBJS = museo.o 5.obj 4.obj

LIBS = -L./a/ -ldcig -lwolfssl -lopus -lz -ld3d11 -ld3dcompiler -ldxgi -ldxguid \
       -luser32 -lgdi32 -lshell32 -lws2_32 -ladvapi32 -lmsimg32 -lsetupapi -limm32 -lm -lssp \
       -lcrypt32 -ldwmapi -lstdc++ -lwinmm -lole32

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
