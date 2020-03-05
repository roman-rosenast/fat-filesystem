CC	=	gcc
SHELL	=	/bin/sh
CFLAGS	=	-g -Og $(PKGFLAGS)

PKGFLAGS	=	`pkg-config fuse --cflags --libs`
TARGET 	= fat

# build an executable named myprog from myprog.c
all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)
	