CC		 = gcc-9
CFLAGS   = -Wall
LDFLAGS  = -lpthread -lm
OBJFILES = spongent.o
TARGET   = attack_exe

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~
