CC	     = gcc-9
CFLAGS   = -Wall
LDFLAGS  = -lpthread -lm
OBJFILES = brute_force.o hash.o printstate.o
TARGET   = ascon_exe

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~
