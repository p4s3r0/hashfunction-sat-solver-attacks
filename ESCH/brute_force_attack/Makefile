CC		 = gcc-9
CFLAGS   = -Wall
LDFLAGS  = -lpthread -lm
OBJFILES = brute_force.o hash.o sparkle_ref.o
TARGET   = attack_exe

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~
