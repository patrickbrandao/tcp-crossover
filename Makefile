NAME = tcp-crossover

CC = gcc
LD = gcc
CFLAGS = -Wall -I./
LDFLAGS = 
OBJS = tcp-crossover.o

BINDIR = /usr/bin
INSTALL = install
STRIP = strip
RM = /bin/rm -f
CP = cp

all: tcp-crossover

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

tcp-crossover: $(OBJS)
	@echo $(CC)
	$(LD) -o $(NAME) $(OBJS) $(LDFLAGS)

install:
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) -m 0755 $(NAME) $(BINDIR)
	$(STRIP) $(BINDIR)/$(NAME)

uninstall:
	$(RM) $(BINDIR)/$(NAME)

clean:
	$(RM) *.o *~ $(NAME) ../$(NAME)

