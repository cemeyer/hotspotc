CC?=gcc
TUNEFLAGS?=-mtune=generic
SRCS=hotspotc.c
OBJS=$(SRCS:.c=.o)

CFLAGS=-Wall -W -fPIC -fvisibility=hidden -D_POSIX_C_SOURCE=200112L -Wno-format-extra-args
OPTFLAGS=-O2 -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fexceptions --param=ssp-buffer-size=4 -grecord-gcc-switches $(TUNEFLAGS)
# If old GCC, 'make EXTRAOPTFLAGS='.
EXTRAOPTFLAGS?=-fstack-protector-strong

FLAGS=$(CFLAGS) $(OPTFLAGS) $(EXTRAOPTFLAGS)

hotspotc: $(OBJS)
	$(CC) $(FLAGS) $^ -o "$@"

%.o: %.c
	$(CC) $(FLAGS) -c "$<"
