SOURCES=main.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=umtsd

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@
