all: main.c wwan_monitor.c settings.c umtsd wan_monitor

umtsd: main.o settings.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

wan_monitor: wwan_monitor.o settings.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@
