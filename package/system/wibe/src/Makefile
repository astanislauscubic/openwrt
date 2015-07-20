all: main.c wwan_monitor.c settings.c umtsd wan_monitor download_data download_data.c

umtsd: main.o settings.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

wan_monitor: wwan_monitor.o settings.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

download_data: download_data.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@
