#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <glib.h>
#include <glib-object.h>
#include <locale.h>

#include <libqmi-glib.h>

// Exit codes
#define QMI_ERROR 12

#define QMI_TIMEOUT 10

static void qmi_error(void)
{
  exit(QMI_ERROR);
};

static void stop_network(void);
static void start_network(void);

static GCancellable *cancellable;
static QmiDevice *device;
static QmiClientDms *dms_client;
static QmiClientNas *nas_client;
static QmiClientWds *wds_client;
static QmiClientUim *uim_client;
static QmiClient *ctl_client;

struct QmiSettings {
  char proto[8];
  char device[128];
  char pincode[32];
  char modes[16];
  char antenna[16];
  int regtimeout;
  int settlewait;
};
static struct QmiSettings qmi_settings;

static void print_settings(void)
{
  fprintf(stderr, "Protocol:    %s\n", qmi_settings.proto);
  fprintf(stderr, "Device:      %s\n", qmi_settings.device);
  fprintf(stderr, "Pincode:     %s\n", qmi_settings.pincode);
  fprintf(stderr, "Modes:       %s\n", qmi_settings.modes);
  fprintf(stderr, "Antenna:     %s\n", qmi_settings.antenna);
  fprintf(stderr, "Reg Timeout: %d\n", qmi_settings.regtimeout);
  fprintf(stderr, "Settle Wait: %d\n", qmi_settings.settlewait);
}

static void snmp_write_string(FILE *snmpfile, const char *key, const char *value)
{
  assert(snmpfile);
  assert(key);
  if (!value)
    return;

  fprintf(snmpfile, "%s=\"%s\"\n", key, value);
}

static void snmp_write_int(FILE *snmpfile, const char *key, int value)
{
  assert(snmpfile);
  assert(key);
  fprintf(snmpfile, "%s=\"%d\"\n", key, value);
}

enum SignalType {
  TypeLte,
  TypeWcdma,
  TypeCount,
  TypeUnknown = TypeCount
};

static const char *SignalTypeText[] = {
  [TypeLte] = "LTE",
  [TypeWcdma] = "WCDMA",
  [TypeUnknown] = "Unknown"
};

struct ApnItem {
  const char* apn;
  const char* username;
  const char* password;
  struct ApnItem *next;
};
static struct ApnItem *apn_list = NULL;

// Explicit numbers to match entries in WIBE SNMP MIB
enum SimStatus {
   SimOk = 0,
   SimFailure = 1,
   SimUnknown = 2,
   NoSim = 3,
   SimPinIncorrect = 4,
   SimPinRequired = 5,
   SimPukRequired = 6,
   SimPin2Required = 7,
   SimPuk2Required = 8,
   SimBusy = 9
};

static const char *SimStatusText[] = {
  [SimOk] = "SIM OK",
  [SimFailure] = "SIM Failure",
  [SimUnknown] = "Sim Status Unknown",
  [NoSim] = "No SIM Present",
  [SimPinIncorrect] = "SIM PIN Incorrect",
  [SimPinRequired] = "SIM PIN Required",
  [SimPukRequired] = "SIM PUK Required",
  [SimPin2Required] = "SIM PIN2 Required",
  [SimPuk2Required] = "SIM PUK2 Required",
  [SimBusy] = "SIM Busy"
};

enum Registration {
  NoService = 0,
  HomeNetwork = 1,
  Searching = 2,
  RegistrationDenied = 3,
  RegistrationProblem = 4,
  RoamingNetwork = 5
};

static const char *RegistrationText[] = {
  [NoService] = "No Service",
  [HomeNetwork] = "Home Network",
  [Searching] = "Searching",
  [RegistrationDenied] = "Registration Denied",
  [RegistrationProblem] = "Registration Problem",
  [RoamingNetwork] = "Roaming Network",
};

enum Antenna {
  FrontBeam = 0,
  BackBeam = 1,
  LeftBeam = 2,
  RightBeam = 3,
  BeamCount,
  UnknownBeam = BeamCount
};

static const char *AntennaText[] = {
  [FrontBeam] = "front",
  [BackBeam] = "back",
  [LeftBeam] = "left",
  [RightBeam] = "right",
  [UnknownBeam] = "unknown"
};

struct AntennaResult {
  bool test_complete;
  struct tm test_time;
  enum SignalType type;
  uint8_t antenna;
  //LAC
  //CID
  int rssi;
  union {
    struct {
      int ecio;
    };
    struct {
      int rsrq;
      int rsrp;
      int snr;
    };
  };
};

struct QmiStatus {
  const char *imei;
  const char *imsi;
  const char *msisdn;
  int cid;
  int lac;
  enum SimStatus sim_status;
  enum Registration wan_status;
  enum Antenna active_antenna;
  enum SignalType signal_type;
  QmiWdsConnectionStatus packet_status;
  uint32_t packet_data_handle;
  int rssi;
  struct AntennaResult antenna_stats;
  struct ApnItem *apn;
  bool changed;
  time_t registration_start;
};
static struct QmiStatus qmi_status;

#define SET_STATUS(field, value) if (qmi_status.field != value) { qmi_status.field = value; qmi_status.changed = true; }

static void qmi_clear_status(void)
{
  qmi_status.imei = NULL;
  qmi_status.imsi = NULL;
  qmi_status.msisdn = NULL;

  qmi_status.sim_status = SimUnknown;
  qmi_status.wan_status = NoService;
  qmi_status.active_antenna = UnknownBeam;
  qmi_status.signal_type = TypeUnknown;

  qmi_status.antenna_stats.test_complete = false;

  qmi_status.apn = NULL;

  qmi_status.changed = true;

  qmi_status.packet_data_handle = 0xffffffff;
}

static void luci_write_status(void)
{
  FILE *lucifile = fopen("/tmp/wibe_luci", "w");

  fprintf(lucifile, "local qmi={}\n");
  fprintf(lucifile, "qmi.service=\"%s\"\n", SignalTypeText[qmi_status.signal_type]);
  fprintf(lucifile, "qmi.imsi=\"%s\"\n", qmi_status.imsi);
  fprintf(lucifile, "qmi.imei=\"%s\"\n", qmi_status.imei);
  fprintf(lucifile, "qmi.msisdn=\"%s\"\n", qmi_status.msisdn);
  fprintf(lucifile, "qmi.antenna=\"%s\"\n", AntennaText[qmi_status.active_antenna]);
  fprintf(lucifile, "qmi.rssi=\"%d\"\n", qmi_status.antenna_stats.rssi);
  if (qmi_status.signal_type == TypeLte)
  {
    fprintf(lucifile, "qmi.ecio=\"N/A\"\n");
    fprintf(lucifile, "qmi.rsrp=\"%d\"\n", qmi_status.antenna_stats.rsrp);
    fprintf(lucifile, "qmi.rsrq=\"%d\"\n", qmi_status.antenna_stats.rsrq);
    fprintf(lucifile, "qmi.snr=\"%d\"\n", qmi_status.antenna_stats.snr);
  }
  else if (qmi_status.signal_type == TypeWcdma)
  {
    fprintf(lucifile, "qmi.ecio=\"%d\"\n", qmi_status.antenna_stats.ecio);
    fprintf(lucifile, "qmi.rsrp=\"N/A\"\n");
    fprintf(lucifile, "qmi.rsrq=\"N/A\"\n");
    fprintf(lucifile, "qmi.snr=\"N/A\"\n");
  }
  fprintf(lucifile, "return qmi\n");


  fclose(lucifile);
}

static void snmp_write_status(void)
{
  if (!qmi_status.changed)
    return;

  luci_write_status();
  FILE *snmpfile = fopen("/tmp/wibe_snmp", "w");
  assert(snmpfile);

  snmp_write_string(snmpfile, "1S10.0", qmi_status.imei);
  snmp_write_string(snmpfile, "1S14.0", qmi_status.imsi);
  snmp_write_string(snmpfile, "1S17.0", qmi_status.msisdn);

  if (qmi_status.apn)
  {
    snmp_write_string(snmpfile, "1S2151.0", qmi_status.apn->apn);
    snmp_write_string(snmpfile, "1S2152.0", qmi_status.apn->username);
    snmp_write_string(snmpfile, "1S2153.0", qmi_status.apn->password);
  }

  snmp_write_int(snmpfile, "1S12.0", qmi_status.sim_status);
  snmp_write_string(snmpfile, "1S11.0", SimStatusText[qmi_status.sim_status]);

  snmp_write_string(snmpfile, "1S13.0", AntennaText[qmi_status.active_antenna]);

  snmp_write_int(snmpfile, "1S259.0", qmi_status.wan_status);
  snmp_write_string(snmpfile, "1S258.0", RegistrationText[qmi_status.wan_status]);

  if (qmi_status.antenna_stats.test_complete)
  {
    struct AntennaResult *result = &qmi_status.antenna_stats;
    snmp_write_int(snmpfile, "1S261.0", result->rssi);
    if (qmi_status.signal_type == TypeLte)
    {
      snmp_write_int(snmpfile, "1S265.0", result->rsrp);
      snmp_write_int(snmpfile, "1S266.0", result->rsrq);
      snmp_write_int(snmpfile, "1S267.0", result->snr);
    }
    else if (qmi_status.signal_type == TypeWcdma)
    {
      snmp_write_int(snmpfile, "1S262.0", result->ecio);
    }
  }

  snmp_write_string(snmpfile, "1S264.0", SignalTypeText[qmi_status.signal_type]);

  snmp_write_int(snmpfile, "1S773.0", qmi_status.cid);
  snmp_write_int(snmpfile, "1S774.0", qmi_status.lac);

  fclose(snmpfile);

  qmi_status.changed = false;
}

static int uci_get_string(const char *key, char *value, size_t len)
{
  struct uci_context *c;
  struct uci_ptr p;
  char *a = strdup(key);

  c = uci_alloc_context();
  if (uci_lookup_ptr(c, &p, a, true) != UCI_OK) {
      syslog(LOG_ERR, "UCI setting not found: %s", value);
      free(a);
      return -1;
  }

  if (p.o)
    snprintf(value, len, "%s", p.o->v.string);
  else
    value[0] = '\0';

  uci_free_context (c);

  free(a);
  return strlen(value);
}

static void uci_get_int_default(const char *key, int *value, int def)
{
  char buf[64];
  int ret = uci_get_string(key, buf, sizeof(buf));
  *value = (ret>0) ? atoi(buf) : def;
}

static void uci_get_string_default(const char *key, char *value, size_t len, const char *def)
{
  int ret = uci_get_string(key, value, len);
  if (ret < 0)
    snprintf(value, len, "%s", def);
}

static int load_settings(void)
{
  if (!uci_get_string("network.wan.proto", qmi_settings.proto,
                      sizeof(qmi_settings.proto)))
    return 0;
  if (strcmp(qmi_settings.proto, "qmi"))
    return 0;
  if (!uci_get_string("network.wan.device", qmi_settings.device,
                      sizeof(qmi_settings.device)))
    return 0;
  uci_get_string_default("network.wan.pincode", qmi_settings.pincode,
                         sizeof(qmi_settings.pincode), "");
  uci_get_string_default("network.wan.modes", qmi_settings.modes,
                         sizeof(qmi_settings.modes), "detect");
  uci_get_string_default("network.wan.antenna", qmi_settings.antenna,
                         sizeof(qmi_settings.antenna), "detect");
  uci_get_int_default("network.wan.regtimeout", &qmi_settings.regtimeout, 60);
  uci_get_int_default("network.wan.settlewait", &qmi_settings.settlewait, 10);
  return 1;
}

static bool modem_is_present(void)
{
  struct stat device_stat;
  lstat(qmi_settings.device, &device_stat);
  return S_ISCHR(device_stat.st_mode);
}

static void uqmi_power(bool powerOn)
{
  int fd = open("/sys/class/gpio/gpio10/value", O_WRONLY);
  if (fd < 0)
  {
    syslog(LOG_ERR, "Failed to open modem reset GPIO");
    exit(1);
  }

  if (write(fd, (powerOn) ? "1" : "0", 1) != 1)
  {
    syslog(LOG_ERR, "Failed to write modem reset GPIO (0)");
  }

  close(fd);
}

static void uqmi_reset(void)
{
  uqmi_power(false);
  sleep(1);
  uqmi_power(true);

  while (!modem_is_present())
    sleep(1);
}

static bool sim_is_present(void)
{
  int fd = open("/sys/class/gpio/gpio8/value", O_RDONLY);
  if (fd < 0)
  {
    syslog(LOG_ERR, "Failed to open card detect GPIO");
    return false;
  }

  char gpio_str[3];
  if (read(fd, gpio_str, 3) < 0)
  {
    syslog(LOG_ERR, "Failed to read card detect GPIO");
    close(fd);
    return false;
  }

  close(fd);

  return atoi(gpio_str) == 1;
}

static void led_3g_red(bool on)
{
  int fd, bytes;
  const char filename[] = "/sys/class/leds/wibe:3g:red/trigger";
  fd = open(filename, O_WRONLY);
  assert(fd);
  if (on)
  {
    bytes = write(fd, "default-on", 10);
    assert(bytes == 10);
  }
  else
  {
    bytes = write(fd, "none", 4);
    assert(bytes == 4);
  }
  close(fd);
}

static void antenna_select(uint8_t beam, bool flash)
{
  int fd, bytes;

  char antenna_name[10];
  fd = open("/sys/devices/wibe-antenna.4/antenna", O_WRONLY);
  assert(fd);
  snprintf(antenna_name, sizeof(antenna_name), "%d", beam);
  bytes = write(fd, antenna_name, strlen(antenna_name));
  assert(bytes > 0);
  close(fd);

  SET_STATUS(active_antenna, beam);
}

static void antenna_led_off(void)
{
  const char *colours[] = {"red", "green"};
  for (int c = 0; c < 2; ++c)
  {
    for (int i = 0; i < 4; ++i)
    {
      char filename[128];
      snprintf(filename, 128, "/sys/class/leds/wibe:%s:%s/trigger", AntennaText[i], colours[c]);
      int fd = open(filename, O_WRONLY);
      assert(fd);
      int bytes = write(fd, "none", 4);
      assert(bytes == 4);
      close(fd);
    }
  }
}

static void antenna_led_searching(void)
{
  int fd, bytes;
  char antenna_name[10];

  antenna_led_off();

  fd = open("/sys/devices/wibe-antenna.4/antenna", O_RDONLY);
  assert(fd);
  bytes = read(fd, &antenna_name, 10);
  assert(bytes > 0);
  antenna_name[bytes-1] = '\0'; // Remove \n
  close(fd);

  char filename[128];
  snprintf(filename, 128, "/sys/class/leds/wibe:%s:red/trigger", antenna_name);
  fd = open(filename, O_WRONLY);
  assert(fd);
  bytes = write(fd, "heartbeat", strlen("heartbeat"));
  assert(bytes > 0);
  close(fd);
}

void antenna_led_testing(bool isLTE)
{
  int fd, bytes;
  char antenna_name[10];
  char filename[128];

  antenna_led_off();

  fd = open("/sys/devices/wibe-antenna.4/antenna", O_RDONLY);
  assert(fd);
  bytes = read(fd, &antenna_name, 10);
  assert(bytes > 0);
  antenna_name[bytes-1] = '\0'; // Remove \n
  close(fd);

  if (!isLTE)
  {
    snprintf(filename, 128, "/sys/class/leds/wibe:%s:red/trigger", antenna_name);
    fd = open(filename, O_WRONLY);
    assert(fd);
    bytes = write(fd, "heartbeat", strlen("heartbeat"));
    assert(bytes > 0);
    close(fd);
  }

  snprintf(filename, 128, "/sys/class/leds/wibe:%s:green/trigger", antenna_name);
  fd = open(filename, O_WRONLY);
  assert(fd);
  bytes = write(fd, "heartbeat", strlen("heartbeat"));
  assert(bytes > 0);
  close(fd);
}

static void antenna_led_selected(bool isLTE)
{
  int fd, bytes;
  char antenna_name[10];
  char filename[128];

  antenna_led_off();

  fd = open("/sys/devices/wibe-antenna.4/antenna", O_RDONLY);
  assert(fd);
  bytes = read(fd, &antenna_name, 10);
  assert(bytes > 0);
  antenna_name[bytes-1] = '\0'; // Remove \n
  close(fd);

  if (!isLTE)
  {
    snprintf(filename, 128, "/sys/class/leds/wibe:%s:red/trigger", antenna_name);
    fd = open(filename, O_WRONLY);
    assert(fd);
    bytes = write(fd, "default-on", strlen("default-on"));
    assert(bytes > 0);
    close(fd);
  }

  snprintf(filename, 128, "/sys/class/leds/wibe:%s:green/trigger", antenna_name);
  fd = open(filename, O_WRONLY);
  assert(fd);
  bytes = write(fd, "default-on", strlen("default-on"));
  assert(bytes > 0);
  close(fd);
}

#define ANTENNAS 4
static struct AntennaResult antenna_results[TypeCount][ANTENNAS];

static void antenna_reset(void)
{
  for (size_t type = 0; type < TypeCount; ++type)
    for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
    {
      memset(&antenna_results[type][antenna], 0, sizeof(struct AntennaResult));
      antenna_results[type][antenna].test_complete = false;
    }
}

struct AntennaResult *antenna_max(struct AntennaResult *a,
                                  struct AntennaResult *b)
{
  if (!a && !b)
    return NULL;
  if ((!a || !a->test_complete) && b)
    return b;
  if ((!b || !b->test_complete) && a)
    return a;

  if (a->rssi > b->rssi)
    return a;
  if (b->rssi > a->rssi)
    return b;

  if (a->type == b->type && a->type == TypeWcdma)
  {
    if (a->ecio > b->ecio)
      return a;
    if (b->ecio > a->ecio)
      return b;
  }

  if (a->type == b->type && a->type == TypeLte)
  {
    if (a->rsrp > b->rsrp)
      return a;
    if (b->rsrp > a->rsrp)
      return b;
  }

  if (a->type == TypeLte)
    return a;
  if (b->type == TypeLte)
    return b;

  syslog(LOG_WARNING, "Returning default in antenna_max");
  return a;
}

static const struct AntennaResult *antenna_find_best(void)
{
  struct AntennaResult *best = NULL;
  for (size_t type = 0; type < TypeCount; ++type)
    for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
      best = antenna_max(best, &antenna_results[type][antenna]);
  return best;
}

static void antenna_log(const struct AntennaResult *const result)
{
  if (!result->test_complete)
    return;
  if (result->type == TypeLte)
      syslog(LOG_INFO, "LTE:%s RSSI:%d RSRQ:%d RSRP:%d SNR:%d",
             AntennaText[result->antenna], result->rssi, result->rsrq,
             result->rsrp, result->snr);
  else if (result->type == TypeWcdma)
      syslog(LOG_INFO, "WCDMA:%s RSSI:%d ECIO:%d",
             AntennaText[result->antenna], result->rssi, result->ecio);
}

static void modem_disconnect(void)
{
  stop_network();
}

static void sig_handler(int sig)
{
  if (sig == SIGINT)
  {
    syslog(LOG_ERR, "SIGINT: Disconnecting...");
    modem_disconnect();
    exit(0);
  }
  else if (sig == SIGUSR1)
  {
    syslog(LOG_ERR, "SIGUSR1: Reloading...");
  }
  else if (sig == SIGUSR2)
  {
    syslog(LOG_ERR, "SIGUSR2: N/A");
  }
}

static void net_renew_lease(void)
{
  int fd = open("/var/run/udhcpc-wwan0.pid", O_RDONLY);
  if (fd < 0)
  {
    syslog(LOG_ERR, "Failed to open udhcpc-wwan0.pid");
    return;
  }

  char udhcpc_pid[8] = {0};
  ssize_t bytes = read(fd, udhcpc_pid, sizeof(udhcpc_pid));
  if (bytes < 0)
  {
    syslog(LOG_ERR, "Failed to read udhcpc PID: %m");
    close(fd);
    return;
  }
  assert(bytes < (sizeof(udhcpc_pid) - 1));
  udhcpc_pid[bytes-1] = 0;

  close(fd);

  char cmd[128];
  // Release lease
  snprintf(cmd, sizeof(cmd), "kill -s SIGUSR2 \"%s\"", udhcpc_pid);
  fprintf(stderr, "%s\n", cmd);
  system(cmd);
  // Renew lease
  snprintf(cmd, sizeof(cmd), "kill -s SIGUSR1 \"%s\"", udhcpc_pid);
  fprintf(stderr, "%s\n", cmd);
  system(cmd);
}

static const char* provider_get_value(struct uci_section *section, const char *name)
{
  struct uci_element *element;
  struct uci_option  *option;

  uci_foreach_element(&section->options, element)
  {
    if (element->type == UCI_TYPE_OPTION)
    {
      option = uci_to_option(element);
      if (!strcmp(name, element->name))
        return strdup(option->v.string);
    }
  }

  return NULL;
}

static bool provider_matches_imsi(struct uci_section *section, const char *imsi)
{
  struct uci_option  *option;
  struct uci_element *element, *list_el;

  uci_foreach_element(&section->options, element)
  {
    if (element->type == UCI_TYPE_OPTION)
    {
      option = uci_to_option(element);

      if (!strcmp(element->name, "network") && option->type == UCI_TYPE_LIST)
      {
        uci_foreach_element(&option->v.list, list_el)
        {
          if (strlen(list_el->name) > 0 && !strncmp(imsi, list_el->name, strlen(list_el->name)))
            return true;
        }
      }
      else if (!strcmp(element->name, "network") && option->type == UCI_TYPE_STRING)
      {
        if (strlen(option->v.string) > 0 && !strncmp(imsi, option->v.string, strlen(option->v.string)))
          return true;
      }
    }
  }

  return false;
}

static void sim_apn_add(struct ApnItem *apn)
{
  fprintf(stderr, "New APN: %s %s %s\n", apn->apn, apn->username, apn->password);
  if (!apn_list)
  {
    apn_list = apn;
    return;
  }

  struct ApnItem *last = apn_list;
  while (last && last->next)
    last = last->next;
  last->next = apn;
}

static void sim_apn_generate_list_from_section(const char* section_name)
{
  struct uci_context *context = NULL;
  struct uci_package *package;
  struct uci_section *section;
  struct uci_element *e;

  assert(qmi_status.imsi);

  context = uci_alloc_context();
  if (!context)
    return;

  if (uci_load(context, section_name, &package) != UCI_OK)
  {
    uci_free_context(context);
    return;
  }

  uci_foreach_element(&package->sections, e)
  {
    section = uci_to_section(e);

    if (provider_matches_imsi(section, qmi_status.imsi))
    {
      struct ApnItem *apn = malloc(sizeof(*apn));
      assert(apn);
      bzero(apn, sizeof(struct ApnItem));
      apn->apn = provider_get_value(section, "apn");
      apn->username = provider_get_value(section, "username");
      apn->password = provider_get_value(section, "password");
      sim_apn_add(apn);
    }
  }
}

static void sim_apn_generate_list(void)
{
  sim_apn_generate_list_from_section("myproviders");
  sim_apn_generate_list_from_section("providers");
}

static void log_handler(const gchar *log_domain, GLogLevelFlags log_level,
                        const gchar *message, gpointer user_data)
{
  switch (log_level) {
    case G_LOG_LEVEL_WARNING:
      syslog(LOG_WARNING, "%s", message);
      break;
    case G_LOG_LEVEL_CRITICAL:
    case G_LOG_FLAG_FATAL:
    case G_LOG_LEVEL_ERROR:
      syslog(LOG_ERR, "%s", message);
      break;
    case G_LOG_LEVEL_DEBUG:
      syslog(LOG_DEBUG, "%s", message);
      break;
    default:
      syslog(LOG_INFO, "%s", message);
      break;
  }
}

static void pin_status_ready(QmiClientDms *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsUimGetPinStatusOutput *status =
    qmi_client_dms_uim_get_pin_status_finish (client, res, &error);
  if (!status)
  {
    syslog(LOG_ERR, "Couldn't get DMS PIN Status: %s\n", error->message);
    exit(QMI_ERROR);
  }

  QmiDmsUimPinStatus pin1_status;
  guint8 verify_pin1_retries;
  guint8 unblock_pin1_retries;

  gboolean found =
    qmi_message_dms_uim_get_pin_status_output_get_pin1_status(status,
                                                              &pin1_status,
                                                              &verify_pin1_retries,
                                                              &unblock_pin1_retries,
                                                              &error);
  if (found)
  {
    // TODO: SNMP
    syslog(LOG_INFO, "PIN Status: %s", qmi_dms_uim_pin_status_get_string(pin1_status));
  }
  qmi_message_dms_uim_get_pin_status_output_unref(status);
}

static void system_selection_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasSetSystemSelectionPreferenceOutput *output = NULL;

  output = qmi_client_nas_set_system_selection_preference_finish(nas_client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish system selection preferences: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_nas_set_system_selection_preference_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to set operating mode: %s", error->message);
  }

  qmi_message_nas_set_system_selection_preference_output_unref(output);
}

static void nas_event_report_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasSetEventReportOutput *output = NULL;
  output = qmi_client_nas_set_event_report_finish(nas_client, res, &error);

  if (!output) {
    syslog(LOG_ERR, "Failed to finish nas report: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_nas_set_event_report_output_get_result(output, &error)) {
    syslog(LOG_ERR, "Failed to check nas report : %s", error->message);
    qmi_error();
  }

  if (output)
    qmi_message_nas_set_event_report_output_unref(output);
}

static void event_report_ready(QmiClientNas *object,
                               QmiIndicationNasEventReportOutput *output,
                               gpointer user_data)
{
  GError *error = NULL;

  uint8_t rssi;
  QmiNasRadioInterface interface;
  if (qmi_indication_nas_event_report_output_get_rssi(output, &rssi, &interface, &error))
  {
    syslog(LOG_INFO, "RSSI: %d (%s)", -rssi, qmi_nas_radio_interface_get_string(interface));
    if (interface == QMI_NAS_RADIO_INTERFACE_LTE)
      qmi_status.antenna_stats.type = TypeLte;
    else if (interface == QMI_NAS_RADIO_INTERFACE_UMTS)
      qmi_status.antenna_stats.type = TypeWcdma;
    else
    {
      qmi_status.antenna_stats.type = TypeUnknown;
      syslog(LOG_ERR, "Unexpected interface: %s", qmi_nas_radio_interface_get_string(interface));
    }
    if (qmi_status.signal_type == qmi_status.antenna_stats.type
        && qmi_status.wan_status == HomeNetwork
        && rssi != 0)
    {
      qmi_status.antenna_stats.rssi = -rssi;
      qmi_status.antenna_stats.test_complete = true;
    }
  }
  error = NULL;

  int16_t rsrp;
  if (qmi_indication_nas_event_report_output_get_lte_rsrp(output, &rsrp, &error))
  {
    syslog(LOG_INFO, "RSRP: %d", rsrp);
    qmi_status.antenna_stats.rsrp = rsrp;
  }
  error = NULL;

  int16_t snr;
  if (qmi_indication_nas_event_report_output_get_lte_snr(output, &snr, &error))
  {
    syslog(LOG_INFO, "SNR: %d", snr);
    qmi_status.antenna_stats.snr = snr;
  }
  error = NULL;

  int8_t rsrq;
  if (qmi_indication_nas_event_report_output_get_rsrq(output, &rsrq, &interface, &error))
  {
    syslog(LOG_INFO, "RSRQ: %d (%s)", rsrq, qmi_nas_radio_interface_get_string(interface));
    qmi_status.antenna_stats.rsrq = rsrq;
  }
  error = NULL;

  int8_t ecio;
  if (qmi_indication_nas_event_report_output_get_ecio(output, &ecio, &interface, &error))
  {
    syslog(LOG_INFO, "ECIO: %d (%s)", ecio, qmi_nas_radio_interface_get_string(interface));
    qmi_status.antenna_stats.ecio = ecio;
  }
  error = NULL;

  int8_t strength;
  if (qmi_indication_nas_event_report_output_get_signal_strength(output, &strength, &interface, &error))
  {
    syslog(LOG_INFO, "Strength: %d (%s)", strength, qmi_nas_radio_interface_get_string(interface));
  }
  error = NULL;
}

static void serving_system_indication_ready(QmiClientNas *object,
                                            QmiIndicationNasServingSystemOutput *output,
                                            gpointer user_data)
{
  QmiNasRegistrationState registration_state;
  QmiNasAttachState cs_attach_state;
  QmiNasAttachState ps_attach_state;
  QmiNasNetworkType selected_network;
  GArray *radio_interfaces;

  if (qmi_indication_nas_serving_system_output_get_serving_system
    (output, &registration_state, &cs_attach_state, &ps_attach_state,
     &selected_network, &radio_interfaces, NULL))
  {
    bool isValid = false;
    for (size_t i = 0; i < radio_interfaces->len; ++i)
    {
      QmiNasRadioInterface intf = g_array_index(radio_interfaces, QmiNasRadioInterface, i);
      syslog(LOG_INFO, "Network status for %d %s %s", intf, qmi_nas_radio_interface_get_string(intf), qmi_nas_registration_state_get_string(registration_state));
      if (intf == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte)
        isValid = true;
      else if (intf == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma)
        isValid = true;
    }

    if (isValid)
      switch (registration_state)
      {
        case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED:
          qmi_status.wan_status = NoService;
          break;
        case QMI_NAS_REGISTRATION_STATE_REGISTERED:
          qmi_status.wan_status = HomeNetwork;
          break;
        case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED_SEARCHING:
          qmi_status.wan_status = Searching;
          break;
        case QMI_NAS_REGISTRATION_STATE_REGISTRATION_DENIED:
          qmi_status.wan_status = RegistrationDenied;
          break;
        case QMI_NAS_REGISTRATION_STATE_UNKNOWN:
          qmi_status.wan_status = NoService;
          break;
      }
  }
}

static void serving_system_ready(QmiClientNas *client,
                                 GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasGetServingSystemOutput *output;
  output = qmi_client_nas_get_serving_system_finish(client, res, &error);

  QmiNasRegistrationState registration_state;
  QmiNasAttachState cs_attach_state;
  QmiNasAttachState ps_attach_state;
  QmiNasNetworkType selected_network;
  GArray *radio_interfaces;

  if (qmi_message_nas_get_serving_system_output_get_serving_system
    (output, &registration_state, &cs_attach_state, &ps_attach_state,
     &selected_network, &radio_interfaces, NULL))
  {
    bool isValid = false;
    for (size_t i = 0; i < radio_interfaces->len; ++i)
    {
      QmiNasRadioInterface intf = g_array_index(radio_interfaces, QmiNasRadioInterface, i);
      syslog(LOG_INFO, "Network status for %d %s %s", intf, qmi_nas_radio_interface_get_string(intf), qmi_nas_registration_state_get_string(registration_state));
      if (qmi_status.signal_type == TypeUnknown)
      {
        qmi_status.signal_type = (intf == QMI_NAS_RADIO_INTERFACE_LTE) ? TypeLte : TypeWcdma;
      }
      if (intf == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte)
        isValid = true;
      else if (intf == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma)
        isValid = true;
    }

    if (isValid)
      switch (registration_state)
      {
        case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED:
          qmi_status.wan_status = NoService;
          break;
        case QMI_NAS_REGISTRATION_STATE_REGISTERED:
          qmi_status.wan_status = HomeNetwork;
          break;
        case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED_SEARCHING:
          qmi_status.wan_status = Searching;
          break;
        case QMI_NAS_REGISTRATION_STATE_REGISTRATION_DENIED:
          qmi_status.wan_status = RegistrationDenied;
          break;
        case QMI_NAS_REGISTRATION_STATE_UNKNOWN:
          qmi_status.wan_status = NoService;
          break;
      }
  }
}

static void signal_info_ready(QmiClientNas *object,
                              QmiIndicationNasSignalInfoOutput *output,
                              gpointer user_data)
{
  GError *error = NULL;

  syslog(LOG_INFO, "Have signal info report");

  int8_t wcdma_signal_strength_rssi;
  int16_t wcdma_signal_strength_ecio;
  if (qmi_indication_nas_signal_info_output_get_wcdma_signal_strength(output,
                                                                      &wcdma_signal_strength_rssi,
                                                                      &wcdma_signal_strength_ecio,
                                                                      &error))
  {
    syslog(LOG_INFO, "RSSI: %d, ECIO: %d\n", wcdma_signal_strength_rssi,
           wcdma_signal_strength_ecio);
  }
  error = NULL;

  int8_t lte_signal_strength_rssi;
  int8_t lte_signal_strength_rsrq;
  int16_t lte_signal_strength_rsrp;
  int16_t lte_signal_strength_snr;
  if (qmi_indication_nas_signal_info_output_get_lte_signal_strength
      (output, &lte_signal_strength_rssi, &lte_signal_strength_rsrq,
       &lte_signal_strength_rsrp, &lte_signal_strength_snr, &error))
  {
    syslog(LOG_INFO, "RSSI: %d, RSRQ: %d, RSRP: %d, SNR: %d\n", lte_signal_strength_rssi,
           lte_signal_strength_rsrq, lte_signal_strength_rsrp, lte_signal_strength_snr);
  }
  error = NULL;
}

static void system_info_ready(QmiClientNas *object,
                              QmiIndicationNasSystemInfoOutput *output,
                              gpointer user_data)
{
  syslog(LOG_INFO, "Have system info report");
}

static void nas_set_mode(enum SignalType type)
{
  GError *error = NULL;

  QmiMessageNasSetSystemSelectionPreferenceInput *input;
  input = qmi_message_nas_set_system_selection_preference_input_new();

  if (type == TypeLte)
  {
    syslog(LOG_INFO, "Setting mode to LTE");
    qmi_message_nas_set_system_selection_preference_input_set_mode_preference
      (input, QMI_NAS_RAT_MODE_PREFERENCE_LTE, &error);
    qmi_status.signal_type = TypeLte;
  }
  else if (type == TypeWcdma)
  {
    syslog(LOG_INFO, "Setting mode to WCDMA");
    qmi_message_nas_set_system_selection_preference_input_set_mode_preference
      (input, QMI_NAS_RAT_MODE_PREFERENCE_UMTS, &error);
    qmi_status.signal_type = TypeWcdma;
  }
  qmi_status.wan_status = NoService;

  qmi_client_nas_set_system_selection_preference
    (nas_client, input, 10, cancellable,
     (GAsyncReadyCallback)system_selection_ready, NULL);

  qmi_message_nas_set_system_selection_preference_input_unref (input);
}

static void setup_nas(void)
{
  GError *error = NULL;

  {
    g_signal_connect(nas_client, "event-report", G_CALLBACK(event_report_ready), NULL);
    g_signal_connect(nas_client, "serving-system", G_CALLBACK(serving_system_indication_ready), NULL);
    g_signal_connect(nas_client, "signal-info", G_CALLBACK(signal_info_ready), NULL);
    g_signal_connect(nas_client, "system-info", G_CALLBACK(system_info_ready), NULL);
  }

  {
    QmiMessageNasSetSystemSelectionPreferenceInput *input;
    input = qmi_message_nas_set_system_selection_preference_input_new();

    /*qmi_message_nas_set_system_selection_preference_input_set_change_duration*/
      /*(input, QMI_NAS_CHANGE_DURATION_PERMANENT, &error);*/

    qmi_message_nas_set_system_selection_preference_input_set_lte_band_preference
      (input, QMI_NAS_LTE_BAND_PREFERENCE_EUTRAN_3, &error);

    qmi_message_nas_set_system_selection_preference_input_set_band_preference
      (input, QMI_NAS_BAND_PREFERENCE_WCDMA_2100, &error);

    qmi_client_nas_set_system_selection_preference
      (nas_client, input, 10, cancellable,
       (GAsyncReadyCallback)system_selection_ready, NULL);

    qmi_message_nas_set_system_selection_preference_input_unref (input);
  }

  {
    QmiMessageNasSetEventReportInput *input;
    input = qmi_message_nas_set_event_report_input_new ();

    static const gint8 thresholds_data[] = { -70, -50, -30, -10, 10 };
    GArray *thresholds;
    thresholds = g_array_sized_new(FALSE, FALSE, sizeof (gint8), G_N_ELEMENTS(thresholds_data));
    g_array_append_vals (thresholds, thresholds_data, G_N_ELEMENTS (thresholds_data));

    qmi_message_nas_set_event_report_input_set_signal_strength_indicator
      (input, true, thresholds, NULL);

    qmi_message_nas_set_event_report_input_set_rssi_indicator
      (input, true, 0, &error);

    qmi_message_nas_set_event_report_input_set_ecio_indicator
      (input, true, 0, &error);

    qmi_client_nas_set_event_report
      (nas_client, input, 5, NULL, (GAsyncReadyCallback)nas_event_report_ready, NULL);

    qmi_message_nas_set_event_report_input_unref(input);
  }
}

static void imsi_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsUimGetImsiOutput *output = qmi_client_dms_uim_get_imsi_finish
    (dms_client, res, &error);
  if (!output) {
    syslog(LOG_ERR, "Couldn't finish imsi get: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_dms_uim_get_imsi_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to read IMSI: %s", error->message);
    qmi_message_dms_uim_get_imsi_output_unref(output);
    qmi_error();
  }
  const gchar *imsi = NULL;
  if (!qmi_message_dms_uim_get_imsi_output_get_imsi(output, &imsi, &error))
  {
    syslog(LOG_ERR, "Failed to extract IMSI: %s", error->message);
    qmi_message_dms_uim_get_imsi_output_unref(output);
    qmi_error();
  }
  qmi_status.imsi = strdup(imsi);
  qmi_message_dms_uim_get_imsi_output_unref(output);
}

static void msisdn_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetMsisdnOutput *output = qmi_client_dms_get_msisdn_finish
    (dms_client, res, &error);
  if (!output) {
    syslog(LOG_ERR, "Couldn't finish msisdn get: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_dms_get_msisdn_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to read MSISDN: %s", error->message);
    qmi_error();
  }
  const gchar *msisdn = NULL;
  if (!qmi_message_dms_get_msisdn_output_get_msisdn(output, &msisdn, &error))
  {
    syslog(LOG_ERR, "Failed to extract MSISDN: %s", error->message);
    qmi_error();
  }
  qmi_status.msisdn = strdup(msisdn);
  qmi_message_dms_get_msisdn_output_unref(output);
}

static void wds_settings_ready(QmiClientWds *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageWdsGetCurrentSettingsOutput *output;
  output = qmi_client_wds_get_current_settings_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish wds current settings: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_wds_get_current_settings_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to set operating mode (WDS): %s", error->message);
  }

  error = NULL;
  const gchar *apn_name = NULL;
  if (qmi_message_wds_get_current_settings_output_get_apn_name(output, &apn_name, &error))
  {
    syslog(LOG_INFO, "Current APN is %s", apn_name);
  }

  error = NULL;
  const gchar *username = NULL;
  if (qmi_message_wds_get_current_settings_output_get_username(output, &username, &error))
  {
    syslog(LOG_INFO, "Current username is %s", username);
  }

  qmi_message_wds_get_current_settings_output_unref(output);
}

static void setup_wds(void)
{
  QmiMessageWdsGetCurrentSettingsInput *input;
  input = qmi_message_wds_get_current_settings_input_new();

  QmiWdsGetCurrentSettingsRequestedSettings requested;
  requested = QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_SETTINGS_APN_NAME |
    QMI_WDS_GET_CURRENT_SETTINGS_REQUESTED_SETTINGS_USERNAME;

  qmi_message_wds_get_current_settings_input_set_requested_settings (input, requested, NULL);

  qmi_client_wds_get_current_settings
    (wds_client, input, QMI_TIMEOUT, cancellable, (GAsyncReadyCallback)wds_settings_ready, NULL);

  qmi_message_wds_get_current_settings_input_unref(input);
}

static void allocate_client_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiClient *client = qmi_device_allocate_client_finish(dev, res, &error);
  if (!client) {
    syslog(LOG_ERR, "Couldn't create client for service: %s\n", error->message);
    exit(QMI_ERROR);
  }

  QmiService service = qmi_client_get_service(client);

  switch (service) {
    case QMI_SERVICE_DMS:
      dms_client = QMI_CLIENT_DMS(client);
      syslog(LOG_INFO, "Requesting PIN Status");
      qmi_client_dms_uim_get_pin_status(dms_client, NULL, QMI_TIMEOUT,
                                        cancellable,
                                        (GAsyncReadyCallback)pin_status_ready,
                                        NULL);
      qmi_client_dms_uim_get_imsi(dms_client, NULL, QMI_TIMEOUT, cancellable,
                                  (GAsyncReadyCallback)imsi_ready, NULL);
      qmi_client_dms_get_msisdn(dms_client, NULL, QMI_TIMEOUT, cancellable,
                                    (GAsyncReadyCallback)msisdn_ready, NULL);
      return;
    case QMI_SERVICE_NAS:
      nas_client = QMI_CLIENT_NAS(client);
      setup_nas();
      return;
    case QMI_SERVICE_WDS:
      wds_client = QMI_CLIENT_WDS(client);
      setup_wds();
      return;
    case QMI_SERVICE_UIM:
      uim_client = QMI_CLIENT_UIM(client);
      return;
    case QMI_SERVICE_CTL:
      ctl_client = client;
      return;
    default:
      syslog(LOG_ERR, "Unknown service %d", service);
      g_assert_not_reached();
  }
}

static void device_open_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  if (!qmi_device_open_finish (dev, res, &error)) {
    syslog(LOG_ERR, "Couldn't open the QmiDevice: %s\n", error->message);
    uqmi_reset();
    qmi_error();
  }

  syslog(LOG_INFO, "QMI device ready");

  qmi_device_allocate_client(dev, QMI_SERVICE_UIM, QMI_CID_NONE, 10, cancellable,
                             (GAsyncReadyCallback)allocate_client_ready, NULL);
  qmi_device_allocate_client(dev, QMI_SERVICE_DMS, QMI_CID_NONE, 10, cancellable,
                             (GAsyncReadyCallback)allocate_client_ready, NULL);
  qmi_device_allocate_client(dev, QMI_SERVICE_NAS, QMI_CID_NONE, 10, cancellable,
                             (GAsyncReadyCallback)allocate_client_ready, NULL);
  qmi_device_allocate_client(dev, QMI_SERVICE_WDS, QMI_CID_NONE, 10, cancellable,
                             (GAsyncReadyCallback)allocate_client_ready, NULL);
}

static void device_new_ready(GObject *unused, GAsyncResult *res)
{
  GError *error = NULL;

  device = qmi_device_new_finish (res, &error);
  if (!device)
  {
    syslog(LOG_ERR, "Couldn't create QmiDevice: %s\n", error->message);
    exit(QMI_ERROR);
  }

  QmiDeviceOpenFlags flags = QMI_DEVICE_OPEN_FLAGS_SYNC |
    QMI_DEVICE_OPEN_FLAGS_NET_802_3 | QMI_DEVICE_OPEN_FLAGS_NET_NO_QOS_HEADER;

  qmi_device_open(device, flags, 15, cancellable,
                  (GAsyncReadyCallback)device_open_ready, NULL);
}

static void packet_service_status_ready(QmiClientWds *client, GAsyncResult *res)
{
  GError *error = NULL;
  QmiMessageWdsGetPacketServiceStatusOutput *output;
  output = qmi_client_wds_get_packet_service_status_finish(client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish service status: %s", error->message);
    return;
  }

  if (!qmi_message_wds_get_packet_service_status_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to get service status: %s", error->message);
    qmi_message_wds_get_packet_service_status_output_unref(output);
    qmi_error();
  }

  if (qmi_message_wds_get_packet_service_status_output_get_connection_status
      (output, &qmi_status.packet_status, &error))
  {
    syslog(LOG_INFO, "Packet status is: %s",
           qmi_wds_connection_status_get_string(qmi_status.packet_status));
  }

  qmi_message_wds_get_packet_service_status_output_unref(output);
}

static void start_network_ready(QmiClientWds *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageWdsStartNetworkOutput *output;
  output = qmi_client_wds_start_network_finish(client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish network start: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_wds_start_network_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to get network start: %s", error->message);
    error = NULL;
  }

  if (qmi_message_wds_start_network_output_get_packet_data_handle(output,
                                                                  &qmi_status.packet_data_handle,
                                                                  &error))
  {
    syslog(LOG_INFO, "Data handle: %d", qmi_status.packet_data_handle);
  }
  else
  {
    qmi_status.packet_data_handle = 0xffffffff;
    stop_network();
    apn_list = apn_list->next;
  }
  error = NULL;

  QmiWdsCallEndReason end_reason;
  if (qmi_message_wds_start_network_output_get_call_end_reason(output, &end_reason, &error))
  {
    syslog(LOG_INFO, "Call end reason: %s", qmi_wds_call_end_reason_get_string(end_reason));
  }
  error = NULL;

  QmiWdsVerboseCallEndReasonType v_reason_type;
  int16_t v_reason_reason;
  if (qmi_message_wds_start_network_output_get_verbose_call_end_reason(output,
                                                                       &v_reason_type,
                                                                       &v_reason_reason,
                                                                       &error))
  {
    syslog(LOG_INFO, "Verbose call end reason: %s",
           qmi_wds_verbose_call_end_reason_get_string(v_reason_type,
                                                      v_reason_reason));
  }
  error = NULL;

  qmi_message_wds_start_network_output_unref(output);

  qmi_client_wds_get_packet_service_status
    (wds_client, NULL, QMI_TIMEOUT, cancellable,
     (GAsyncReadyCallback)packet_service_status_ready, NULL);
}

static void start_network(void)
{
  qmi_status.packet_data_handle = 0xffffffff;

  GError *error = NULL;
  QmiMessageWdsStartNetworkInput *input;

  input = qmi_message_wds_start_network_input_new();

  if (!qmi_message_wds_start_network_input_set_enable_autoconnect(input, false, &error))
  {
    syslog(LOG_ERR, "Failed to set autoconnect field to true: %s", error->message);
    error = NULL;
  }

  if (apn_list)
  {
    syslog(LOG_INFO, "Attempting to connect with %s %s", apn_list->apn, apn_list->username);
    if (!qmi_message_wds_start_network_input_set_apn(input, apn_list->apn, &error))
      syslog(LOG_ERR, "Failed to set APN: %s", error->message);
    error = NULL;
    if (apn_list->username && strcmp(apn_list->username, ""))
      if (!qmi_message_wds_start_network_input_set_username(input, apn_list->username, &error))
        syslog(LOG_ERR, "Failed to set username: %s", error->message);
    error = NULL;
    if (apn_list->password && strcmp(apn_list->password, ""))
      if (!qmi_message_wds_start_network_input_set_password(input, apn_list->password, &error))
        syslog(LOG_ERR, "Failed to set password: %s", error->message);
    error = NULL;
    qmi_message_wds_start_network_input_set_authentication_preference
      (input, QMI_WDS_AUTHENTICATION_PAP | QMI_WDS_AUTHENTICATION_CHAP, &error);
    error = NULL;
  }

  qmi_client_wds_start_network(wds_client, input, QMI_TIMEOUT, cancellable,
                               (GAsyncReadyCallback)start_network_ready, NULL);

  qmi_message_wds_start_network_input_unref(input);
}

static void stop_network_ready(QmiClientWds *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageWdsStopNetworkOutput *output;
  output = qmi_client_wds_stop_network_finish(client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish network stop: %s", error->message);
    qmi_error();
  }

  if (!qmi_message_wds_stop_network_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to stop network: %s", error->message);
  }

  qmi_message_wds_stop_network_output_unref(output);
}

static void stop_network(void)
{
  GError *error = NULL;

  QmiMessageWdsStopNetworkInput *input;
  input = qmi_message_wds_stop_network_input_new();

  /*qmi_message_wds_stop_network_input_set_disable_autoconnect(input, false, &error);*/
  qmi_message_wds_stop_network_input_set_packet_data_handle(input,
                                                            qmi_status.packet_data_handle,
                                                            &error);

  qmi_client_wds_stop_network(wds_client, input, QMI_TIMEOUT, cancellable,
                              (GAsyncReadyCallback)stop_network_ready, NULL);

  qmi_message_wds_stop_network_input_unref(input);
}

static void disable_autoconnect(void)
{
  GError *error = NULL;

  QmiMessageWdsStopNetworkInput *input;
  input = qmi_message_wds_stop_network_input_new();

  if (!qmi_message_wds_stop_network_input_set_disable_autoconnect(input, true, &error))
  {
    syslog(LOG_ERR, "Failed to set disable autoconnect: %s", error->message);
    qmi_error();
  }
  error = NULL;
  if (!qmi_message_wds_stop_network_input_set_packet_data_handle(input,
                                                                 0xffffffff,
                                                                 &error))
  {
    syslog(LOG_ERR, "Failed to set data handle disabing autoconnect: %s", error->message);
    qmi_error();
  }

  qmi_client_wds_stop_network(wds_client, input, QMI_TIMEOUT, cancellable,
                              (GAsyncReadyCallback)stop_network_ready, NULL);

  qmi_message_wds_stop_network_input_unref(input);
}

enum State {
  StateStartup,
  StateFindBest,
  StateNextBeam,
  StateWaitForBeam,
  StateSaveResults,
  StateTestsComplete,
  StateRegister,
  StateRegisterWait,
  StateDataConnect,
  StateTryApn,
  StateDataConnectWait,
  StateMonitorData,
  StateCount,
};

struct BeamTest {
  int8_t beam;
  enum SignalType type;
  bool included;
  bool tested;
  time_t scan_start;
};
static struct BeamTest beam_tests[] = {
  {0, TypeLte,   true, false, 0},
  {0, TypeWcdma, true, false, 0},
  {1, TypeLte,   true, false, 0},
  {1, TypeWcdma, true, false, 0},
  {2, TypeLte,   true, false, 0},
  {2, TypeWcdma, true, false, 0},
  {3, TypeLte,   true, false, 0},
  {3, TypeWcdma, true, false, 0},
};
#define BEAM_TEST_COUNT 8
static struct BeamTest *current_beam = NULL;

enum State current_state;

void query_data_connection(void)
{
  qmi_client_wds_get_packet_service_status
    (wds_client, NULL, QMI_TIMEOUT, cancellable,
     (GAsyncReadyCallback)packet_service_status_ready, NULL);
}

void query_serving_system(void)
{
  qmi_client_nas_get_serving_system
    (nas_client, NULL, QMI_TIMEOUT, cancellable,
     (GAsyncReadyCallback)serving_system_ready, NULL);
}

gboolean main_check(gpointer data)
{
  if (!nas_client || !wds_client)
    return TRUE;

  enum State next_state = current_state;

  switch (current_state)
  {
    case StateStartup:
      {
        syslog(LOG_DEBUG, "UMTSD Startup");
        query_data_connection();
        disable_autoconnect();
        if (qmi_status.packet_status == QMI_WDS_CONNECTION_STATUS_CONNECTED)
          next_state = StateMonitorData;
        else
        {
          struct stat file_stat;
          lstat("/tmp/connected", &file_stat);
          if (S_ISREG(file_stat.st_mode))
            next_state = StateRegister;
          else
            next_state = StateFindBest;
        }
      }
      break;
    case StateFindBest:
      {
        syslog(LOG_DEBUG, "Searching for best signal");
        antenna_reset();
        for (size_t t = 0; t < BEAM_TEST_COUNT; ++t)
          beam_tests[t].tested = false;
        next_state = StateNextBeam;
      }
      break;
    case StateNextBeam:
      {
        bool changed_beam = false;
        for (size_t t = 0; t < BEAM_TEST_COUNT; ++t)
          if (beam_tests[t].included && !beam_tests[t].tested)
          {
            current_beam = &beam_tests[t];
            current_beam->tested = true;
            current_beam->scan_start = time(NULL);
            syslog(LOG_INFO, "Testing antenna %d (%s)", current_beam->beam,
                   SignalTypeText[current_beam->type]);
            nas_set_mode(current_beam->type);
            antenna_select(current_beam->beam, current_beam->type == TypeLte);
            memset(&qmi_status.antenna_stats, 0, sizeof(struct AntennaResult));
            antenna_led_searching();
            changed_beam = true;
            break;
          }
        next_state = (changed_beam) ? StateWaitForBeam : StateTestsComplete;
      }
      break;
    case StateWaitForBeam:
      syslog(LOG_DEBUG, "Waiting for antenna test to complete");
      if (qmi_status.antenna_stats.test_complete && qmi_status.wan_status == HomeNetwork)
        next_state = StateSaveResults;
      else if (time(NULL) - current_beam->scan_start > qmi_settings.regtimeout)
      {
        syslog(LOG_INFO, "Antenna registration timed out");
        next_state = StateNextBeam;
      }
      /*else if (qmi_status.wan_status == RegistrationDenied)*/
      /*{*/
        /*syslog(LOG_INFO, "Antenna registration denied");*/
        /*next_state = StateNextBeam;*/
      /*}*/
      break;
    case StateSaveResults:
      syslog(LOG_DEBUG, "Saving antenna results");
      memcpy(&antenna_results[qmi_status.antenna_stats.type][current_beam->beam],
             &qmi_status.antenna_stats, sizeof(struct AntennaResult));
      antenna_log(&qmi_status.antenna_stats);
      next_state = StateNextBeam;
      break;
    case StateTestsComplete:
      {
        const struct AntennaResult *antenna = antenna_find_best();
        syslog(LOG_INFO, "Selected antenna %d (%s)", antenna->antenna,
               SignalTypeText[antenna->type]);
        nas_set_mode(antenna->type);
        antenna_select(antenna->antenna, false);
        antenna_led_selected(antenna->type == TypeLte);
        next_state = StateRegister;
      }
      break;
    case StateRegister:
      syslog(LOG_DEBUG, "Registering");
      qmi_status.registration_start = time(NULL);
      qmi_status.wan_status = NoService;
      query_serving_system();
      next_state = StateRegisterWait;
      break;
    case StateRegisterWait:
      if (qmi_status.wan_status == HomeNetwork)
        next_state = StateDataConnect;
      else if (time(NULL) - qmi_status.registration_start > 2*qmi_settings.regtimeout)
      {
        syslog(LOG_INFO, "Registration timed out");
        next_state = StateFindBest;
      }
      else
        query_serving_system();
      break;
    case StateDataConnect:
      syslog(LOG_DEBUG, "Connecting to data service");
      sim_apn_generate_list();
      if (!apn_list)
      {
        syslog(LOG_ERR, "No APNs found for SIM %s", qmi_status.imsi);
        break;
      }
      next_state = StateTryApn;
      break;
    case StateTryApn:
      syslog(LOG_DEBUG, "Trying next APN");
      start_network();
      next_state = StateDataConnectWait;
      break;
    case StateDataConnectWait:
      syslog(LOG_DEBUG, "Waiting for data connection");
      query_data_connection();
      if (qmi_status.packet_data_handle != 0xffffffff
          && qmi_status.packet_status == QMI_WDS_CONNECTION_STATUS_CONNECTED)
      {
        net_renew_lease();
        next_state = StateMonitorData;
      }
      break;
    case StateMonitorData:
      {
        syslog(LOG_DEBUG, "Monitoring data connection");
        fclose(fopen("/tmp/connected", "w"));
        query_data_connection();
        if (qmi_status.packet_status == QMI_WDS_CONNECTION_STATUS_DISCONNECTED)
          next_state = StateDataConnect;
      }
      break;
    case StateCount:
      g_assert_not_reached();
      break;
  }

  current_state = next_state;

  snmp_write_status();

  return TRUE;
}

int main(int argc, char **argv)
{
  openlog("umtsd", LOG_PERROR, LOG_DAEMON);

  if (signal(SIGUSR1, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGUSR1 handler");
  if (signal(SIGUSR2, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGUSR2 handler");
  if (signal(SIGINT, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGINT handler");
  if (signal(SIGHUP, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGINT handler");
  if (signal(SIGTERM, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGINT handler");

  qmi_clear_status();
  snmp_write_status();

  if (!load_settings())
  {
    syslog(LOG_ERR, "Invalid WAN settings for QMI");
    exit(1);
  }
  print_settings();

  setlocale(LC_ALL, "");

  uqmi_power(true);
  sleep(2);
  while (!modem_is_present())
  {
    syslog(LOG_ERR, "Device %s is not a character device, waiting", qmi_settings.device);
    sleep(2);
  }

  while (!sim_is_present())
  {
    SET_STATUS(sim_status, NoSim);
    snmp_write_status();
    led_3g_red(true);
    sleep(1);
  };

  g_log_set_handler (NULL, G_LOG_LEVEL_MASK, log_handler, NULL);
  g_log_set_handler ("Qmi", G_LOG_LEVEL_MASK, log_handler, NULL);
  /*qmi_utils_set_traces_enabled(true);*/

  GFile *file = g_file_new_for_commandline_arg (qmi_settings.device);

  cancellable = g_cancellable_new ();
  GMainLoop *loop = g_main_loop_new (NULL, FALSE);
  g_timeout_add_seconds(3, main_check, "main check");

  qmi_device_new (file, cancellable, (GAsyncReadyCallback)device_new_ready, NULL);
  g_main_loop_run (loop);

  if (cancellable)
    g_object_unref (cancellable);
  g_main_loop_unref (loop);
  g_object_unref (file);

  syslog(LOG_INFO, "Data connection lost, restarting umtsd...");

  closelog();

  return 0;
}
