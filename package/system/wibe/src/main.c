#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <json/json.h>
#include <signal.h>

struct QmiSettings {
  char proto[8];
  char device[128];
  char apn[128];
  char username[128];
  char password[128];
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
  fprintf(stderr, "APN:         %s\n", qmi_settings.apn);
  fprintf(stderr, "Username:    %s\n", qmi_settings.username);
  fprintf(stderr, "Password:    %s\n", qmi_settings.password);
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
  struct ApnItem *apn;
  bool changed;
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

  qmi_status.rssi = -999;
  qmi_status.ecio = -999;
  qmi_status.rsrp = -999;
  qmi_status.rsrq = -999;
  qmi_status.snr = -999;

  qmi_status.apn = NULL;

  qmi_status.changed = true;
}

static void snmp_write_status(void)
{
  if (!qmi_status.changed)
    return;

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

  snmp_write_int(snmpfile, "1S261.0", qmi_status.rssi);
  if (qmi_status.signal_type == TypeLte)
  {
    snmp_write_int(snmpfile, "1S265.0", qmi_status.rsrp);
    snmp_write_int(snmpfile, "1S266.0", qmi_status.rsrq);
    snmp_write_int(snmpfile, "1S267.0", qmi_status.snr);
  }
  else if (qmi_status.signal_type == TypeWcdma)
  {
    snmp_write_int(snmpfile, "1S262.0", qmi_status.ecio);
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
  if (!uci_get_string("network.wan.apn", qmi_settings.apn,
                      sizeof(qmi_settings.apn)))
    return 0;
  uci_get_string_default("network.wan.username", qmi_settings.username,
                         sizeof(qmi_settings.username), "");
  uci_get_string_default("network.wan.password", qmi_settings.password,
                         sizeof(qmi_settings.password), "");
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

struct QmiResponse {
  json_object *jobj;
  char error_string[128];
  char response_string[128];
};

static void uqmi_free(struct QmiResponse *resp)
{
  if (!resp)
    return;

  if (resp->jobj)
    json_object_put(resp->jobj);
  free(resp);
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

static struct QmiResponse *uqmi_once(const char * const args)
{
  char cmd[384];
  int len = snprintf(cmd, sizeof(cmd), "uqmi -s -d %s %s", qmi_settings.device, args);
  if (len > sizeof(cmd))
    syslog(LOG_ERR, "Not enough space in uqmi command bufffer for %s", args);
  FILE *fp = popen(cmd, "r");
  if (fp == NULL)
  {
    syslog(LOG_ERR, "Failed to execute: '%s'", cmd);
    exit(1);
  }
  fprintf(stderr, "%s\n", cmd);

  int nready;
  int fd = fileno(fp);
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);

  struct timeval timeout = { .tv_sec=7, .tv_usec=0 };
  nready = select(fd+1, &readfds, NULL, NULL, &timeout);
  if (nready <= 0)
  {
    syslog(LOG_ERR, "QMI command timed out, resetting modem");
    uqmi_reset();
    exit(1);
  }

  char buf[1024];
  char *ret = fgets(buf, sizeof(buf)-1, fp);
  if (!ret)
    strncpy(buf, "{}", sizeof(buf));

  if (buf[strlen(buf)-1] == '\n')
    buf[strlen(buf)-1] = '\0';
  fprintf(stderr, "\t%s\n", buf);

  struct QmiResponse *resp = malloc(sizeof(*resp));
  assert(resp);
  resp->error_string[0] = '\0';
  resp->response_string[0] = '\0';
  resp->jobj = json_tokener_parse(buf);
  enum json_type type = json_object_get_type(resp->jobj);
  if (type != json_type_object && buf[0] == '"')
  {
    snprintf(resp->error_string, sizeof(resp->error_string), "%s", buf+1);
    if (resp->error_string[strlen(resp->error_string)-2] == '"')
      resp->error_string[strlen(resp->error_string)-2] = '\0';
    else if (resp->error_string[strlen(resp->error_string)-1] == '"')
      resp->error_string[strlen(resp->error_string)-1] = '\0';
  }
  else if (type != json_type_object)
  {
    strncpy(resp->response_string, buf, sizeof(resp->response_string));
  }

  pclose(fp);
  return resp;
}

static bool uqmi_is_error(const struct QmiResponse * const resp)
{
  return resp->error_string[0] != '\0';
}

static struct QmiResponse *uqmi(const char * const args)
{
  // Multiple retries if we get the "Unknown Error" response
  for (int i = 0; i < 5; ++i)
  {
    struct QmiResponse* resp = uqmi_once(args);
    if (!resp)
      continue;
    if (uqmi_is_error(resp) &&
        (!strcmp(resp->error_string, "Unknown error")
         || !strcmp(resp->error_string, "JSON Error")))
    {
      uqmi_free(resp);
      continue;
    }
    return resp;
  }
  uqmi_reset();
  exit(1);
}

const char *uqmi_get_string(const struct QmiResponse * const resp,
                            const char * const search_key)
{
  json_object_object_foreach(resp->jobj, key, val) {
    if (strcmp(key, search_key))
      continue;
    enum json_type type = json_object_get_type(val);
    switch (type) {
      case json_type_string:
        return json_object_get_string(val);
      default:
        syslog(LOG_ERR, "Unexpected JSON type: %d", type);
        break;
    }
  }
  return NULL;
}

int uqmi_get_int(const struct QmiResponse * const resp,
                 const char * const search_key)
{
  json_object_object_foreach(resp->jobj, key, val) {
    if (strcmp(key, search_key))
      continue;
    enum json_type type = json_object_get_type(val);
    switch (type) {
      case json_type_int:
        return json_object_get_int(val);
      default:
        syslog(LOG_ERR, "Unexpected JSON type: %d", type);
        break;
    }
  }
  return -1;
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

static void antenna_led_testing(bool isLTE)
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

#define ANTENNAS 4
static struct AntennaResult antenna_results[TypeCount][ANTENNAS];

static void antenna_reset(void)
{
  for (size_t type = 0; type < TypeCount; ++type)
    for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
      antenna_results[type][antenna].test_complete = false;
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

static void antenna_test(const char *antenna_mode, bool isLTE)
{
  int antenna_start = 0;
  int antenna_count = 4;

  if (strcmp(antenna_mode, "detect"))
  {
    antenna_start = atoi(antenna_mode);
    antenna_count = 1;
  }

  for (int antenna = antenna_start; antenna < antenna_count; ++antenna)
  {
    antenna_select(antenna, true);
    antenna_led_searching();
    sleep(qmi_settings.settlewait);
    struct QmiResponse *resp = NULL;
    const char *reg_status = NULL;
    for (int timeout = qmi_settings.regtimeout; timeout > 0; --timeout)
    {
      resp = uqmi("--get-serving-system");
      if (!uqmi_is_error(resp))
      {
        reg_status = uqmi_get_string(resp, "registration");
        if (!strcmp(reg_status, "registered"))
          break;
        if (!strcmp(reg_status, "registering_denied"))
          break;
        syslog(LOG_INFO, "Waiting for registration to complete: %s", reg_status);
      }
      else
      {
        syslog(LOG_INFO, "Waiting for registration to complete: %s", resp->error_string);
      }
      sleep(1);
    }

    if (reg_status && strcmp(reg_status, "registered"))
      continue;
    uqmi_free(resp);

    antenna_led_testing(isLTE);

    sleep(qmi_settings.settlewait);

    // Update qmi_statsu (around here somewhere)
    snmp_write_status();

    resp = uqmi("--get-signal-info");
    if (!uqmi_is_error(resp))
    {
      const char *type = uqmi_get_string(resp, "type");
      if (!strcmp(type, "lte"))
      {
        int rssi = uqmi_get_int(resp, "rssi");
        int rsrq = uqmi_get_int(resp, "rsrq");
        int rsrp = uqmi_get_int(resp, "rsrp");
        int snr = uqmi_get_int(resp, "snr");
        syslog(LOG_INFO, "lte %d %d %d %d", rssi, rsrq, rsrp, snr);
        struct AntennaResult r = { .test_complete = true, .rssi = rssi, .rsrq = rsrq,
                                   .rsrp = rsrp, .snr = snr, .type = TypeLte,
                                   .antenna = antenna};
        time_t now;
        time(&now);
        memcpy(&r.test_time, localtime(&now), sizeof(struct tm));
        memcpy(&antenna_results[TypeLte][antenna], &r, sizeof(struct AntennaResult));
      }
      else if (!strcmp(type, "wcdma"))
      {
        int rssi = uqmi_get_int(resp, "rssi");
        int ecio = uqmi_get_int(resp, "ecio");
        syslog(LOG_INFO, "wcdma %d %d", rssi, ecio);
        struct AntennaResult r = { .test_complete = true, .rssi = rssi,
                                   .ecio = ecio, .type = TypeWcdma,
                                   .antenna = antenna};
        time_t now;
        time(&now);
        memcpy(&r.test_time, localtime(&now), sizeof(struct tm));
        memcpy(&antenna_results[TypeWcdma][antenna], &r, sizeof(struct AntennaResult));
      }
      else
      {
        syslog(LOG_INFO, "Unexpected signal type: %s", type);
      }
    }
    else
    {
      syslog(LOG_INFO, "Error reading signal info: %s", resp->error_string);
    }
  }
}

static char cid[32];

static void modem_disconnect(void)
{
  uqmi_free(uqmi("--stop-network 0xffffffff --autoconnect"));

  char cmd[128];
  snprintf(cmd, sizeof(cmd),
           "--set-client-id wds,\"%s\" --release-client-id wds", cid);
  uqmi_free(uqmi(cmd));
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
    }
  }

  return false;
}

static void sim_apn_add(struct ApnItem *apn)
{
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

static void uqmi_save_apn(const char *imsi, struct ApnItem *apn)
{
  assert(imsi);
  assert(apn);

  system("touch /etc/config/myproviders");

  FILE *tmp = fopen("/tmp/.newapn", "w");

  fprintf(tmp, "delete myproviders.%s\n", imsi);
  fprintf(tmp, "set myproviders.%s=provider\n", imsi);
  fprintf(tmp, "add_list myproviders.%s.network=%s\n", imsi, imsi);
  fprintf(tmp, "set myproviders.%s.apn=%s\n", imsi, apn->apn);
  if (apn->username && strlen(apn->username) > 0)
    fprintf(tmp, "set myproviders.%s.username=%s\n", imsi, apn->username);
  if (apn->password && strlen(apn->password) > 0)
    fprintf(tmp, "set myproviders.%s.password=%s\n", imsi, apn->password);
  fprintf(tmp, "commit myproviders");

  fclose(tmp);

  system("uci batch < /tmp/.newapn");
  unlink("/tmp/.newapn");
}

static void uqmi_data_connect(void)
{
  char connect_command[256];

  struct ApnItem *apn = apn_list;

  bool connected = false;
  while (apn)
  {
    syslog(LOG_INFO, "Attempting to connect with APN: %s", apn->apn);
    for (int i = 0; i < qmi_settings.settlewait; ++i)
    {
      struct QmiResponse *resp = uqmi("--get-data-status");
      if (!strcmp(resp->error_string, "disconnected"))
        break;
      sleep(1);
    }
    uqmi_free(uqmi("--stop-network 0xffffffff --autoconnect"));
    snprintf(connect_command, sizeof(connect_command),
             "--set-client-id wds,\"%s\" --start-network \"%s\" %s %s %s %s "
             "--autoconnect ", cid, apn->apn,
             (apn->username && strlen(apn->username) > 0) ? "--username" : "",
             (apn->username && strlen(apn->username) > 0) ? apn->username : "",
             (apn->password && strlen(apn->password) > 0) ? "--password" : "",
             (apn->password && strlen(apn->password) > 0) ? apn->password : "");
    struct QmiResponse *resp = uqmi(connect_command);
    uqmi_free(resp);

    for (int i = 0; i < qmi_settings.settlewait; ++i)
    {
      struct QmiResponse *resp = uqmi("--get-data-status");
      if (!strcmp(resp->error_string, "connected"))
      {
        syslog(LOG_INFO, "Connected with APN: %s", apn->apn);
        qmi_status.apn = apn;
        uqmi_save_apn(qmi_status.imsi, apn);
        net_renew_lease();
        connected = true;
        break;
      }
      sleep(1);
    }
    if (connected)
      break;

    apn = apn->next;
  }

  syslog(LOG_INFO, "Could not find a working APN");
}

static const char* qmi_get_error_response(const char *argument)
{
  struct QmiResponse *resp = uqmi(argument);
  if (!uqmi_is_error(resp))
  {
    syslog(LOG_ERR, "Could not %s", argument);
    uqmi_free(resp);
    exit(1);
  }
  const char *dst = strdup(resp->error_string);
  uqmi_free(resp);
  return dst;
}

static void modem_set_service(enum SignalType type)
{
  if (type == TypeLte)
    uqmi_free(uqmi("--set-network-modes lte"));
  else if (type == TypeWcdma)
    uqmi_free(uqmi("--set-network-modes umts"));

  SET_STATUS(signal_type, type);
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

  qmi_clear_status();
  snmp_write_status();

  if (!load_settings())
  {
    syslog(LOG_ERR, "Invalid WAN settings for QMI");
    exit(1);
  }
  print_settings();

  uqmi_power(true);
  sleep(5);
  while (!modem_is_present())
  {
    syslog(LOG_ERR, "Device %s is not a character device, waiting", qmi_settings.device);
    sleep(5);
  }

  while (!sim_is_present())
  {
    SET_STATUS(sim_status, NoSim);
    snmp_write_status();
    led_3g_red(true);
    sleep(1);
  };

  struct QmiResponse *resp = uqmi("--get-pin-status");
  if (uqmi_is_error(resp))
  {
    // update qmi_status
    snmp_write_status();
    syslog(LOG_WARNING, "SIM is not initialised");
    uqmi_reset();
    exit(1);
  }
  uqmi_free(resp);
  led_3g_red(false);

  SET_STATUS(sim_status, SimOk);
  SET_STATUS(imei, qmi_get_error_response("--get-imei"));
  SET_STATUS(imsi, qmi_get_error_response("--get-imsi"));
  SET_STATUS(msisdn, qmi_get_error_response("--get-msisdn"));
  snmp_write_status();

  if (strlen(qmi_settings.pincode))
  {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "--verify-pin1 %s", qmi_settings.pincode);
    struct QmiResponse *resp = uqmi(cmd);
    if (uqmi_is_error(resp) && !strcmp(resp->error_string, "No effect"))
    {
      syslog(LOG_WARNING, "Pin1 had no effect");
    }
    else if (uqmi_is_error(resp))
    {
      syslog(LOG_ERR, "PIN1 verify: %s", resp->error_string);
      SET_STATUS(sim_status, SimPinIncorrect);
    }
    uqmi_free(resp);
  }
  snmp_write_status();

  uqmi_free(uqmi("--set-data-format 802.3"));
  uqmi_free(uqmi("--wda-set-data-format 802.3"));

  antenna_reset();
  if (!strcmp(qmi_settings.modes, "detect"))
  {
    for (int type = 0; type < TypeCount; ++type)
    {
      modem_set_service(type);
      net_renew_lease();
      antenna_test(qmi_settings.antenna, type == TypeLte);
    }
  }
  else
  {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "--set-network-modes %s", qmi_settings.modes);
    uqmi_free(uqmi(cmd));
    net_renew_lease();
    antenna_test(qmi_settings.antenna, !strcmp(qmi_settings.modes, "lte"));
  }

  const struct AntennaResult *antenna = antenna_find_best();
  if (!strcmp(qmi_settings.modes, "detect"))
  {
    syslog(LOG_INFO, "Selecting %s mode", SignalTypeText[antenna->type]);
    modem_set_service(antenna->type);
    net_renew_lease();
  }

  if (!strcmp(qmi_settings.antenna, "detect"))
  {
    syslog(LOG_INFO, "Selecting antenna %d", antenna->antenna);
    antenna_select(antenna->antenna, false);
    antenna_led_selected(antenna->type == TypeLte);
  }

  resp = uqmi("--get-client-id wds");
  strncpy(cid, resp->response_string, sizeof(cid));
  uqmi_free(resp);

  modem_disconnect();

  resp = uqmi("--get-client-id wds");
  strncpy(cid, resp->response_string, sizeof(cid));
  uqmi_free(resp);

  sim_apn_generate_list();
  uqmi_data_connect();

  // Update qmi_statsu
  snmp_write_status();

  while (true)
  {
    if (!sim_is_present())
    {
      led_3g_red(true);
      exit(1);
    }

    resp = uqmi("--get-data-status");
    fprintf(stderr, "%s", resp->error_string);
    if (strcmp(resp->error_string, "connected"))
    {
      uqmi_free(resp);
      sleep(qmi_settings.settlewait);
      resp = uqmi("--get-data-status");
      if (strcmp(resp->error_string, "connected"))
        break;
    }
    sleep(1);

    // Update qmi_statsu
    snmp_write_status();
  }

  syslog(LOG_INFO, "Data connection lost, restarting umtsd...");

  closelog();

  return 0;
}
