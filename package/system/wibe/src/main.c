#define _GNU_SOURCE
#define __USE_GNU

#include <sys/timerfd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <termios.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>
#include "settings.h"

#include <glib.h>
#include <glib-object.h>
#include <locale.h>

#include <libqmi-glib.h>

// Exit codes
#define QMI_ERROR 12

#define QMI_TIMEOUT 15

#define WDOG_INTERVAL 30

static int wdog_fd = -1;

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
static QmiClientVoice *voice_client;
static QmiClient *ctl_client;

struct QmiSettings {
  char proto[8];
  char device[128];
  char pincode[32];
  char modes[16];
  char antenna[16];
  int regtimeout;
  int enable_roaming;
  int debug;
  QmiDmsLteBandCapability lte_bands;
  QmiDmsBandCapability bands;
  int download_test;
  int domain;
};
static struct QmiSettings qmi_settings;

static void print_settings(void)
{
  syslog(LOG_DEBUG, "Settings:");
  syslog(LOG_DEBUG, "  Protocol:    %s", qmi_settings.proto);
  syslog(LOG_DEBUG, "  Device:      %s", qmi_settings.device);
  syslog(LOG_DEBUG, "  Pincode:     %s", qmi_settings.pincode);
  syslog(LOG_DEBUG, "  Modes:       %s", qmi_settings.modes);
  syslog(LOG_DEBUG, "  Antenna:     %s", qmi_settings.antenna);
  syslog(LOG_DEBUG, "  Reg Timeout: %d", qmi_settings.regtimeout);
  syslog(LOG_DEBUG, "  Roaming:     %d", qmi_settings.enable_roaming);
  syslog(LOG_DEBUG, "  Debug:       %d", qmi_settings.debug);
  syslog(LOG_DEBUG, "  Download:    %d", qmi_settings.download_test);
  syslog(LOG_DEBUG, "  Domain:      %d", qmi_settings.domain);
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
  BackBeam = 0,
  RightBeam = 1,
  LeftBeam = 2,
  FrontBeam = 3,
  BeamCount,
  UnknownBeam = BeamCount
};

static const char *AntennaText[] = {
  [BackBeam] = "back",
  [RightBeam] = "right",
  [LeftBeam] = "left",
  [FrontBeam] = "front",
  [UnknownBeam] = "unknown"
};

struct AntennaResult {
  bool test_complete;
  struct tm test_time;
  enum SignalType type;
  uint8_t antenna;
  uint16_t lac;
  uint32_t cid;
  int rssi;
  int ecio;
  int rsrq;
  int rsrp;
  int snr;
  unsigned long download_bytes;
};

struct QmiStatus {
  const char *imei;
  const char *imsi;
  const char *msisdn;
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
  bool antenna_testing;
  const char *manufacturer;
  const char *model;
  const char *revision;
  size_t download_tests_remaining;
  size_t download_tests_complete;
  const char *pri_pri;
  const char *pri_carrier_pri;
  const char *pri_revision;
};
static struct QmiStatus qmi_status;

#define SET_STATUS(field, value) { if (qmi_status.field != value) { qmi_status.field = value; qmi_status.changed = true; } }

#define ANTENNAS 4
static struct AntennaResult antenna_results[TypeCount][ANTENNAS];

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
  qmi_status.antenna_testing = false;

  qmi_status.download_tests_remaining = 0;
  qmi_status.download_tests_complete = 0;

  qmi_status.pri_pri = NULL;
  qmi_status.pri_carrier_pri = NULL;
  qmi_status.pri_revision = NULL;
}

static void luci_write_status(void)
{
  FILE *lucifile = fopen("/tmp/wibe_luci", "w");

  fprintf(lucifile, "local qmi={}\n");
  fprintf(lucifile, "qmi.service=\"%s (%s)\"\n", SignalTypeText[qmi_status.antenna_stats.type], RegistrationText[qmi_status.wan_status]);
  fprintf(lucifile, "qmi.imsi=\"%s\"\n", qmi_status.imsi);
  fprintf(lucifile, "qmi.imei=\"%s\"\n", qmi_status.imei);
  fprintf(lucifile, "qmi.msisdn=\"%s\"\n", qmi_status.msisdn);
  fprintf(lucifile, "qmi.antenna=\"%s\"\n", AntennaText[qmi_status.active_antenna]);
  fprintf(lucifile, "qmi.rssi=\"%d\"\n", qmi_status.antenna_stats.rssi);
  if (qmi_status.antenna_stats.type == TypeLte)
  {
    fprintf(lucifile, "qmi.ecio=\"N/A\"\n");
    fprintf(lucifile, "qmi.rsrp=\"%d\"\n", qmi_status.antenna_stats.rsrp);
    fprintf(lucifile, "qmi.rsrq=\"%d\"\n", qmi_status.antenna_stats.rsrq);
    fprintf(lucifile, "qmi.snr=\"%d\"\n", qmi_status.antenna_stats.snr);
  }
  else if (qmi_status.antenna_stats.type == TypeWcdma)
  {
    fprintf(lucifile, "qmi.ecio=\"%d\"\n", qmi_status.antenna_stats.ecio);
    fprintf(lucifile, "qmi.rsrp=\"N/A\"\n");
    fprintf(lucifile, "qmi.rsrq=\"N/A\"\n");
    fprintf(lucifile, "qmi.snr=\"N/A\"\n");
  }
  fprintf(lucifile, "qmi.lac=\"%d\"\n", qmi_status.antenna_stats.lac);
  fprintf(lucifile, "qmi.cid=\"%d\"\n", qmi_status.antenna_stats.cid);

  fprintf(lucifile, "qmi.pripri=\"%s\"\n", qmi_status.pri_pri);
  fprintf(lucifile, "qmi.pricarrierpri=\"%s\"\n", qmi_status.pri_carrier_pri);
  fprintf(lucifile, "qmi.prirevision=\"%s\"\n", qmi_status.pri_revision);

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

  struct AntennaResult *result = &qmi_status.antenna_stats;
  snmp_write_int(snmpfile, "1S261.0", result->rssi);
  if (qmi_status.antenna_stats.type == TypeLte)
  {
    snmp_write_int(snmpfile, "1S265.0", result->rsrp);
    snmp_write_int(snmpfile, "1S266.0", result->rsrq);
    snmp_write_int(snmpfile, "1S267.0", result->snr);
  }
  else if (qmi_status.antenna_stats.type == TypeWcdma)
  {
    snmp_write_int(snmpfile, "1S262.0", result->ecio);
  }

  snmp_write_string(snmpfile, "1S264.0", SignalTypeText[qmi_status.antenna_stats.type]);

  snmp_write_int(snmpfile, "1S773.0", qmi_status.antenna_stats.cid);
  snmp_write_int(snmpfile, "1S774.0", qmi_status.antenna_stats.lac);

  fclose(snmpfile);

  qmi_status.changed = false;
}

static void snmp_write_antenna_test(void)
{
  FILE *snmpfile = fopen("/tmp/snmp_antenna", "w");
  if (snmpfile == NULL)
    return;

  size_t count = 0;
  for (enum SignalType type = 0; type < TypeCount; ++type)
  {
    for (size_t beam = 0; beam < ANTENNAS; ++beam)
    {
      struct AntennaResult *r = &antenna_results[type][beam];
      if (!r->test_complete)
        continue;

      fprintf(snmpfile, "2S100.%d=\"%s%s\"\n", count, AntennaText[beam], SignalTypeText[r->type]);
      char *test_time = asctime(&r->test_time);
      test_time[strlen(test_time) - 1] = '\0';
      fprintf(snmpfile, "2S101.%d=\"%s\"\n", count, test_time);
      fprintf(snmpfile, "2S102.%d=\"scan\"\n", count);
      fprintf(snmpfile, "2S103.%d=\"%d\"\n", count, r->lac);
      fprintf(snmpfile, "2S104.%d=\"%d\"\n", count, r->cid);
      fprintf(snmpfile, "2S105.%d=\"%d\"\n", count, r->rssi);
      fprintf(snmpfile, "2S106.%d=\"0\"\n", count);
      fprintf(snmpfile, "2S107.%d=\"0\"\n", count);
      fprintf(snmpfile, "2S108.%d=\"0\"\n", count);
      fprintf(snmpfile, "2S109.%d=\"%d\"\n", count, (r->type == TypeWcdma) ? r->ecio : -999);
      fprintf(snmpfile, "2S110.%d=\"%d\"\n", count, (r->type == TypeLte) ? r->rsrq : -999);
      fprintf(snmpfile, "2S111.%d=\"%d\"\n", count, (r->type == TypeLte) ? r->rsrp : -999);
      fprintf(snmpfile, "2S112.%d=\"%d\"\n", count, (r->type == TypeLte) ? r->snr : -999);
      count += 1;
    }
  }

  fclose(snmpfile);
}

static void write_result_txt(uint8_t selected)
{
  const char interface_count = 3;
  const char *interfaces[] = {"wwan0", "wlan0", "eth0"};

  FILE *fh = fopen("/tmp/results.txt.tmp", "w");
  if (fh == NULL)
    return;

  fprintf(fh, "Firmware Version:  %s\n", getenv("DISTRIB_DESCRIPTION"));
  fprintf(fh, "Firmware Type: 0\n");
  fprintf(fh, "Modem: %s %s %s\n", qmi_status.manufacturer, qmi_status.model, qmi_status.revision);
  fprintf(fh, "IMEI: %s\n", qmi_status.imei);
  fprintf(fh, "IMSI: %s\n", qmi_status.imsi);
  for (size_t i = 0; i < ANTENNAS; ++i)
    fprintf(fh, "%d:  %d   %d   %d   %d\n",
            i,
            antenna_results[TypeWcdma][i].rssi,
            antenna_results[TypeLte][i].rssi,
            antenna_results[TypeWcdma][i].test_complete,
            antenna_results[TypeLte][i].test_complete);

  fprintf(fh, "Chosen antenna: %d\n", selected);

  for (size_t i = 0; i < interface_count; ++i)
  {
    char buf[128];
    snprintf(buf, sizeof(buf), "/sys/class/net/%s/address", interfaces[i]);
    FILE *mac = fopen(buf, "r");
    if (!mac)
      continue;
    fgets(buf, sizeof(buf), mac);
    fclose(mac);
    fprintf(fh, "%s MAC: %s", interfaces[i], buf);
  }
  bool isPass = true;
  for (size_t beam = 0; beam < ANTENNAS; ++beam)
  {
    if (antenna_results[TypeWcdma][beam].rssi < -90)
      isPass = false;
    if (!antenna_results[TypeWcdma][beam].test_complete)
      isPass = false;
  }

  fprintf(fh, "%s\n", (isPass) ? "PASS" : "FAIL");

  fclose(fh);

  (void)rename("/tmp/results.txt.tmp", "/tmp/results.txt");
  (void)symlink("/tmp/results.txt", "/www/results.txt");
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
  uci_get_int_default("network.wan.roaming", &qmi_settings.enable_roaming, 0);
  uci_get_int_default("network.wan.umtsddebug", &qmi_settings.debug, 0);
  uci_get_int_default("network.wan.download_test", &qmi_settings.download_test, 0);
  uci_get_int_default("network.wan.domain", &qmi_settings.domain,
                      QMI_NAS_SERVICE_DOMAIN_PREFERENCE_CS_PS);

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
  SET_STATUS(antenna_stats.antenna, beam);
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

  int fd = open("/sys/class/leds/wibe:base/trigger", O_WRONLY);
  assert(fd);
  int bytes = write(fd, "none", 4);
  assert(bytes == 4);
  close(fd);

  fd = open("/sys/class/leds/wibe:cabin/trigger", O_WRONLY);
  assert(fd);
  bytes = write(fd, "none", 4);
  assert(bytes == 4);
  close(fd);
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

  fd = open("/sys/class/leds/wibe:base/trigger", O_WRONLY);
  assert(fd);
  bytes = write(fd, "heartbeat", strlen("heartbeat"));
  assert(bytes > 0);
  close(fd);

  fd = open("/sys/class/leds/wibe:cabin/trigger", O_WRONLY);
  assert(fd);
  bytes = write(fd, "heartbeat", strlen("heartbeat"));
  assert(bytes > 0);
  close(fd);
}

enum Antenna beam_from_sysfs(void)
{
  static char antenna_name[10];

  int fd = open("/sys/devices/wibe-antenna.4/antenna", O_RDONLY);
  assert(fd);
  int bytes = read(fd, &antenna_name, 10);
  assert(bytes > 0);
  antenna_name[bytes-1] = '\0'; // Remove \n
  close(fd);

  for (size_t i = 0; i < ANTENNAS; ++i)
    if (!strcmp(AntennaText[i], antenna_name))
      return i;

  return UnknownBeam;
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

  fd = open("/sys/class/leds/wibe:base/trigger", O_WRONLY);
  assert(fd);
  bytes = write(fd, "default-on", strlen("default-on"));
  assert(bytes > 0);
  close(fd);

  fd = open("/sys/class/leds/wibe:cabin/trigger", O_WRONLY);
  assert(fd);
  bytes = write(fd, "default-on", strlen("default-on"));
  assert(bytes > 0);
  close(fd);
}

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

static const struct AntennaResult *antenna_find_best_of_type(enum SignalType type)
{
  struct AntennaResult *best = NULL;
  for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
    best = antenna_max(best, &antenna_results[type][antenna]);
  return best;
}

static const struct AntennaResult *antenna_find_best(void)
{
  struct AntennaResult *best = NULL;
  for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
    best = antenna_max(best, &antenna_results[TypeWcdma][antenna]);
  for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
    best = antenna_max(best, &antenna_results[TypeLte][antenna]);
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
  switch (sig)
  {
    case SIGINT:
    case SIGTERM:
      syslog(LOG_ERR, "%s: Disconnecting...", strsignal(sig));
      modem_disconnect();
      write(wdog_fd, "V", 1);
      close(wdog_fd);
      exit(0);
      break;
    case SIGUSR1:
      syslog(LOG_ERR, "SIGUSR1: Received");
      break;
    case SIGUSR2:
      syslog(LOG_ERR, "SIGUSR2: N/A");
      break;
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
    g_error_free(error);
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
                                                              NULL);
  if (found)
  {
    syslog(LOG_INFO, "PIN Status: %s", qmi_dms_uim_pin_status_get_string(pin1_status));
    switch (pin1_status)
    {
      case QMI_DMS_UIM_PIN_STATUS_NOT_INITIALIZED:
        SET_STATUS(sim_status, SimFailure);
        break;
      case QMI_DMS_UIM_PIN_STATUS_ENABLED_NOT_VERIFIED:
        SET_STATUS(sim_status, SimPinRequired);
        break;
      case QMI_DMS_UIM_PIN_STATUS_ENABLED_VERIFIED:
      case QMI_DMS_UIM_PIN_STATUS_DISABLED:
        SET_STATUS(sim_status, SimOk);
        break;
      case QMI_DMS_UIM_PIN_STATUS_BLOCKED:
      case QMI_DMS_UIM_PIN_STATUS_PERMANENTLY_BLOCKED:
        SET_STATUS(sim_status, SimPukRequired);
        break;
      case QMI_DMS_UIM_PIN_STATUS_UNBLOCKED:
      case QMI_DMS_UIM_PIN_STATUS_CHANGED:
      default:
        SET_STATUS(sim_status, SimUnknown);
        break;
    }
  }
  qmi_message_dms_uim_get_pin_status_output_unref(status);
}

static void serving_system_ready(QmiClientNas *client,
                                 GAsyncResult *res)
{
  GError *error = NULL;

  syslog(LOG_DEBUG, "Serving system indication");

  QmiMessageNasGetServingSystemOutput *output;
  output = qmi_client_nas_get_serving_system_finish(client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish serving system ready: %s", error->message);
    g_error_free(error);
    return;
  }

  QmiNasRegistrationState registration_state;
  QmiNasAttachState cs_attach_state;
  QmiNasAttachState ps_attach_state;
  QmiNasNetworkType selected_network;
  GArray *radio_interfaces;

  if (qmi_message_nas_get_serving_system_output_get_serving_system
    (output, &registration_state, &cs_attach_state, &ps_attach_state,
     &selected_network, &radio_interfaces, NULL))
  {
    QmiNasRoamingIndicatorStatus roaming_indicator = QMI_NAS_ROAMING_INDICATOR_STATUS_OFF;
    qmi_message_nas_get_serving_system_output_get_roaming_indicator(output, &roaming_indicator, NULL);
    for (size_t i = 0; i < radio_interfaces->len; ++i)
    {
      bool isValid = false;
      QmiNasRadioInterface intf = g_array_index(radio_interfaces, QmiNasRadioInterface, i);
      syslog(LOG_DEBUG, "  Network status request (%d) for %d %s %s", i, intf, qmi_nas_radio_interface_get_string(intf), qmi_nas_registration_state_get_string(registration_state));
      if (qmi_status.signal_type == TypeUnknown)
      {
        qmi_status.signal_type = (intf == QMI_NAS_RADIO_INTERFACE_LTE) ? TypeLte : TypeWcdma;
      }
      if (intf == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte)
        isValid = true;
      else if (intf == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma)
        isValid = true;

      if (isValid)
      {
        switch (registration_state)
        {
          case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED:
            SET_STATUS(wan_status, NoService);
            syslog(LOG_DEBUG, "  No Service");
            break;
          case QMI_NAS_REGISTRATION_STATE_REGISTERED:
            if (roaming_indicator == QMI_NAS_ROAMING_INDICATOR_STATUS_ON)
            {
              SET_STATUS(wan_status, RoamingNetwork);
              syslog(LOG_DEBUG, "  Roaming");
            }
            else
            {
              SET_STATUS(wan_status, HomeNetwork);
              syslog(LOG_DEBUG, "  Home Network");
            }
            break;
          case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED_SEARCHING:
            SET_STATUS(wan_status, Searching);
            syslog(LOG_DEBUG, "  Searching");
            break;
          case QMI_NAS_REGISTRATION_STATE_REGISTRATION_DENIED:
            SET_STATUS(wan_status, RegistrationDenied);
            syslog(LOG_DEBUG, "  Registration Denied");
            break;
          case QMI_NAS_REGISTRATION_STATE_UNKNOWN:
            SET_STATUS(wan_status, NoService);
            syslog(LOG_DEBUG, "  Unknown Registration");
            break;
        }
        uint32_t cid;
        if (qmi_message_nas_get_serving_system_output_get_cid_3gpp(output, &cid, NULL))
          qmi_status.antenna_stats.cid = cid;
        uint16_t lac;
        if (qmi_message_nas_get_serving_system_output_get_lac_3gpp(output, &lac, NULL))
          qmi_status.antenna_stats.lac = lac;
      }
    }
  }
  qmi_message_nas_get_serving_system_output_unref(output);
}

void query_serving_system(void)
{
  qmi_client_nas_get_serving_system
    (nas_client, NULL, QMI_TIMEOUT, cancellable,
     (GAsyncReadyCallback)serving_system_ready, NULL);
}

static void system_selection_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasSetSystemSelectionPreferenceOutput *output = NULL;

  output = qmi_client_nas_set_system_selection_preference_finish(nas_client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish system selection preferences: %s", error->message);
    g_error_free(error);
    qmi_error();
  }

  if (!qmi_message_nas_set_system_selection_preference_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to set operating mode: %s", error->message);
    g_error_free(error);
  }
  qmi_message_nas_set_system_selection_preference_output_unref(output);

  query_serving_system();
}

static void nas_event_report_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasSetEventReportOutput *output = NULL;
  output = qmi_client_nas_set_event_report_finish(nas_client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish nas report: %s", error->message);
    g_error_free(error);
    qmi_error();
  }

  if (!qmi_message_nas_set_event_report_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to check nas report : %s", error->message);
    g_error_free(error);
    qmi_error();
  }

  if (output)
    qmi_message_nas_set_event_report_output_unref(output);
}

static void set_voice_ready(QmiClientVoice *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageVoiceSetConfigOutput *output;
  output = qmi_client_voice_set_config_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish set voice: %s", error->message);
    g_error_free(error);
    return;
  }

  if (!qmi_message_voice_set_config_output_get_result(output, &error))
    syslog(LOG_ERR, "Failed to set voice preferences: %s", error->message);

  qmi_message_voice_set_config_output_unref(output);
}

static void nas_register_indications_ready(QmiClientNas *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasRegisterIndicationsOutput *output;
  output = qmi_client_nas_register_indications_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish nas register indications: %s", error->message);
    g_error_free(error);
    return;
  }

  if (!qmi_message_nas_register_indications_output_get_result(output, &error))
    syslog(LOG_ERR, "Failed to set nas register indications: %s", error->message);

  qmi_message_nas_register_indications_output_unref(output);
}

static void event_report_ready(QmiClientNas *object,
                               QmiIndicationNasEventReportOutput *output,
                               gpointer user_data)
{
  syslog(LOG_DEBUG, "NAS Event Report:");
  uint8_t rssi;
  QmiNasRadioInterface interface;
  if (qmi_indication_nas_event_report_output_get_rssi(output, &rssi, &interface, NULL))
  {
    syslog(LOG_DEBUG, "  RSSI: %d (%s)", -rssi, qmi_nas_radio_interface_get_string(interface));
    if (interface == QMI_NAS_RADIO_INTERFACE_LTE)
    {
      SET_STATUS(antenna_stats.type, TypeLte);
    }
    else if (interface == QMI_NAS_RADIO_INTERFACE_UMTS)
    {
      SET_STATUS(antenna_stats.type, TypeWcdma);
    }
    else
    {
      SET_STATUS(antenna_stats.type, TypeUnknown);
      syslog(LOG_ERR, "  Unexpected interface: %s", qmi_nas_radio_interface_get_string(interface));
    }
    if (qmi_status.signal_type == qmi_status.antenna_stats.type
        && (qmi_status.wan_status == HomeNetwork || qmi_status.wan_status == RoamingNetwork)
        && rssi != 0)
    {
      if (qmi_status.antenna_testing)
        antenna_led_testing(interface == QMI_NAS_RADIO_INTERFACE_LTE);
      SET_STATUS(antenna_stats.rssi, -rssi);
      time_t now = time(NULL);
      gmtime_r(&now, &qmi_status.antenna_stats.test_time);
      qmi_status.antenna_stats.test_complete = true;
    }
  }

  int16_t rsrp;
  if (qmi_indication_nas_event_report_output_get_lte_rsrp(output, &rsrp, NULL))
  {
    syslog(LOG_DEBUG, "  RSRP: %d", rsrp);
    SET_STATUS(antenna_stats.rsrp, rsrp);
  }

  int16_t snr;
  if (qmi_indication_nas_event_report_output_get_lte_snr(output, &snr, NULL))
  {
    syslog(LOG_DEBUG, "  SNR: %d", snr);
    SET_STATUS(antenna_stats.snr, snr);
  }

  int8_t rsrq;
  if (qmi_indication_nas_event_report_output_get_rsrq(output, &rsrq, &interface, NULL))
  {
    syslog(LOG_DEBUG, "  RSRQ: %d (%s)", rsrq, qmi_nas_radio_interface_get_string(interface));
    SET_STATUS(antenna_stats.rsrq, rsrq);
  }

  uint8_t ecio;
  if (qmi_indication_nas_event_report_output_get_ecio(output, &ecio, &interface, NULL))
  {
    syslog(LOG_DEBUG, "  ECIO: %d (%s)", ecio, qmi_nas_radio_interface_get_string(interface));
    SET_STATUS(antenna_stats.ecio, ecio);
  }

  int8_t strength;
  if (qmi_indication_nas_event_report_output_get_signal_strength(output, &strength, &interface, NULL))
  {
    syslog(LOG_DEBUG, "  Strength: %d (%s)", strength, qmi_nas_radio_interface_get_string(interface));
  }

  QmiNasNetworkServiceDomain registration_reject_reason_service_domain;
  guint16 registration_reject_reason_reject_cause;
  if (qmi_indication_nas_event_report_output_get_registration_reject_reason
      (output, &registration_reject_reason_service_domain, &registration_reject_reason_reject_cause, NULL))
  {
    syslog(LOG_WARNING, "  Registration rejected for %s: %d",
           qmi_nas_network_service_domain_get_string(registration_reject_reason_service_domain),
           registration_reject_reason_reject_cause);
  }
}

static void signal_strength_ready(QmiClientNas *client,
                                  GAsyncResult *res)
{
  syslog(LOG_DEBUG, "Signal Strength:");
  GError *error = NULL;

  QmiMessageNasGetSignalStrengthOutput *output;
  output = qmi_client_nas_get_signal_strength_finish(client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish signal strength indicator: %s", error->message);
    g_error_free(error);
    return;
  }

  GArray *rssi_list;
  if (qmi_message_nas_get_signal_strength_output_get_rssi_list(output, &rssi_list, NULL))
  {
    for (size_t i = 0; i < rssi_list->len; ++i)
    {
      QmiMessageNasGetSignalStrengthOutputRssiListElement rssi;
      rssi = g_array_index(rssi_list, QmiMessageNasGetSignalStrengthOutputRssiListElement, i);
      if ((rssi.radio_interface == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte) ||
          (rssi.radio_interface == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma))
      {
        syslog(LOG_DEBUG, "  RSSI: %d (%s)", -(rssi.rssi), qmi_nas_radio_interface_get_string(rssi.radio_interface));
        if ((qmi_status.wan_status == HomeNetwork || qmi_status.wan_status == RoamingNetwork) && rssi.rssi != 0)
        {
          if (qmi_status.antenna_testing)
            antenna_led_testing(rssi.radio_interface == QMI_NAS_RADIO_INTERFACE_LTE);
          SET_STATUS(antenna_stats.rssi, -(rssi.rssi));
          time_t now = time(NULL);
          gmtime_r(&now, &qmi_status.antenna_stats.test_time);
          qmi_status.antenna_stats.test_complete = true;
        }
      }
    }
  }
  error = NULL;

  int16_t rsrp;
  if (qmi_message_nas_get_signal_strength_output_get_lte_rsrp(output, &rsrp, NULL))
  {
    syslog(LOG_DEBUG, "  RSRP: %d", rsrp);
    SET_STATUS(antenna_stats.rsrp, rsrp);
  }
  error = NULL;

  int16_t snr;
  if (qmi_message_nas_get_signal_strength_output_get_lte_snr(output, &snr, NULL))
  {
    syslog(LOG_DEBUG, "  SNR: %d", snr);
    SET_STATUS(antenna_stats.snr, snr);
  }
  error = NULL;

  int8_t rsrq;
  QmiNasRadioInterface interface;
  if (qmi_message_nas_get_signal_strength_output_get_rsrq(output, &rsrq, &interface, NULL))
  {
    if ((interface == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte) ||
        (interface == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma))
    {
      syslog(LOG_DEBUG, "  RSRQ: %d (%s)", rsrq, qmi_nas_radio_interface_get_string(interface));
      SET_STATUS(antenna_stats.rsrq, rsrq);
    }
  }
  error = NULL;

  GArray *ecio_list;
  if (qmi_message_nas_get_signal_strength_output_get_ecio_list(output, &ecio_list, NULL))
  {
    for (size_t i = 0; i < ecio_list->len; ++i)
    {
      QmiMessageNasGetSignalStrengthOutputEcioListElement ecio;
      ecio = g_array_index(ecio_list, QmiMessageNasGetSignalStrengthOutputEcioListElement, i);
      if ((ecio.radio_interface == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte) ||
          (ecio.radio_interface == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma))
      {
        syslog(LOG_DEBUG, "  ECIO: %d (%s)", ecio.ecio, qmi_nas_radio_interface_get_string(ecio.radio_interface));
        SET_STATUS(antenna_stats.ecio, ecio.ecio);
      }
    }
  }
  error = NULL;

  qmi_message_nas_get_signal_strength_output_unref(output);
}

static void serving_system_indication_ready(QmiClientNas *object,
                                            QmiIndicationNasServingSystemOutput *output,
                                            gpointer user_data)
{
  syslog(LOG_DEBUG, "Serving system indication:");
  QmiNasRegistrationState registration_state;
  QmiNasAttachState cs_attach_state;
  QmiNasAttachState ps_attach_state;
  QmiNasNetworkType selected_network;
  GArray *radio_interfaces;

  gboolean plmn_not_changed_indication;
  if (qmi_indication_nas_serving_system_output_get_plmn_not_changed_indication
      (output, &plmn_not_changed_indication, NULL))
  {
    syslog(LOG_INFO, "  PLMN not changed: %d", plmn_not_changed_indication);
  }

  QmiNasCallBarringStatus call_barring_status_cs_status;
  QmiNasCallBarringStatus call_barring_status_ps_status;
  if (qmi_indication_nas_serving_system_output_get_call_barring_status
      (output, &call_barring_status_cs_status, &call_barring_status_ps_status, NULL))
  {
    syslog(LOG_INFO, "  CS call barring status: %s", qmi_nas_call_barring_status_get_string(call_barring_status_cs_status));
    syslog(LOG_INFO, "  PS call barring status: %s", qmi_nas_call_barring_status_get_string(call_barring_status_ps_status));
  }

  QmiNasServiceStatus detailed_service_status_status;
  QmiNasNetworkServiceDomain detailed_service_status_capability;
  QmiNasServiceStatus detailed_service_status_hdr_status;
  gboolean detailed_service_status_hdr_hybrid;
  gboolean detailed_service_status_forbidden;
  if (qmi_indication_nas_serving_system_output_get_detailed_service_status
      (output, &detailed_service_status_status,
       &detailed_service_status_capability, &detailed_service_status_hdr_status,
       &detailed_service_status_hdr_hybrid, &detailed_service_status_forbidden,
       NULL))
  {
    syslog(LOG_DEBUG, "  Service Status: %s", qmi_nas_service_status_get_string(detailed_service_status_status));
    syslog(LOG_DEBUG, "  Service capability: %s", qmi_nas_network_service_domain_get_string(detailed_service_status_capability));
    syslog(LOG_DEBUG, "  Forbidden: %d", (int)detailed_service_status_forbidden);
  }

  gboolean dtm_support;
  if (qmi_indication_nas_serving_system_output_get_dtm_support
      (output, &dtm_support, NULL))
  {
    syslog(LOG_DEBUG, "  DTM Support: %d", (int)dtm_support);
  }

  QmiNasRoamingIndicatorStatus default_roaming_indicator;
  if (qmi_indication_nas_serving_system_output_get_default_roaming_indicator
      (output, &default_roaming_indicator, NULL))
  {
    syslog(LOG_DEBUG, "  Default Roaming: %s", qmi_nas_roaming_indicator_status_get_string(default_roaming_indicator));
  }

  QmiNasRoamingIndicatorStatus roaming_indicator;
  if (qmi_indication_nas_serving_system_output_get_roaming_indicator
      (output, &roaming_indicator, NULL))
  {
    syslog(LOG_DEBUG, "  Roaming: %s", qmi_nas_roaming_indicator_status_get_string(roaming_indicator));
  }

  GArray *data_service_capability;
  if (qmi_indication_nas_serving_system_output_get_data_service_capability
      (output, &data_service_capability, NULL))
  {
    for (size_t i = 0; i < data_service_capability->len; ++i)
    {
      QmiNasDataCapability capability;
      capability = g_array_index(data_service_capability, QmiNasDataCapability, i);
      syslog(LOG_DEBUG, "  Data service capability: %s", qmi_nas_data_capability_get_string(capability));
    }
  }

  if (qmi_indication_nas_serving_system_output_get_serving_system
    (output, &registration_state, &cs_attach_state, &ps_attach_state,
     &selected_network, &radio_interfaces, NULL))
  {
    QmiNasRoamingIndicatorStatus roaming_indicator = QMI_NAS_ROAMING_INDICATOR_STATUS_OFF;
    qmi_indication_nas_serving_system_output_get_roaming_indicator(output, &roaming_indicator, NULL);
    for (size_t i = 0; i < radio_interfaces->len; ++i)
    {
      bool isValid = false;
      QmiNasRadioInterface intf = g_array_index(radio_interfaces, QmiNasRadioInterface, i);
      syslog(LOG_DEBUG, "  Network status indication (%d) for %d %s %s", i, intf, qmi_nas_radio_interface_get_string(intf), qmi_nas_registration_state_get_string(registration_state));
      if (intf == QMI_NAS_RADIO_INTERFACE_LTE && qmi_status.signal_type == TypeLte)
        isValid = true;
      else if (intf == QMI_NAS_RADIO_INTERFACE_UMTS && qmi_status.signal_type == TypeWcdma)
        isValid = true;

      if (isValid)
      {
        switch (registration_state)
        {
          case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED:
            SET_STATUS(wan_status, NoService);
            syslog(LOG_DEBUG, "  No Service");
            break;
          case QMI_NAS_REGISTRATION_STATE_REGISTERED:
            {
              if (roaming_indicator == QMI_NAS_ROAMING_INDICATOR_STATUS_ON)
              {
                SET_STATUS(wan_status, RoamingNetwork);
                syslog(LOG_DEBUG, "  Roaming");
              }
              else
              {
                SET_STATUS(wan_status, HomeNetwork);
                syslog(LOG_DEBUG, "  Home Network");
              }
            }
            break;
          case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED_SEARCHING:
            SET_STATUS(wan_status, Searching);
            syslog(LOG_DEBUG, "  Searching");
            break;
          case QMI_NAS_REGISTRATION_STATE_REGISTRATION_DENIED:
            SET_STATUS(wan_status, RegistrationDenied);
            syslog(LOG_DEBUG, "  Registration Denied");
            break;
          case QMI_NAS_REGISTRATION_STATE_UNKNOWN:
            SET_STATUS(wan_status, NoService);
            syslog(LOG_DEBUG, "  Unknown Registration");
            break;
        }
        uint32_t cid;
        if (qmi_indication_nas_serving_system_output_get_cid_3gpp(output, &cid, NULL))
          qmi_status.antenna_stats.cid = cid;
        uint16_t lac;
        if (qmi_indication_nas_serving_system_output_get_lac_3gpp(output, &lac, NULL))
          qmi_status.antenna_stats.lac = lac;
      }
    }
  }
}

static void signal_info_ready(QmiClientNas *object,
                              QmiIndicationNasSignalInfoOutput *output,
                              gpointer user_data)
{
  syslog(LOG_DEBUG, "Signal info report");

  int8_t wcdma_signal_strength_rssi;
  int16_t wcdma_signal_strength_ecio;
  if (qmi_indication_nas_signal_info_output_get_wcdma_signal_strength(output,
                                                                      &wcdma_signal_strength_rssi,
                                                                      &wcdma_signal_strength_ecio,
                                                                      NULL))
  {
    syslog(LOG_DEBUG, "  RSSI: %d, ECIO: %d\n", wcdma_signal_strength_rssi,
           wcdma_signal_strength_ecio);
  }

  int8_t lte_signal_strength_rssi;
  int8_t lte_signal_strength_rsrq;
  int16_t lte_signal_strength_rsrp;
  int16_t lte_signal_strength_snr;
  if (qmi_indication_nas_signal_info_output_get_lte_signal_strength
      (output, &lte_signal_strength_rssi, &lte_signal_strength_rsrq,
       &lte_signal_strength_rsrp, &lte_signal_strength_snr, NULL))
  {
    syslog(LOG_DEBUG, "  RSSI: %d, RSRQ: %d, RSRP: %d, SNR: %d\n", lte_signal_strength_rssi,
           lte_signal_strength_rsrq, lte_signal_strength_rsrp, lte_signal_strength_snr);
  }
}

static void system_info_ready(QmiClientNas *object,
                              QmiIndicationNasSystemInfoOutput *output,
                              gpointer user_data)
{
  syslog(LOG_DEBUG, "System Info Indication");

  gboolean lte_system_info_domain_valid;
  QmiNasNetworkServiceDomain lte_system_info_domain;
  gboolean lte_system_info_service_capability_valid;
  QmiNasNetworkServiceDomain lte_system_info_service_capability;
  gboolean lte_system_info_roaming_status_valid;
  QmiNasRoamingStatus lte_system_info_roaming_status;
  gboolean lte_system_info_forbidden_valid;
  gboolean lte_system_info_forbidden;
  gboolean lte_system_info_lac_valid;
  guint16 lte_system_info_lac;
  gboolean lte_system_info_cid_valid;
  guint32 lte_system_info_cid;
  gboolean lte_system_info_registration_reject_info_valid;
  QmiNasNetworkServiceDomain lte_system_info_registration_reject_domain;
  guint8 lte_system_info_registration_reject_cause;
  gboolean lte_system_info_network_id_valid;
  const gchar *lte_system_info_mcc;
  const gchar *lte_system_info_mnc;
  gboolean lte_system_info_tac_valid;
  guint16 lte_system_info_tac;
  if (qmi_indication_nas_system_info_output_get_lte_system_info
      (output, &lte_system_info_domain_valid, &lte_system_info_domain,
       &lte_system_info_service_capability_valid,
       &lte_system_info_service_capability, &lte_system_info_roaming_status_valid,
       &lte_system_info_roaming_status, &lte_system_info_forbidden_valid,
       &lte_system_info_forbidden, &lte_system_info_lac_valid,
       &lte_system_info_lac, &lte_system_info_cid_valid, &lte_system_info_cid,
       &lte_system_info_registration_reject_info_valid,
       &lte_system_info_registration_reject_domain,
       &lte_system_info_registration_reject_cause,
       &lte_system_info_network_id_valid, &lte_system_info_mcc,
       &lte_system_info_mnc, &lte_system_info_tac_valid, &lte_system_info_tac,
       NULL))
  {
    syslog(LOG_DEBUG, "  LTE System Information:");
    if (lte_system_info_domain_valid)
      syslog(LOG_DEBUG, "    Service Domain: %s", qmi_nas_network_service_domain_get_string(lte_system_info_domain));
    if (lte_system_info_service_capability_valid)
      syslog(LOG_DEBUG, "    Capability: %s", qmi_nas_network_service_domain_get_string(lte_system_info_service_capability));
    if (lte_system_info_roaming_status_valid)
      syslog(LOG_DEBUG, "    Roaming Status: %s", qmi_nas_roaming_status_get_string(lte_system_info_roaming_status));
    if (lte_system_info_forbidden_valid)
      syslog(LOG_DEBUG, "    Forbidden: %d", lte_system_info_forbidden);
    if (lte_system_info_lac_valid)
      syslog(LOG_DEBUG, "    LAC: %d", lte_system_info_lac);
    if (lte_system_info_cid_valid)
      syslog(LOG_DEBUG, "    CID: %d", lte_system_info_cid);
    if (lte_system_info_registration_reject_info_valid)
      syslog(LOG_DEBUG, "    Rejection for %s %d", qmi_nas_network_service_domain_get_string(lte_system_info_registration_reject_domain), lte_system_info_registration_reject_cause);
    if (lte_system_info_network_id_valid)
      syslog(LOG_DEBUG, "    MCC %s, MNC %s", lte_system_info_mcc, lte_system_info_mnc);
    if (lte_system_info_tac_valid)
      syslog(LOG_DEBUG, "    TAC: %d", lte_system_info_tac);
  }

  gboolean wcdma_system_info_domain_valid;
  QmiNasNetworkServiceDomain wcdma_system_info_domain;
  gboolean wcdma_system_info_service_capability_valid;
  QmiNasNetworkServiceDomain wcdma_system_info_service_capability;
  gboolean wcdma_system_info_roaming_status_valid;
  QmiNasRoamingStatus wcdma_system_info_roaming_status;
  gboolean wcdma_system_info_forbidden_valid;
  gboolean wcdma_system_info_forbidden;
  gboolean wcdma_system_info_lac_valid;
  guint16 wcdma_system_info_lac;
  gboolean wcdma_system_info_cid_valid;
  guint32 wcdma_system_info_cid;
  gboolean wcdma_system_info_registration_reject_info_valid;
  QmiNasNetworkServiceDomain wcdma_system_info_registration_reject_domain;
  guint8 wcdma_system_info_registration_reject_cause;
  gboolean wcdma_system_info_network_id_valid;
  const gchar *wcdma_system_info_mcc;
  const gchar *wcdma_system_info_mnc;
  gboolean wcdma_system_info_hs_call_status_valid;
  QmiNasWcdmaHsService wcdma_system_info_hs_call_status;
  gboolean wcdma_system_info_hs_service_valid;
  QmiNasWcdmaHsService wcdma_system_info_hs_service;
  gboolean wcdma_system_info_primary_scrambling_code_valid;
  guint16 wcdma_system_info_primary_scrambling_code;
  if (qmi_indication_nas_system_info_output_get_wcdma_system_info
      (output, &wcdma_system_info_domain_valid, &wcdma_system_info_domain,
       &wcdma_system_info_service_capability_valid,
       &wcdma_system_info_service_capability,
       &wcdma_system_info_roaming_status_valid,
       &wcdma_system_info_roaming_status, &wcdma_system_info_forbidden_valid,
       &wcdma_system_info_forbidden, &wcdma_system_info_lac_valid,
       &wcdma_system_info_lac, &wcdma_system_info_cid_valid,
       &wcdma_system_info_cid,
       &wcdma_system_info_registration_reject_info_valid,
       &wcdma_system_info_registration_reject_domain,
       &wcdma_system_info_registration_reject_cause,
       &wcdma_system_info_network_id_valid, &wcdma_system_info_mcc,
       &wcdma_system_info_mnc, &wcdma_system_info_hs_call_status_valid,
       &wcdma_system_info_hs_call_status, &wcdma_system_info_hs_service_valid,
       &wcdma_system_info_hs_service,
       &wcdma_system_info_primary_scrambling_code_valid,
       &wcdma_system_info_primary_scrambling_code, NULL))
  {
    syslog(LOG_DEBUG, "  WCDMA System Information:");
    if (wcdma_system_info_domain_valid)
      syslog(LOG_DEBUG, "    Service Domain: %s", qmi_nas_network_service_domain_get_string(wcdma_system_info_domain));
    if (wcdma_system_info_service_capability_valid)
      syslog(LOG_DEBUG, "    Capability: %s", qmi_nas_network_service_domain_get_string(wcdma_system_info_service_capability));
    if (wcdma_system_info_roaming_status_valid)
      syslog(LOG_DEBUG, "    Roaming Status: %s", qmi_nas_roaming_status_get_string(wcdma_system_info_roaming_status));
    if (wcdma_system_info_forbidden_valid)
      syslog(LOG_DEBUG, "    Forbidden: %d", wcdma_system_info_forbidden);
    if (wcdma_system_info_lac_valid)
      syslog(LOG_DEBUG, "    LAC: %d", wcdma_system_info_lac);
    if (wcdma_system_info_cid_valid)
      syslog(LOG_DEBUG, "    CID: %d", wcdma_system_info_cid);
    if (wcdma_system_info_registration_reject_info_valid)
      syslog(LOG_DEBUG, "    Rejection for %s %d", qmi_nas_network_service_domain_get_string(wcdma_system_info_registration_reject_domain), wcdma_system_info_registration_reject_cause);
    if (wcdma_system_info_network_id_valid)
      syslog(LOG_DEBUG, "    MCC %s, MNC %s", wcdma_system_info_mcc, wcdma_system_info_mnc);
  }
}

static void wds_info_ready(QmiClientNas *object,
                           QmiIndicationWdsPacketServiceStatusOutput *output,
                           gpointer user_data)
{
  syslog(LOG_DEBUG, "Packet Service Status Indication:");

  QmiWdsExtendedTechnologyPreference extended_technology_preference;
  if (qmi_indication_wds_packet_service_status_output_get_extended_technology_preference
      (output, &extended_technology_preference, NULL))
  {
    syslog(LOG_DEBUG, "  Technology Preference: %s",
           qmi_wds_extended_technology_preference_get_string(extended_technology_preference));
  }

  QmiWdsIpFamily ip_family;
  if (qmi_indication_wds_packet_service_status_output_get_ip_family
      (output, &ip_family, NULL))
  {
    syslog(LOG_DEBUG, "  IP Family: IPv%d", ip_family);
  }

  QmiWdsCallEndReason call_end_reason;
  if (qmi_indication_wds_packet_service_status_output_get_call_end_reason
      (output, &call_end_reason, NULL))
  {
    syslog(LOG_DEBUG, "  Call end reason: %s", qmi_wds_call_end_reason_get_string(call_end_reason));
  }

  QmiWdsVerboseCallEndReasonType verbose_call_end_reason_type;
  gint16 verbose_call_end_reason_reason;
  if (qmi_indication_wds_packet_service_status_output_get_verbose_call_end_reason
      (output, &verbose_call_end_reason_type, &verbose_call_end_reason_reason, NULL))
  {
    syslog(LOG_DEBUG, "  Verbose call end reason: %s",
           qmi_wds_verbose_call_end_reason_get_string(verbose_call_end_reason_type,
                                                      verbose_call_end_reason_reason));
  }

  QmiWdsConnectionStatus connection_status_status;
  gboolean connection_status_reconfiguration_required;
  if (qmi_indication_wds_packet_service_status_output_get_connection_status
      (output, &connection_status_status, &connection_status_reconfiguration_required, NULL))
  {
    syslog(LOG_DEBUG, "  Connection status: %s",
           qmi_wds_connection_status_get_string(connection_status_status));
    qmi_status.packet_status = connection_status_status;
    syslog(LOG_DEBUG, "  Reconfiguration required: %d", connection_status_reconfiguration_required);
  }
}


/*static void technology_preference_ready(QmiClientNas *client, GAsyncResult *res)*/
/*{*/
  /*GError *error = NULL;*/

  /*QmiMessageNasSetTechnologyPreferenceOutput *output;*/
  /*output = qmi_client_nas_set_technology_preference_finish(client, res, &error);*/
  /*if (!output)*/
  /*{*/
    /*syslog(LOG_ERR, "Failed to finish techology preference: %s", error->message);*/
    /*g_error_free(error);*/
    /*return;*/
  /*}*/

  /*if (!qmi_message_nas_set_technology_preference_output_get_result(output, &error))*/
  /*{*/
    /*syslog(LOG_ERR, "Failed to set techology preference: %s", error->message);*/
    /*g_error_free(error);*/
  /*}*/

  /*qmi_message_nas_set_technology_preference_output_unref(output);*/
/*}*/

/*static void nas_set_technology(enum SignalType type)*/
/*{*/
  /*QmiMessageNasSetTechnologyPreferenceInput *input;*/
  /*input = qmi_message_nas_set_technology_preference_input_new();*/

  /*if (type == TypeLte)*/
  /*{*/
    /*syslog(LOG_INFO, "Setting mode to LTE");*/
    /*qmi_message_nas_set_technology_preference_input_set_current*/
      /*(input, QMI_NAS_RADIO_TECHNOLOGY_PREFERENCE_LTE, QMI_NAS_PREFERENCE_DURATION_POWER_CYCLE, NULL);*/
    /*SET_STATUS(signal_type, TypeLte);*/
  /*}*/
  /*else if (type == TypeWcdma)*/
  /*{*/
    /*syslog(LOG_INFO, "Setting mode to WCDMA");*/
    /*qmi_message_nas_set_technology_preference_input_set_current*/
      /*(input, QMI_NAS_RADIO_TECHNOLOGY_PREFERENCE_CDMA_OR_WCDMA, QMI_NAS_PREFERENCE_DURATION_POWER_CYCLE, NULL);*/
    /*SET_STATUS(signal_type, TypeWcdma);*/
  /*}*/

  /*SET_STATUS(wan_status, NoService);*/

  /*qmi_client_nas_set_technology_preference*/
    /*(nas_client, input, 10, cancellable,*/
     /*(GAsyncReadyCallback)technology_preference_ready, NULL);*/

  /*qmi_message_nas_set_technology_preference_input_unref(input);*/
/*}*/

static void restrict_bands(QmiDmsLteBandCapability lte_bands, QmiDmsBandCapability bands)
{
  QmiMessageNasSetSystemSelectionPreferenceInput *input;
  input = qmi_message_nas_set_system_selection_preference_input_new();

  gchar *lte_band_str = qmi_dms_lte_band_capability_build_string_from_mask(lte_bands);
  syslog(LOG_INFO, "Selecting LTE Bands: %s", lte_band_str);
  g_free(lte_band_str);

  gchar *band_str = qmi_dms_band_capability_build_string_from_mask(bands);
  syslog(LOG_INFO, "Selecting UMTS Bands: %s", band_str);
  g_free(band_str);

  qmi_message_nas_set_system_selection_preference_input_set_lte_band_preference
    (input, lte_bands, NULL);

  qmi_message_nas_set_system_selection_preference_input_set_band_preference
    (input, bands, NULL);

  qmi_message_nas_set_system_selection_preference_input_set_modem_usage_preference
    (input, QMI_NAS_MODEM_USAGE_DATA, NULL);

  qmi_client_nas_set_system_selection_preference
    (nas_client, input, 10, cancellable,
     (GAsyncReadyCallback)system_selection_ready, NULL);

  qmi_message_nas_set_system_selection_preference_input_unref (input);
}

static void nas_set_mode(enum SignalType type)
{
  QmiMessageNasSetSystemSelectionPreferenceInput *input;
  input = qmi_message_nas_set_system_selection_preference_input_new();

  /*qmi_message_nas_set_system_selection_preference_input_set_mode_preference*/
    /*(input, QMI_NAS_RAT_MODE_PREFERENCE_UMTS | QMI_NAS_RAT_MODE_PREFERENCE_LTE, NULL);*/
  if (type == TypeLte)
  {
    syslog(LOG_INFO, "Setting mode to LTE");
    restrict_bands(qmi_settings.lte_bands, 0);
    qmi_message_nas_set_system_selection_preference_input_set_mode_preference
      (input, QMI_NAS_RAT_MODE_PREFERENCE_LTE, NULL);
    SET_STATUS(signal_type, TypeLte);
  }
  else if (type == TypeWcdma)
  {
    syslog(LOG_INFO, "Setting mode to WCDMA");
    restrict_bands(0, qmi_settings.bands);
    qmi_message_nas_set_system_selection_preference_input_set_mode_preference
      (input, QMI_NAS_RAT_MODE_PREFERENCE_UMTS, NULL);
    SET_STATUS(signal_type, TypeWcdma);
  }
  else
  {
    syslog(LOG_INFO, "Setting mode to LTE and WCDMA");
    restrict_bands(qmi_settings.lte_bands, qmi_settings.bands);
    qmi_message_nas_set_system_selection_preference_input_set_mode_preference
      (input, QMI_NAS_RAT_MODE_PREFERENCE_UMTS | QMI_NAS_RAT_MODE_PREFERENCE_LTE, NULL);
    SET_STATUS(signal_type, TypeUnknown);
  }

  GError *error = NULL;
  if (qmi_settings.enable_roaming == 0)
    qmi_message_nas_set_system_selection_preference_input_set_roaming_preference
      (input, QMI_NAS_ROAMING_PREFERENCE_OFF, &error);
  else if (qmi_settings.enable_roaming == 1)
    qmi_message_nas_set_system_selection_preference_input_set_roaming_preference
      (input, QMI_NAS_ROAMING_PREFERENCE_ANY, &error);
  else if (qmi_settings.enable_roaming == 2)
    qmi_message_nas_set_system_selection_preference_input_set_roaming_preference
      (input, QMI_NAS_ROAMING_PREFERENCE_NOT_OFF, &error);
  else if (qmi_settings.enable_roaming == 3)
    qmi_message_nas_set_system_selection_preference_input_set_roaming_preference
      (input, QMI_NAS_ROAMING_PREFERENCE_NOT_FLASHING, &error);
  if (error)
  {
    syslog(LOG_ERR, "Failed to set roaming status: %s", error->message);
    g_error_free(error);
  }

  error = NULL;
  if (!qmi_message_nas_set_system_selection_preference_input_set_modem_usage_preference
    (input, QMI_NAS_MODEM_USAGE_DATA, NULL))
  {
    syslog(LOG_ERR, "Failed to set modem usage preference: %s", error->message);
    g_error_free(error);
  }

  error = NULL;
  if (!qmi_message_nas_set_system_selection_preference_input_set_service_domain_preference
      (input, qmi_settings.domain, &error))
  {
    syslog(LOG_ERR, "Failed to set domain preference: %s", error->message);
    g_error_free(error);
  }
  else
  {
    syslog(LOG_INFO, "Domain Preference: %s",
           qmi_nas_service_domain_preference_get_string(qmi_settings.domain));
  }

  SET_STATUS(wan_status, NoService);

  qmi_client_nas_set_system_selection_preference
    (nas_client, input, 10, cancellable,
     (GAsyncReadyCallback)system_selection_ready, NULL);

  qmi_message_nas_set_system_selection_preference_input_unref(input);
}

static void setup_voice(void)
{
  QmiMessageVoiceSetConfigInput *input;

  input = qmi_message_voice_set_config_input_new();

  qmi_message_voice_set_config_input_set_preferred_voice_domain(input, QMI_VOICE_DOMAIN_CS_ONLY, NULL);

  qmi_client_voice_set_config(voice_client, input, QMI_TIMEOUT, NULL, (GAsyncReadyCallback)set_voice_ready, NULL);

  qmi_message_voice_set_config_input_unref(input);
}

static void setup_nas(void)
{
  {
    g_signal_connect(nas_client, "event-report", G_CALLBACK(event_report_ready), NULL);
    g_signal_connect(nas_client, "serving-system", G_CALLBACK(serving_system_indication_ready), NULL);
    g_signal_connect(nas_client, "signal-info", G_CALLBACK(signal_info_ready), NULL);
    g_signal_connect(nas_client, "system-info", G_CALLBACK(system_info_ready), NULL);
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
      (input, true, 0, NULL);

    qmi_message_nas_set_event_report_input_set_ecio_indicator
      (input, true, 0, NULL);

    qmi_message_nas_set_event_report_input_set_ecio_indicator
      (input, true, 0, NULL);

    qmi_message_nas_set_event_report_input_set_registration_reject_reason
      (input, true, NULL);

    qmi_client_nas_set_event_report
      (nas_client, input, QMI_TIMEOUT, NULL, (GAsyncReadyCallback)nas_event_report_ready, NULL);

    qmi_message_nas_set_event_report_input_unref(input);
  }

  {
    QmiMessageNasRegisterIndicationsInput *input;
    input = qmi_message_nas_register_indications_input_new();

    qmi_message_nas_register_indications_input_set_rf_band_information(input, true, NULL);
    qmi_message_nas_register_indications_input_set_managed_roaming(input, true, NULL);
    qmi_message_nas_register_indications_input_set_signal_info(input, true, NULL);
    qmi_message_nas_register_indications_input_set_system_info(input, true, NULL);
    qmi_message_nas_register_indications_input_set_subscription_info(input, true, NULL);
    qmi_message_nas_register_indications_input_set_serving_system_events(input, true, NULL);
    qmi_message_nas_register_indications_input_set_system_selection_preference(input, true, NULL);

    qmi_client_nas_register_indications
      (nas_client, input, QMI_TIMEOUT, NULL, (GAsyncReadyCallback)nas_register_indications_ready, NULL);

    qmi_message_nas_register_indications_input_unref(input);
  }
}

static void imsi_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsUimGetImsiOutput *output = qmi_client_dms_uim_get_imsi_finish
    (dms_client, res, &error);
  if (!output) {
    syslog(LOG_ERR, "Couldn't finish imsi get: %s", error->message);
    g_error_free(error);
    return;
  }

  if (!qmi_message_dms_uim_get_imsi_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to read IMSI: %s", error->message);
    qmi_message_dms_uim_get_imsi_output_unref(output);
    g_error_free(error);
    return;
  }
  const gchar *imsi = NULL;
  if (!qmi_message_dms_uim_get_imsi_output_get_imsi(output, &imsi, &error))
  {
    syslog(LOG_ERR, "Failed to extract IMSI: %s", error->message);
    g_error_free(error);
    qmi_message_dms_uim_get_imsi_output_unref(output);
    return;
  }
  char *imsi_dup = strdup(imsi);
  SET_STATUS(imsi, imsi_dup);
  qmi_message_dms_uim_get_imsi_output_unref(output);
}

static void msisdn_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetMsisdnOutput *output = qmi_client_dms_get_msisdn_finish
    (dms_client, res, &error);
  if (!output) {
    syslog(LOG_ERR, "Couldn't finish msisdn get: %s", error->message);
    g_error_free(error);
    return;
  }

  if (!qmi_message_dms_get_msisdn_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to read MSISDN: %s", error->message);
    qmi_message_dms_get_msisdn_output_unref(output);
    g_error_free(error);
    return;
  }

  const gchar *msisdn = NULL;
  if (!qmi_message_dms_get_msisdn_output_get_msisdn(output, &msisdn, &error))
  {
    syslog(LOG_ERR, "Failed to extract MSISDN: %s", error->message);
    qmi_message_dms_get_msisdn_output_unref(output);
    g_error_free(error);
    return;
  }
  char *msisdn_dup = strdup(msisdn);
  SET_STATUS(msisdn, msisdn_dup);
  qmi_message_dms_get_msisdn_output_unref(output);
}

static void ids_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetIdsOutput *output;
  output = qmi_client_dms_get_ids_finish(dms_client, res, &error);
  if (!output) {
    syslog(LOG_ERR, "Couldn't finish ids get: %s", error->message);
    g_error_free(error);
    return;
  }

  if (!qmi_message_dms_get_ids_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to read ids: %s", error->message);
    qmi_message_dms_get_ids_output_unref(output);
    g_error_free(error);
    return;
  }

  const gchar *esn = NULL;
  if (qmi_message_dms_get_ids_output_get_esn(output, &esn, NULL))
    syslog(LOG_INFO, "ESN: %s", esn);

  const gchar *meid = NULL;
  if (qmi_message_dms_get_ids_output_get_meid(output, &meid, NULL))
    syslog(LOG_INFO, "MEID: %s", meid);

  const gchar *imei = NULL;
  if (!qmi_message_dms_get_ids_output_get_imei(output, &imei, &error))
  {
    syslog(LOG_ERR, "Failed to extract IMEI: %s", error->message);
    qmi_message_dms_get_ids_output_unref(output);
    g_error_free(error);
    return;
  }
  char *imei_dup = strdup(imei);
  SET_STATUS(imei, imei_dup);
  qmi_message_dms_get_ids_output_unref(output);
}

static void manufacturer_ready(QmiClientDms *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetManufacturerOutput *output;
  output = qmi_client_dms_get_manufacturer_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish manufacturer: %s", error->message);
    g_error_free(error);
    return;
  }

  if (qmi_message_dms_get_manufacturer_output_get_result(output, NULL))
  {
    const gchar *manufacturer;
    if (qmi_message_dms_get_manufacturer_output_get_manufacturer(output, &manufacturer, NULL))
    {
      qmi_status.manufacturer = strdup(manufacturer);
      syslog(LOG_INFO, "Modem manufacturer: %s", manufacturer);
    }
  }

  qmi_message_dms_get_manufacturer_output_unref(output);
}

static void model_ready(QmiClientDms *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetModelOutput *output;
  output = qmi_client_dms_get_model_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish model: %s", error->message);
    g_error_free(error);
    return;
  }

  if (qmi_message_dms_get_model_output_get_result(output, NULL))
  {
    const gchar *model;
    if (qmi_message_dms_get_model_output_get_model(output, &model, NULL))
    {
      qmi_status.model = strdup(model);
      syslog(LOG_INFO, "Modem model: %s", model);
    }
  }

  qmi_message_dms_get_model_output_unref(output);
}

static void revision_ready(QmiClientDms *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetRevisionOutput *output;
  output = qmi_client_dms_get_revision_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish revision: %s", error->message);
    g_error_free(error);
    return;
  }

  if (qmi_message_dms_get_revision_output_get_result(output, NULL))
  {
    const gchar *revision;
    if (qmi_message_dms_get_revision_output_get_revision(output, &revision, NULL))
    {
      qmi_status.revision = strdup(revision);
      syslog(LOG_INFO, "Modem revision: %s", revision);
    }
  }

  qmi_message_dms_get_revision_output_unref(output);
}

static void band_capabilities_ready(QmiClientDms *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageDmsGetBandCapabilitiesOutput *output;
  output = qmi_client_dms_get_band_capabilities_finish(client, res, &error);
  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish band capabilities: %s", error->message);
    g_error_free(error);
    return;
  }

  if (qmi_message_dms_get_band_capabilities_output_get_result(output, NULL))
  {
    QmiDmsLteBandCapability lte_band_capability;
    if (qmi_message_dms_get_band_capabilities_output_get_lte_band_capability
        (output, &lte_band_capability, NULL))
    {
      QmiDmsLteBandCapability supported = QMI_DMS_LTE_BAND_CAPABILITY_EUTRAN_2
                                        | QMI_DMS_LTE_BAND_CAPABILITY_EUTRAN_3
                                        | QMI_DMS_LTE_BAND_CAPABILITY_EUTRAN_4
                                        | QMI_DMS_LTE_BAND_CAPABILITY_EUTRAN_25;
      qmi_settings.lte_bands = supported & lte_band_capability;
    }
    QmiDmsBandCapability band_capability;
    if (qmi_message_dms_get_band_capabilities_output_get_band_capability
        (output, &band_capability, NULL))
    {
      QmiDmsBandCapability supported = QMI_DMS_BAND_CAPABILITY_WCDMA_2100;
      qmi_settings.bands = supported & band_capability;
    }
  }

  qmi_message_dms_get_band_capabilities_output_unref(output);
}

static void setup_dms(void)
{
  syslog(LOG_INFO, "Requesting PIN Status");
  qmi_client_dms_uim_get_pin_status(dms_client, NULL, QMI_TIMEOUT,
                                    cancellable,
                                    (GAsyncReadyCallback)pin_status_ready,
                                    NULL);
  qmi_client_dms_uim_get_imsi(dms_client, NULL, QMI_TIMEOUT, cancellable,
                              (GAsyncReadyCallback)imsi_ready, NULL);
  qmi_client_dms_get_msisdn(dms_client, NULL, QMI_TIMEOUT, cancellable,
                            (GAsyncReadyCallback)msisdn_ready, NULL);
  qmi_client_dms_get_ids(dms_client, NULL, QMI_TIMEOUT, cancellable,
                         (GAsyncReadyCallback)ids_ready, NULL);
  qmi_client_dms_get_manufacturer(dms_client, NULL, QMI_TIMEOUT, cancellable,
                                  (GAsyncReadyCallback)manufacturer_ready, NULL);
  qmi_client_dms_get_model(dms_client, NULL, QMI_TIMEOUT, cancellable,
                                  (GAsyncReadyCallback)model_ready, NULL);
  qmi_client_dms_get_revision(dms_client, NULL, QMI_TIMEOUT, cancellable,
                                  (GAsyncReadyCallback)revision_ready, NULL);
  qmi_client_dms_get_band_capabilities(dms_client, NULL, QMI_TIMEOUT,
                                       cancellable,
                                       (GAsyncReadyCallback)band_capabilities_ready,
                                       NULL);
}

static void allocate_client_ready(QmiDevice *dev, GAsyncResult *res)
{
  GError *error = NULL;

  QmiClient *client = qmi_device_allocate_client_finish(dev, res, &error);
  if (!client) {
    syslog(LOG_ERR, "Couldn't create client for service: %s\n", error->message);
    g_error_free(error);
    exit(QMI_ERROR);
  }

  QmiService service = qmi_client_get_service(client);

  switch (service) {
    case QMI_SERVICE_DMS:
      dms_client = QMI_CLIENT_DMS(client);
      setup_dms();
      return;
    case QMI_SERVICE_NAS:
      nas_client = QMI_CLIENT_NAS(client);
      setup_nas();
      return;
    case QMI_SERVICE_WDS:
      wds_client = QMI_CLIENT_WDS(client);
      g_signal_connect(wds_client, "packet-service-status", G_CALLBACK(wds_info_ready), NULL);
      return;
    case QMI_SERVICE_UIM:
      uim_client = QMI_CLIENT_UIM(client);
      return;
    case QMI_SERVICE_CTL:
      ctl_client = client;
      return;
    case QMI_SERVICE_VOICE:
      voice_client = QMI_CLIENT_VOICE(client);
      setup_voice();
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
    g_error_free(error);
    exit(QMI_ERROR);
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
  qmi_device_allocate_client(dev, QMI_SERVICE_VOICE, QMI_CID_NONE, 10, cancellable,
                             (GAsyncReadyCallback)allocate_client_ready, NULL);
}

static void device_new_ready(GObject *unused, GAsyncResult *res)
{
  GError *error = NULL;

  device = qmi_device_new_finish (res, &error);
  if (!device)
  {
    syslog(LOG_ERR, "Couldn't create QmiDevice: %s\n", error->message);
    g_error_free(error);
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
    if (error->code == QMI_CORE_ERROR_WRONG_STATE)
    {
      syslog(LOG_ERR, "Restarting umtsd, device no longer available");
      exit(QMI_ERROR);
    }
    g_error_free(error);
    return;
  }

  if (!qmi_message_wds_get_packet_service_status_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to get service status: %s", error->message);
    g_error_free(error);
  }

  if (qmi_message_wds_get_packet_service_status_output_get_connection_status
      (output, &qmi_status.packet_status, NULL))
  {
    syslog(LOG_DEBUG, "Packet status is: %s",
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
    g_error_free(error);
    return;
  }

  bool isConnected = true;
  if (qmi_message_wds_start_network_output_get_packet_data_handle(output,
                                                                  &qmi_status.packet_data_handle,
                                                                  NULL))
  {
    syslog(LOG_INFO, "Data handle: %d", qmi_status.packet_data_handle);
  }
  else
  {
    isConnected = false;
    qmi_status.packet_data_handle = 0xffffffff;
  }
  error = NULL;

  if (!qmi_message_wds_start_network_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to get network start: %s", error->message);
    isConnected = false;
    g_error_free(error);
  }
  error = NULL;

  if (!isConnected)
  {
    stop_network();
    apn_list = apn_list->next;
  }

  QmiWdsCallEndReason end_reason;
  if (qmi_message_wds_start_network_output_get_call_end_reason(output, &end_reason, NULL))
  {
    syslog(LOG_INFO, "Call end reason: %s", qmi_wds_call_end_reason_get_string(end_reason));
  }
  error = NULL;

  QmiWdsVerboseCallEndReasonType v_reason_type;
  int16_t v_reason_reason;
  if (qmi_message_wds_start_network_output_get_verbose_call_end_reason(output,
                                                                       &v_reason_type,
                                                                       &v_reason_reason,
                                                                       NULL))
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
  qmi_status.packet_data_handle = 0x0;

  GError *error = NULL;
  QmiMessageWdsStartNetworkInput *input;

  input = qmi_message_wds_start_network_input_new();

  if (!qmi_message_wds_start_network_input_set_enable_autoconnect(input, true, &error))
  {
    syslog(LOG_ERR, "Failed to set autoconnect field to true: %s", error->message);
    g_error_free(error);
    error = NULL;
  }

  if (apn_list)
  {
    syslog(LOG_INFO, "Attempting to connect with %s %s", apn_list->apn, apn_list->username);
    if (!qmi_message_wds_start_network_input_set_apn(input, apn_list->apn, &error))
    {
      syslog(LOG_ERR, "Failed to set APN: %s", error->message);
      g_error_free(error);
    }
    error = NULL;
    if (apn_list->username && strcmp(apn_list->username, ""))
      if (!qmi_message_wds_start_network_input_set_username(input, apn_list->username, &error))
      {
        syslog(LOG_ERR, "Failed to set username: %s", error->message);
        g_error_free(error);
      }
    error = NULL;
    if (apn_list->password && strcmp(apn_list->password, ""))
      if (!qmi_message_wds_start_network_input_set_password(input, apn_list->password, &error))
      {
        syslog(LOG_ERR, "Failed to set password: %s", error->message);
        g_error_free(error);
      }
    error = NULL;
    qmi_message_wds_start_network_input_set_authentication_preference
      (input, QMI_WDS_AUTHENTICATION_PAP | QMI_WDS_AUTHENTICATION_CHAP, NULL);
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
    g_error_free(error);
    return;
  }

  if (!qmi_message_wds_stop_network_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Failed to stop network: %s", error->message);
    g_error_free(error);
  }

  qmi_message_wds_stop_network_output_unref(output);
}

static void stop_network(void)
{
  QmiMessageWdsStopNetworkInput *input;
  input = qmi_message_wds_stop_network_input_new();

  qmi_message_wds_stop_network_input_set_disable_autoconnect(input, true, NULL);
  qmi_message_wds_stop_network_input_set_packet_data_handle(input,
                                                            qmi_status.packet_data_handle,
                                                            NULL);

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
    g_error_free(error);
  }
  error = NULL;
  if (!qmi_message_wds_stop_network_input_set_packet_data_handle(input,
                                                                 0xffffffff,
                                                                 &error))
  {
    syslog(LOG_ERR, "Failed to set data handle disabing autoconnect: %s", error->message);
    g_error_free(error);
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
  StateDownloadTest,
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
  {2, TypeLte,   false, false, 0},
  {2, TypeWcdma, false, false, 0},
  {3, TypeLte,   false, false, 0},
  {3, TypeWcdma, false, false, 0},
  {1, TypeLte,   false, false, 0},
  {1, TypeWcdma, false, false, 0},
  {0, TypeLte,   false, false, 0},
  {0, TypeWcdma, false, false, 0},
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

void query_signal_strength(void)
{
  GError *error = NULL;

  QmiMessageNasGetSignalStrengthInput *input;
  input = qmi_message_nas_get_signal_strength_input_new();

  if (!qmi_message_nas_get_signal_strength_input_set_request_mask
      (input, QMI_NAS_SIGNAL_STRENGTH_REQUEST_RSSI |
       QMI_NAS_SIGNAL_STRENGTH_REQUEST_ECIO |
       QMI_NAS_SIGNAL_STRENGTH_REQUEST_SINR |
       QMI_NAS_SIGNAL_STRENGTH_REQUEST_RSRQ |
       QMI_NAS_SIGNAL_STRENGTH_REQUEST_LTE_SNR |
       QMI_NAS_SIGNAL_STRENGTH_REQUEST_LTE_RSRP, &error))
  {
    syslog(LOG_ERR, "Failed to set signal strength request mask: %s", error->message);
    g_error_free(error);
  }

  qmi_client_nas_get_signal_strength
    (nas_client, input, QMI_TIMEOUT, cancellable,
     (GAsyncReadyCallback)signal_strength_ready, NULL);

  qmi_message_nas_get_signal_strength_input_unref(input);
}

static bool is_mode_enabled(enum SignalType type)
{
  // As of 2015-06-17 the factory only has a 3G test basestation, all test SIMs
  // have an IMSI starting with 001
  if (type == TypeLte && !strncmp("001", qmi_status.imsi, 3))
  {
    syslog(LOG_WARNING, "Disabling LTE due to 001 MCC");
    return false;
  }

  return (type == TypeLte && strstr(qmi_settings.modes, "lte"))
    || (type == TypeWcdma && strstr(qmi_settings.modes, "umts"));
}

static bool is_beam_enabled(uint8_t beam)
{
  return strchr(qmi_settings.antenna, '0' + beam);
}

static void network_register_ready(QmiClientNas *client, GAsyncResult *res)
{
  GError *error = NULL;

  QmiMessageNasInitiateNetworkRegisterOutput *output = NULL;
  output = qmi_client_nas_initiate_network_register_finish(client, res, &error);

  if (!output)
  {
    syslog(LOG_ERR, "Failed to finish network registration: %s", error->message);
    g_error_free(error);
    return;
  }

  if (!qmi_message_nas_initiate_network_register_output_get_result(output, &error))
  {
    syslog(LOG_ERR, "Registration failed: %s", error->message);
  }
  else
  {
    syslog(LOG_INFO, "Registration complete");
  }

  qmi_message_nas_initiate_network_register_output_unref(output);
}

static void register_network(void)
{
  QmiMessageNasInitiateNetworkRegisterInput *input;
  input = qmi_message_nas_initiate_network_register_input_new();

  /*qmi_message_nas_initiate_network_register_input_set_manual_registration_info_3gpp*/
    /*(input, 234, 30, QMI_NAS_RADIO_INTERFACE_LTE, NULL);*/

  qmi_message_nas_initiate_network_register_input_set_action
    (input, QMI_NAS_NETWORK_REGISTER_TYPE_AUTOMATIC, NULL);

  qmi_client_nas_initiate_network_register(nas_client, input, QMI_TIMEOUT,
                                           cancellable,
                                           (GAsyncReadyCallback)network_register_ready,
                                           NULL);

  qmi_message_nas_initiate_network_register_input_unref(input);
}

char *interface_byte_count(const char *interface, int field)
{
  static char line[1024];
  char *token = NULL;
  int count;
  int done = 0;
  FILE *proc_file;

  if (!interface) return NULL;

  proc_file = fopen("/proc/net/dev", "r");
  if (proc_file == NULL) return NULL;

  fgets(line, 1024, proc_file);
  while (!feof(proc_file) && !done)
  {
    token = strtok(line, " :");

    if (token != NULL && strcmp(token, interface) == 0) {
      for (count = 0; count < field; ++count) {
        token = strtok(NULL, " :");
      }
      done = 1;
    }
    else
      fgets(line, 1024, proc_file);
  }

  fclose (proc_file);
  if (done) return token;

  return NULL;
}

long long download_byte_count(const char *interface)
{
  char *token = interface_byte_count("wwan0", 1);
  if (token == NULL) return -1;

  return strtoll(token, NULL, 10);
}

static int open_timer(time_t startup_delay_s, long interval_s)
{
  int fd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (fd < 0)
    return -1;

  struct itimerspec timer = {
    .it_interval = {.tv_sec = interval_s, .tv_nsec = 0},
    .it_value = {.tv_sec = startup_delay_s, .tv_nsec = 0}
  };

  int err = timerfd_settime(fd, 0, &timer, NULL);
  if (err < 0)
    return -1;

  return fd;
}

static void wait_for_timer(int timer_fd)
{
  uint64_t exp;
  int err = read(timer_fd, &exp, sizeof(uint64_t));
  assert(err == sizeof(uint64_t));
}

static void start_download(int threads, const char *host, const char *file)
{
  char *command;

  asprintf(&command,
           "for i in `seq %d`; do ( /usr/sbin/download_data %s \"%s\" & ); done",
           threads, host, file);
  system(command);
  sleep(1);
  free(command);
}

void stop_download(void)
{
  system("killall download_data");
}

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
           __typeof__ (b) _b = (b); \
         _a < _b ? _a : _b; })

static bool starts_with(const char * const a, const char * const b)
{
  return !strncmp(a, b, min(strlen(a), strlen(b)));
}

static const char *at_parse_line(const char * const line)
{
  const char *rs = NULL;

  if (starts_with(line, "PRI Part Number: "))
    qmi_status.pri_pri = strdup(line+strlen("PRI Part Number: "));
  else if (starts_with(line, "Carrier PRI: "))
    qmi_status.pri_carrier_pri = strdup(line+strlen("Carrier PRI: "));
  else if (starts_with(line, "Revision: "))
    qmi_status.pri_revision = strdup(line+strlen("Revision: "));
  else if (starts_with(line, "+CGAUTH: 1,"))
  {
    rs = line+strlen("+CGAUTH: ");
    syslog(LOG_DEBUG, "Auth: %s", rs);
  }
  else if (starts_with(line, "+CGAUTH: "))
  {
    /* Throw away all other CGAUTH lines */
  }
  else if (starts_with(line, "+CGDCONT: 1,"))
  {
    rs = line+strlen("+CGDCONT: ");
    syslog(LOG_DEBUG, "Context: %s", rs);
  }
  else if (starts_with(line, "+CGDCONT: "))
  {
    /* Throw away all other CGDCONT lines */
  }
  else
    syslog(LOG_DEBUG, "Read '%s'", line);

  return rs ? strdup(rs) : NULL;
}

static bool file_is_char_device(const char *filename)
{
  struct stat device_stat;
  lstat(filename, &device_stat);
  return S_ISCHR(device_stat.st_mode);
}

static void at_readline(int fd, char *line)
{
  size_t lineWrite = 0;
  while (1)
  {
    int n = read(fd, line + lineWrite, 1);
    lineWrite += n;
    line[lineWrite] = '\0';
    if (lineWrite >= 1 && line[lineWrite-1] == '\n')
    {
      line[lineWrite-1] = '\0';
      break;
    }
  }
}

static bool at_is_ok(const char * const line)
{
  return !strncmp(line, "OK", 2);
}

static bool at_is_error(const char * const line)
{
  return !strncmp(line, "ERROR", 5);
}

static bool at_is_empty(const char * const line)
{
  return strlen(line) == 0;
}

static int at_configure(int fd, int speed, int parity)
{
  struct termios tty;
  memset (&tty, 0, sizeof tty);
  if (tcgetattr (fd, &tty) != 0)
  {
    syslog(LOG_ERR, "error %d from tcgetattr", errno);
    return -1;
  }

  cfsetospeed (&tty, speed);
  cfsetispeed (&tty, speed);

  tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
  tty.c_iflag &= ~IGNBRK;         // disable break processing
  tty.c_lflag = 0;                // no signaling chars, no echo,
  tty.c_oflag = 0;                // no remapping, no delays
  tty.c_cc[VMIN]  = 0;            // read doesn't block
  tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

  tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

  tty.c_cflag &= ~(CLOCAL | CREAD);
  tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
  tty.c_cflag |= parity;
  tty.c_cflag &= ~CSTOPB;
  tty.c_cflag &= ~CRTSCTS;

  if (tcsetattr (fd, TCSANOW, &tty) != 0)
  {
    syslog(LOG_ERR, "error %d from tcsetattr", errno);
    return -1;
  }
  return 0;
}

static const char* at_run_cmd(int fd, const char * const cmd)
{
  syslog(LOG_DEBUG, "AT Run: %s", cmd);
  write(fd, cmd, strlen(cmd));

  const char *rv = NULL;
  char line[512];
  while (1)
  {
    at_readline(fd, line);
    if (at_is_ok(line))
    {
      break;
    }
    else if (at_is_error(line))
    {
      syslog(LOG_ERR, "AT command error: %s %s", cmd, line);
      break;
    }
    else if (!at_is_empty(line))
    {
      const char *tmp = at_parse_line(line);
      if (tmp)
        rv = tmp;
    }
  }

  syslog(LOG_DEBUG, "AT Response: %s", rv ? rv : "");
  return rv;
}

#define AT_LEN 256

static void at_set_context(int fd,
                           const char * const apn,
                           const char * const username,
                           const char * const password)
{
  char context[AT_LEN];
  char auth[AT_LEN];
  snprintf(context, AT_LEN, "1,\"IPV4V6\",\"%s\"", apn);

  int auth_type = 0;
  if (password && strcmp(password, ""))
  {
    if (!username || !strcmp(username, ""))
    {
      // CHAP, password only
      auth_type = 2;
      snprintf(auth, AT_LEN, "1,%d", auth_type);
    }
    else
    {
      // PAP, password and username
      auth_type = 1;
      snprintf(auth, AT_LEN, "1,%d,\"%s\"", auth_type, username);
    }
  }
  else
  {
    // No username/password
    auth_type = 0;
    snprintf(auth, AT_LEN, "1,%d", auth_type);
  }

  const char *current_context = at_run_cmd(fd, "AT+CGDCONT?\r");
  if (current_context && strncmp(current_context, context, strlen(context)))
  {
    free((char*)current_context);
    char cmd[AT_LEN];
    snprintf(cmd, AT_LEN, "AT+CGDCONT=%s\r", context);
    at_run_cmd(fd, cmd);

    current_context = at_run_cmd(fd, "AT+CGDCONT?\r");
    if (strncmp(current_context, context, strlen(context)))
      syslog(LOG_ERR, "Failed to set context: %s %s", current_context, context);
    else
      syslog(LOG_INFO, "PDP context set: %s", context);
  }
  else
  {
    syslog(LOG_INFO, "PDP context correct: %s", current_context);
  }
  free((char*)current_context);

  const char *current_auth = at_run_cmd(fd, "AT+CGAUTH?\r");
  if (current_auth && strncmp(current_auth, auth, strlen(auth)))
  {
    free((char*)current_auth);
    char cmd[AT_LEN];
    switch (auth_type)
    {
      case 0:
        snprintf(cmd, AT_LEN, "AT+CGAUTH=1,0\r");
        break;
      case 1:
        snprintf(cmd, AT_LEN, "AT+CGAUTH=1,1,\"%s\",\"%s\"\r", password, username);
        break;
      case 2:
        snprintf(cmd, AT_LEN, "AT+CGAUTH=1,2,\"%s\"\r", password);
        break;
    }
    at_run_cmd(fd, cmd);

    current_auth = at_run_cmd(fd, "AT+CGAUTH?\r");
    if (strncmp(current_auth, auth, strlen(auth)))
      syslog(LOG_DEBUG, "Failed to set auth: %s %s", current_auth, auth);
    else
      syslog(LOG_INFO, "PDP auth set: %s", auth);
  }
  else
  {
    syslog(LOG_INFO, "PDP auth correct: %s", current_auth);
  }
  free((char*)current_auth);
}

static void at_setup(void)
{
  const char *port = "/dev/ttyUSB2";
  if (!file_is_char_device(port))
    return;

  int fd = open(port, O_RDWR | O_NOCTTY);
  if (fd < 0)
  {
    syslog(LOG_DEBUG, "Failed to open %s: %s", port, strerror(errno));
    return;
  }

  at_configure(fd, B115200, 0);
  at_run_cmd(fd, "ATE0\r");

  at_run_cmd(fd, "AT!PRIID?\r");


  sim_apn_generate_list();
  if (apn_list)
    at_set_context(fd, apn_list->apn, apn_list->username, apn_list->password);

  close(fd);
}

gboolean main_check(gpointer data)
{
  static int timer_fd;
  if (wdog_fd != -1)
    write(wdog_fd, "w", 1);

  if (!nas_client || !wds_client)
    return TRUE;

  enum State next_state = current_state;

  switch (current_state)
  {
    case StateStartup:
      {
        syslog(LOG_DEBUG, "UMTSD Startup");
        restrict_bands(qmi_settings.lte_bands, qmi_settings.bands);
        if (!qmi_status.imsi || strlen(qmi_status.imsi) < 3)
          break;
        for (size_t i = 0; i < BEAM_TEST_COUNT; ++i)
          if (is_mode_enabled(beam_tests[i].type))
            if (is_beam_enabled(beam_tests[i].beam))
              beam_tests[i].included = true;
        syslog(LOG_DEBUG, "UMTSD Startup 2");

        qmi_status.download_tests_complete = 0;
        qmi_status.download_tests_remaining = 0;

        query_data_connection();
        disable_autoconnect();
        at_setup();
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
        qmi_status.antenna_testing = true;
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
            syslog(LOG_INFO, "Testing antenna %d/%s (%s)", current_beam->beam,
                   AntennaText[current_beam->beam],
                   SignalTypeText[current_beam->type]);
            nas_set_mode(current_beam->type);
            memset(&qmi_status.antenna_stats, 0, sizeof(struct AntennaResult));
            antenna_select(current_beam->beam, current_beam->type == TypeLte);
            antenna_led_searching();
            changed_beam = true;
            break;
          }
        register_network();
        query_signal_strength();
        query_serving_system();
        next_state = (changed_beam) ? StateWaitForBeam : StateTestsComplete;
      }
      break;
    case StateWaitForBeam:
      syslog(LOG_DEBUG, "Waiting for antenna test to complete");
      query_signal_strength();
      query_serving_system();
      if (qmi_status.antenna_stats.test_complete && (qmi_status.wan_status == HomeNetwork || qmi_status.wan_status == RoamingNetwork))
      {
        next_state = StateSaveResults;
      }
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
      snmp_write_antenna_test();
      next_state = StateNextBeam;
      break;
    case StateTestsComplete:
      {
        qmi_status.antenna_testing = false;
        const struct AntennaResult *antenna = NULL;
        if (qmi_status.download_tests_remaining & (1 << TypeLte))
        {
          // Remaining LTE download test
          antenna = antenna_find_best_of_type(TypeLte);
        }
        else if (qmi_settings.download_test > 0 && !qmi_status.download_tests_complete)
        {
          const struct AntennaResult *best_wcdma;
          const struct AntennaResult *best_lte;
          best_wcdma = antenna_find_best_of_type(TypeWcdma);
          best_lte = antenna_find_best_of_type(TypeLte);
          if (best_wcdma && best_lte)
          {
            antenna = best_wcdma;
            qmi_status.download_tests_remaining = (1 << TypeLte) | (1 << TypeWcdma);
          }
          else
          {
            syslog(LOG_INFO, "Download test requires WCDMA and LTE service, skipping...");
            antenna = antenna_find_best();
          }
        }
        else
        {
          antenna = antenna_find_best();
        }
        syslog(LOG_INFO, "Selected antenna %s (%s)", AntennaText[antenna->antenna],
               SignalTypeText[antenna->type]);
        nas_set_mode(antenna->type);
        antenna_select(antenna->antenna, false);
        antenna_led_selected(antenna->type == TypeLte);
        snmp_write_antenna_test();
        write_result_txt(antenna->antenna);
        next_state = StateRegister;
      }
      break;
    case StateRegister:
      nas_set_mode(TypeUnknown);
      syslog(LOG_DEBUG, "Registering");
      qmi_status.registration_start = time(NULL);
      SET_STATUS(wan_status, NoService);
      query_serving_system();
      register_network();
      next_state = StateRegisterWait;
      break;
    case StateRegisterWait:
      if (qmi_status.wan_status == HomeNetwork || qmi_status.wan_status == RoamingNetwork)
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
      if (qmi_status.wan_status != HomeNetwork && qmi_status.wan_status != RoamingNetwork)
      {
        next_state = StateRegister;
      }
      else
      {
        sim_apn_generate_list();
        if (!apn_list)
        {
          syslog(LOG_ERR, "No APNs found for SIM %s", qmi_status.imsi);
          break;
        }
        next_state = StateTryApn;
      }
      break;
    case StateTryApn:
      syslog(LOG_DEBUG, "Trying next APN");
      if (!apn_list)
      {
        syslog(LOG_ERR, "No more APNs for SIM, restarting");
        next_state = StateDataConnect;
      }
      else
      {
        start_network();
        next_state = StateDataConnectWait;
      }
      break;
    case StateDataConnectWait:
      syslog(LOG_DEBUG, "Waiting for data connection");
      query_data_connection();
      if (qmi_status.packet_data_handle != 0xffffffff
          && qmi_status.packet_status == QMI_WDS_CONNECTION_STATUS_CONNECTED)
      {
        net_renew_lease();
        if (qmi_status.download_tests_remaining)
          next_state = StateDownloadTest;
        else
          next_state = StateMonitorData;
      }
      else if (qmi_status.packet_data_handle == 0xffffffff)
      {
        next_state = StateTryApn;
      }
      break;
    case StateDownloadTest:
      {
        int threads = 3;
        const char *hostname = "172.17.13.123";
        const char *filename = "/16MB.bin";
        start_download(threads, hostname, filename);

        long long last_byte_count = download_byte_count("wwan0");
        timer_fd = open_timer(1, 1);
        if (timer_fd < 0)
        {
          perror("Failed to open timerfd");
          stop_download();
          return 1;
        }

        long long latest_byte_count;
        long long downloaded;
        double mbps;
        const size_t measurements = 2;
        for (size_t i = 0; i < measurements; ++i)
        {
          wait_for_timer(timer_fd);
          latest_byte_count = download_byte_count("wwan0");
          downloaded = latest_byte_count - last_byte_count;
          mbps = ((downloaded/(measurements+1.0) * 8.0) / 1024.0 / 1024.0);
          syslog(LOG_INFO, "Downloaded %lli bytes, %.02f Mbps\n", downloaded, mbps);
        }

        stop_download();
        close(timer_fd);

        syslog(LOG_INFO, "Download test complete for %s", SignalTypeText[qmi_status.signal_type]);
        qmi_status.download_tests_remaining &= ~(1 << qmi_status.signal_type);
        qmi_status.download_tests_complete |= (1 << qmi_status.signal_type);
        if (qmi_status.download_tests_remaining)
        {
          stop_network();
          next_state = StateTestsComplete;
        }
        else
        {
          next_state = StateMonitorData;
        }
      }
      break;
    case StateMonitorData:
      {
        syslog(LOG_DEBUG, "Monitoring data connection");
        fclose(fopen("/tmp/connected", "w"));
        query_data_connection();
        query_signal_strength();
        query_serving_system();
        if (qmi_status.active_antenna == UnknownBeam)
          qmi_status.active_antenna = beam_from_sysfs();
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
  char syslog_name[32];
  snprintf(syslog_name, 32, "umtsd[%d]", getpid());
  openlog(syslog_name, LOG_PERROR, LOG_DAEMON);

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

  if (qmi_settings.debug)
    setlogmask(LOG_UPTO(LOG_DEBUG));
  else
    setlogmask(LOG_UPTO(LOG_INFO));

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

  wdog_fd = open("/dev/watchdog", O_RDWR);
  if (wdog_fd == -1)
  {
    syslog(LOG_ERR, "Failed to open /dev/watchdog: %s\n", strerror(errno));
  }
  else
  {
    int bootstatus;
    if (ioctl(wdog_fd, WDIOC_GETBOOTSTATUS, &bootstatus) == 0) {
      syslog(LOG_INFO, "Last boot is caused by: %s\n", (bootstatus != 0) ? "Watchdog" : "Power-On-Reset");
    }

    if (ioctl(wdog_fd, WDIOC_SETTIMEOUT, WDOG_INTERVAL) != 0)
    {
      syslog(LOG_INFO, "Failed to set watchdog interval: %s", strerror(errno));
    }
    else
    {
      syslog(LOG_INFO, "Watchdog interval set to %d seconds", WDOG_INTERVAL);
    }
  }

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
