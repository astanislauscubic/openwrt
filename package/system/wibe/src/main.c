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

void print_settings(void)
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

int uci_get_string(const char *key, char *value, size_t len)
{
  struct uci_context *c;
  struct uci_ptr p;
  char *a = strdup(key);

  c = uci_alloc_context();
  if (uci_lookup_ptr(c, &p, a, true) != UCI_OK) {
      syslog(LOG_ERR, "UCI setting not found: %s", value);
      return -1;
  }

  if (p.o)
    snprintf(value, len, "%s", p.o->v.string);
  else
    value[0] = '\0';

  uci_free_context (c);

  free (a);
  return strlen(value);
}

int uci_get_int_default(const char *key, int *value, int def)
{
  char buf[64];
  int ret = uci_get_string(key, buf, sizeof(buf));
  *value = (ret>0) ? atoi(buf) : def;
  return strlen(buf);
}

int uci_get_string_default(const char *key, char *value, size_t len, const char *def)
{
  int ret = uci_get_string(key, value, len);
  if (ret < 0)
    snprintf(value, len, "%s", def);
  return strlen(value);
}

int load_settings(void)
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

void uqmi_free(struct QmiResponse *resp)
{
  if (!resp)
    return;

  if (resp->jobj)
    json_object_put(resp->jobj);
  free(resp);
}

bool modem_is_present(void)
{
  struct stat device_stat;
  lstat(qmi_settings.device, &device_stat);
  return S_ISCHR(device_stat.st_mode);
}

void uqmi_reset(void)
{
  int fd = open("/sys/class/gpio/gpio10/value", O_WRONLY);
  if (fd < 0)
  {
    syslog(LOG_ERR, "Failed to open modem reset GPIO");
    exit(1);
  }

  if (write(fd, "0", 1) != 1)
  {
    syslog(LOG_ERR, "Failed to write modem reset GPIO (0)");
  }
  sleep(5);
  if (write(fd, "1", 1) != 1)
  {
    syslog(LOG_ERR, "Failed to write modem reset GPIO (1)");
  }

  close(fd);

  while (!modem_is_present())
    sleep(1);
}

struct QmiResponse *uqmi_once(const char * const args)
{
  char cmd[256];
  snprintf(cmd, 256, "uqmi -s -d %s %s", qmi_settings.device, args);
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

bool uqmi_is_error(const struct QmiResponse * const resp)
{
  return resp->error_string[0] != '\0';
}

struct QmiResponse *uqmi(const char * const args)
{
  // Multiple retries if we get the "Unknown Error" response
  for (int i = 0; i < 5; ++i)
  {
    struct QmiResponse* resp = uqmi_once(args);
    if (!resp)
    {
      continue;
    }
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
bool sim_is_present(void)
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
    return false;
  }

  close(fd);

  return atoi(gpio_str) == 1;
}

void antenna_select(uint8_t beam, bool flash)
{
  const char *beams[] = {"front", "back", "left", "right"};

  int fd, bytes;
  char filename[128];

  for (int i = 0; i < 4; ++i)
  {
    snprintf(filename, 128, "/sys/class/leds/wibe:%s:green/trigger", beams[i]);
    fd = open(filename, O_WRONLY);
    assert(fd);
    bytes = write(fd, "none", 4);
    assert(bytes == 4);
    close(fd);
  }

  char antenna_name[10];
  fd = open("/sys/devices/wibe-antenna.4/antenna", O_WRONLY);
  assert(fd);
  snprintf(antenna_name, sizeof(antenna_name), "%d", beam);
  bytes = write(fd, antenna_name, strlen(antenna_name));
  assert(bytes > 0);
  close(fd);

  fd = open("/sys/devices/wibe-antenna.4/antenna", O_RDONLY);
  assert(fd);
  bytes = read(fd, &antenna_name, 10);
  assert(bytes > 0);
  antenna_name[bytes-1] = '\0'; // Remove \n
  close(fd);

  snprintf(filename, 128, "/sys/class/leds/wibe:%s:green/trigger", antenna_name);
  fd = open(filename, O_WRONLY);
  assert(fd);
  if (flash)
    bytes = write(fd, "heartbeat", strlen("heartbeat"));
  else
    bytes = write(fd, "default-on", strlen("default-on"));
  assert(bytes > 0);
  close(fd);
}

enum SignalType {
  TYPE_LTE,
  TYPE_WCDMA,
  TYPE_COUNT
};

struct AntennaResult {
  bool test_complete;
  struct tm test_time;
  enum SignalType type;
  uint8_t antenna;
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
static struct AntennaResult antenna_results[TYPE_COUNT][ANTENNAS];

void antenna_reset(void)
{
  for (size_t type = 0; type < TYPE_COUNT; ++type)
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

  if (a->type == b->type && a->type == TYPE_WCDMA)
  {
    if (a->ecio > b->ecio)
      return a;
    if (b->ecio > a->ecio)
      return b;
  }

  if (a->type == b->type && a->type == TYPE_LTE)
  {
    if (a->rsrp > b->rsrp)
      return a;
    if (b->rsrp > a->rsrp)
      return b;
  }

  if (a->type == TYPE_LTE)
    return a;
  if (b->type == TYPE_LTE)
    return b;

  syslog(LOG_WARNING, "Returning default in antenna_max");
  return a;
}

const struct AntennaResult *antenna_find_best(void)
{
  struct AntennaResult *best = NULL;
  for (size_t type = 0; type < TYPE_COUNT; ++type)
    for (size_t antenna = 0; antenna < ANTENNAS; ++antenna)
      best = antenna_max(best, &antenna_results[type][antenna]);
  return best;
}

void antenna_test(void)
{
  for (int antenna = 0; antenna < 4; ++antenna)
  {
    antenna_select(antenna, true);
    sleep(qmi_settings.settlewait);
    for (int timeout = qmi_settings.regtimeout; timeout > 0; --timeout)
    {
      struct QmiResponse *resp = uqmi("--get-serving-system");
      if (!uqmi_is_error(resp))
      {
        const char *reg = uqmi_get_string(resp, "registration");
        if (!strcmp(reg, "registered"))
          break;
        syslog(LOG_INFO, "Waiting for registration to complete: %s", reg);
        sleep(1);
      }
      else
      {
        syslog(LOG_INFO, "Waiting for registrtion to complete: %s", resp->error_string);
      }
    }
    sleep(qmi_settings.settlewait);
    struct QmiResponse *resp = uqmi("--get-signal-info");
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
                                   .rsrp = rsrp, .snr = snr, .type = TYPE_LTE,
                                   .antenna = antenna};
        time_t now;
        time(&now);
        memcpy(&r.test_time, localtime(&now), sizeof(struct tm));
        memcpy(&antenna_results[TYPE_LTE][antenna], &r, sizeof(struct AntennaResult));
      }
      else if (!strcmp(type, "wcdma"))
      {
        int rssi = uqmi_get_int(resp, "rssi");
        int ecio = uqmi_get_int(resp, "ecio");
        syslog(LOG_INFO, "wcdma %d %d", rssi, ecio);
        struct AntennaResult r = { .test_complete = true, .rssi = rssi,
                                   .ecio = ecio, .type = TYPE_WCDMA,
                                   .antenna = antenna};
        time_t now;
        time(&now);
        memcpy(&r.test_time, localtime(&now), sizeof(struct tm));
        memcpy(&antenna_results[TYPE_WCDMA][antenna], &r, sizeof(struct AntennaResult));
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

void modem_disconnect(void)
{
  uqmi_free(uqmi("--stop-network 0xffffffff --autoconnect"));

  char cmd[128];
  snprintf(cmd, sizeof(cmd),
           "--set-client-id wds,\"%s\" --release-client-id wds", cid);
  uqmi_free(uqmi(cmd));
}

void sig_handler(int sig)
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

void net_renew_lease(void)
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

int main(int argc, char **argv)
{
  openlog("umtsd", LOG_PERROR, LOG_DAEMON);

  if (signal(SIGUSR1, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGUSR1 handler");
  if (signal(SIGUSR2, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGUSR2 handler");
  if (signal(SIGINT, sig_handler) == SIG_ERR)
    syslog(LOG_ERR, "Failed to register SIGINT handler");

  if (!load_settings())
  {
    syslog(LOG_ERR, "Invalid WAN settings for QMI");
    exit(1);
  }
  print_settings();

  if (!modem_is_present())
  {
    syslog(LOG_ERR, "Device %s is not a character device", qmi_settings.device);
    uqmi_reset();
    exit(1);
  }

  struct QmiResponse *resp = uqmi("--get-pin-status");
  if (uqmi_is_error(resp))
  {
    syslog(LOG_WARNING, "SIM is not initialised");
    if (sim_is_present())
      uqmi_reset();
  }
  uqmi_free(resp);

  if (strlen(qmi_settings.pincode))
  {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "--verify-pin1 %s", qmi_settings.pincode);
    struct QmiResponse *resp = uqmi(cmd);
    if (uqmi_is_error(resp) && !strcmp(resp->error_string, "No effect"))
      syslog(LOG_WARNING, "Pin1 had no effect");
    else if (uqmi_is_error(resp))
      syslog(LOG_ERR, "PIN1 verify: %s", resp->error_string);
    uqmi_free(resp);
  }

  uqmi_free(uqmi("--set-data-format 802.3"));
  uqmi_free(uqmi("--wda-set-data-format 802.3"));

  antenna_reset();
  if (!strcmp(qmi_settings.modes, "detect"))
  {
    uqmi_free(uqmi("--set-network-modes lte"));
    net_renew_lease();
    if (!strcmp(qmi_settings.antenna, "detect"))
      antenna_test();
    else
      antenna_select(atoi(qmi_settings.antenna), false);
    uqmi_free(uqmi("--set-network-modes umts"));
    net_renew_lease();
    if (!strcmp(qmi_settings.antenna, "detect"))
      antenna_test();
    else
      antenna_select(atoi(qmi_settings.antenna), false);
  }
  else
  {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "--set-network-modes %s", qmi_settings.modes);
    uqmi_free(uqmi(cmd));
    net_renew_lease();
    if (!strcmp(qmi_settings.antenna, "detect"))
      antenna_test();
    else
      antenna_select(atoi(qmi_settings.antenna), false);
  }

  const struct AntennaResult *antenna = antenna_find_best();
  if (!strcmp(qmi_settings.modes, "detect"))
  {
    if (antenna->type == TYPE_LTE)
    {
      syslog(LOG_INFO, "Selecting LTE mode");
      uqmi_free(uqmi("--set-network-modes lte"));
      net_renew_lease();
    }
    else if (antenna->type == TYPE_WCDMA)
    {
      syslog(LOG_INFO, "Selecting WCDMA mode");
      uqmi_free(uqmi("--set-network-modes umts"));
      net_renew_lease();
    }
  }

  if (!strcmp(qmi_settings.antenna, "detect"))
  {
    syslog(LOG_INFO, "Selecting antenna %d", antenna->antenna);
    antenna_select(antenna->antenna, false);
  }

  resp = uqmi("--get-client-id wds");
  strncpy(cid, resp->response_string, sizeof(cid));
  uqmi_free(resp);

  modem_disconnect();

  resp = uqmi("--get-client-id wds");
  strncpy(cid, resp->response_string, sizeof(cid));
  uqmi_free(resp);

  char connect_command[256];

  snprintf(connect_command, sizeof(connect_command),
           "--set-client-id wds,\"%s\" --start-network \"%s\" %s %s %s %s"
           "--autoconnect ", cid, qmi_settings.apn,
           (strlen(qmi_settings.username) != 0) ? "--username" : "", qmi_settings.username,
           (strlen(qmi_settings.password) != 0) ? "--password" : "", qmi_settings.password);
  uqmi_free(uqmi(connect_command));
  sleep(qmi_settings.settlewait);

  while (1)
  {
    resp =  uqmi("--get-data-status");
    fprintf(stderr, "%s", resp->error_string);
    if (strcmp(resp->error_string, "connected"))
    {
      uqmi_free(resp);
      sleep(qmi_settings.settlewait);
      resp =  uqmi("--get-data-status");
      if (strcmp(resp->error_string, "connected"))
        break;
    }
    sleep(1);
  }

  syslog(LOG_INFO, "Data connection lost, restarting umtsd...");

  closelog();

  return 0;
}
