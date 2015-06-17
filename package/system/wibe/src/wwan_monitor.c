#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include "settings.h"

#define BOOT_TIME 60

static char wan_device[128];

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

static bool modem_is_present(void)
{
  struct stat device_stat;
  lstat(wan_device, &device_stat);
  return S_ISCHR(device_stat.st_mode);
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

static void start_modem(void)
{
  uqmi_power(true);
  for (size_t i = 0; i < BOOT_TIME; ++i)
  {
    if (!modem_is_present())
      sleep(1);
    else
      break;
  }

  if (!modem_is_present())
  {
    syslog(LOG_ERR, "Modem did not enumerate within %d seconds, rebooting", BOOT_TIME);
    uqmi_power(false);
    system("reboot");
    exit(1);
  }
}

static void monitor_modem(void)
{
  if (!sim_is_present())
  {
    syslog(LOG_INFO, "SIM card removed, shutting down modem");
    uqmi_power(false);
    while (!sim_is_present())
      sleep(1);
    syslog(LOG_INFO, "SIM detected, starting modem");
    sleep(1);
    start_modem();
  }
  else if (!modem_is_present())
  {
    syslog(LOG_INFO, "Modem disconnected, restarting modem");
    uqmi_power(false);
    sleep(5);
    start_modem();
  }
  else
  {
    sleep(2);
  }
}

int main(int argc, char **argv)
{
  openlog("wwan", LOG_PERROR, LOG_DAEMON);
  setlogmask(LOG_UPTO(LOG_INFO));

  if (!uci_get_string("network.wan.device", wan_device, sizeof(wan_device)))
  {
    syslog(LOG_ERR, "Failed to get network.wan.device");
  }

  syslog(LOG_INFO, "WWAN monitor starting up");

  while (!sim_is_present())
    sleep(1);

  sleep(1);
  syslog(LOG_INFO, "SIM detected, starting modem");
  start_modem();

  while (true)
    monitor_modem();
}
