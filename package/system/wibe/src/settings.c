#include "settings.h"
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

int uci_get_string(const char *key, char *value, size_t len)
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

void uci_get_int_default(const char *key, int *value, int def)
{
  char buf[64];
  int ret = uci_get_string(key, buf, sizeof(buf));
  *value = (ret>0) ? atoi(buf) : def;
}

void uci_get_string_default(const char *key, char *value, size_t len, const char *def)
{
  int ret = uci_get_string(key, value, len);
  if (ret < 0)
    snprintf(value, len, "%s", def);
}

const char* provider_get_value(struct uci_section *section, const char *name)
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

bool provider_matches_imsi(struct uci_section *section, const char *imsi)
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
