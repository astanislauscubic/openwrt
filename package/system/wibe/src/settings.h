#ifndef _SETTINGS_H_
#define _SETTINGS_H_

#include <uci.h>

int uci_get_string(const char *key, char *value, size_t len);
void uci_get_int_default(const char *key, int *value, int def);
void uci_get_string_default(const char *key, char *value, size_t len, const char *def);
const char* provider_get_value(struct uci_section *section, const char *name);
bool provider_matches_imsi(struct uci_section *section, const char *imsi);

#endif
