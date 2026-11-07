/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#ifndef DINIT_LOGIND_DBUS_H
#define DINIT_LOGIND_DBUS_H
#include "../core/core.h"
#include <systemd/sd-bus.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    sd_bus *bus;
    sd_bus_slot *manager_slot;
} dl_dbus;
int dl_dbus_open(dl_dbus *dbus, dl_manager *manager);
int dl_dbus_process(dl_dbus *dbus);
void dl_dbus_close(dl_dbus *dbus);
#ifdef __cplusplus
}
#endif
#endif
