/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_GLOBAL_WRAPPERS_H
#define WDB_GLOBAL_WRAPPERS_H

#include "wazuh_db/wdb.h"

int __wrap_wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key,char* group, int date_add);
int __wrap_wdb_global_update_agent_name(wdb_t *wdb, int id, char* name);
int __wrap_wdb_global_update_agent_version(wdb_t *wdb,
                                    int id,
                                    const char *os_name,
                                    const char *os_version,
                                    const char *os_major,
                                    const char *os_minor,
                                    const char *os_codename,
                                    const char *os_platform,
                                    const char *os_build,
                                    const char *os_uname,
                                    const char *os_arch,
                                    const char *version,
                                    const char *config_sum,
                                    const char *merged_sum,
                                    const char *manager_host,
                                    const char *node_name,
                                    const char *agent_ip,
                                    wdb_sync_status_t sync_status);

cJSON* __wrap_wdb_global_get_agent_labels(wdb_t *wdb, int id);

#endif
