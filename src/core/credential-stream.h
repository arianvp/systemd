/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

/* Per-credential watcher attached to a Unit. Maintains a long-lived AF_UNIX SOCK_SEQPACKET
 * connection to the credential source. When the source pushes a datagram the watcher schedules a
 * reload of the unit (which goes through the existing RefreshOnReload=credentials machinery — i.e.
 * acquire_credentials() reconnects, reads the current value, and the credential mount is swapped
 * atomically). The watcher therefore does not need to forward the actual bytes anywhere — it is
 * purely a "credentials changed, please reload" signal.
 *
 * If the source listens on SOCK_STREAM rather than SOCK_SEQPACKET (i.e. the source is the
 * historical "static" kind) the connect will fail with -EPROTOTYPE and no watcher is installed,
 * preserving today's one-shot behaviour. */

typedef struct CredentialStreamWatcher CredentialStreamWatcher;

CredentialStreamWatcher* credential_stream_watcher_free(CredentialStreamWatcher *w);
DEFINE_TRIVIAL_CLEANUP_FUNC(CredentialStreamWatcher*, credential_stream_watcher_free);

/* Set up SEQPACKET watchers for all absolute-path LoadCredential= entries on this unit that have a
 * SOCK_SEQPACKET listener. Idempotent. Existing watchers are left in place. Sources that don't
 * accept SEQPACKET (most existing setups) silently get no watcher. */
int unit_setup_credential_streams(Unit *u);

/* Tear down all watchers for the unit. Called from unit_free(). */
void unit_teardown_credential_streams(Unit *u);
