/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "credential-stream.h"
#include "errno-util.h"
#include "exec-credential.h"
#include "execute.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "manager.h"
#include "path-util.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "unit.h"

typedef struct CredentialStreamWatcher {
        Unit *unit;             /* back-reference, not owned */
        char *id;               /* credential id (hashmap key) */

        int fd;                 /* connected SOCK_SEQPACKET fd, or -EBADF */
        sd_event_source *io_event;

        bool seen_first;        /* first datagram is the initial value, no reload needed */
} CredentialStreamWatcher;

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        credential_stream_watcher_hash_ops,
        char, string_hash_func, string_compare_func,
        CredentialStreamWatcher, credential_stream_watcher_free);

CredentialStreamWatcher* credential_stream_watcher_free(CredentialStreamWatcher *w) {
        if (!w)
                return NULL;

        w->io_event = sd_event_source_disable_unref(w->io_event);
        w->fd = safe_close(w->fd);
        free(w->id);
        return mfree(w);
}

static int watcher_schedule_reload(CredentialStreamWatcher *w) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(w);
        assert(w->unit);

        /* Only reload if the unit is currently running and reloadable. The watcher keeps running
         * regardless — we will simply not propagate updates to a stopped unit. The next time the
         * unit starts, it will pick up the current value via acquire_credentials(). */
        if (!UNIT_IS_ACTIVE_OR_RELOADING(unit_active_state(w->unit)))
                return 0;
        if (!unit_can_reload(w->unit))
                return 0;

        r = manager_add_job(w->unit->manager, JOB_RELOAD, w->unit, JOB_FAIL, &error, /* ret= */ NULL);
        if (r < 0)
                log_unit_warning_errno(w->unit, r,
                                "Failed to enqueue reload after streamed credential update for '%s': %s",
                                w->id, bus_error_message(&error, r));
        return r;
}

static int watcher_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        CredentialStreamWatcher *w = ASSERT_PTR(userdata);

        assert(s);
        assert(fd == w->fd);

        if (revents & (EPOLLHUP|EPOLLERR)) {
                /* Source went away. Don't reconnect — Unix domain sockets are local; the source is
                 * either gone for good or will be brought back by its own service manager, which
                 * should orchestrate consumer restarts via BindsTo=/PartOf= ordering. */
                log_unit_debug(w->unit, "Credential watcher socket for '%s' closed by peer.", w->id);
                w->io_event = sd_event_source_disable_unref(w->io_event);
                w->fd = safe_close(w->fd);
                return 0;
        }

        /* Drain one datagram. We don't care about the contents — the reload we trigger below will
         * re-run acquire_credentials() which reconnects and reads the current value. Zero-byte
         * recv with MSG_TRUNC consumes the next SEQPACKET datagram regardless of its size. */
        (void) recv(fd, NULL, 0, MSG_TRUNC|MSG_DONTWAIT);

        if (!w->seen_first) {
                /* The first datagram on a fresh connection is the current value of the credential.
                 * The unit's start path read the same value via its own one-shot SEQPACKET connect
                 * in xfopenat_unix_socket(), so reloading right now would be a no-op-but-expensive
                 * waste. Skip it. */
                w->seen_first = true;
                return 0;
        }

        return watcher_schedule_reload(w);
}

static int watcher_new_and_connect(Unit *u, const ExecLoadCredential *lc, CredentialStreamWatcher **ret) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *bindname = NULL;
        union sockaddr_union bsa;
        int r;

        assert(u);
        assert(lc);
        assert(ret);

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        /* Same bind-name convention as load_credential() in exec-credential.c, so a source server
         * can use a single recognition path for both the static read and the streaming watcher. */
        if (asprintf(&bindname, "@%" PRIx64 "/unit/%s/%s",
                     random_u64(), u->id, lc->id) < 0)
                return -ENOMEM;

        r = sockaddr_un_set_path(&bsa.un, bindname);
        if (r < 0)
                return r;

        if (bind(fd, &bsa.sa, r) < 0)
                return -errno;

        r = connect_unix_path(fd, AT_FDCWD, lc->path);
        if (r < 0)
                return r;

        _cleanup_(credential_stream_watcher_freep) CredentialStreamWatcher *w = new(CredentialStreamWatcher, 1);
        if (!w)
                return -ENOMEM;

        *w = (CredentialStreamWatcher) {
                .unit = u,
                .fd = TAKE_FD(fd),
        };

        w->id = strdup(lc->id);
        if (!w->id)
                return -ENOMEM;

        r = sd_event_add_io(u->manager->event, &w->io_event, w->fd,
                            EPOLLIN, watcher_io, w);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(w->io_event, "credential-stream");

        *ret = TAKE_PTR(w);
        return 0;
}

int unit_setup_credential_streams(Unit *u) {
        ExecContext *ec;
        ExecLoadCredential *lc;

        assert(u);

        ec = unit_get_exec_context(u);
        if (!ec)
                return 0;

        HASHMAP_FOREACH(lc, ec->load_credentials) {
                CredentialStreamWatcher *w;
                int r;

                /* Only AF_UNIX absolute-path sources can be watched. */
                if (!path_is_absolute(lc->path))
                        continue;

                if (hashmap_get(u->credential_stream_watchers, lc->id))
                        continue;

                r = watcher_new_and_connect(u, lc, &w);
                if (r == -EPROTOTYPE) {
                        /* Source listens on SOCK_STREAM, i.e. it's the historical static-credential
                         * kind. Don't install a watcher; the existing one-shot read in
                         * acquire_credentials() handles it. */
                        log_unit_debug(u,
                                       "Credential source for '%s' is not SOCK_SEQPACKET; not installing streaming watcher.",
                                       lc->id);
                        continue;
                }
                if (r < 0) {
                        /* Other failures (ENOENT, ECONNREFUSED, …): the source is presumably not
                         * up. Same answer as the existing static-source case — order the unit
                         * after the source via After=/Requires=. */
                        log_unit_debug_errno(u, r,
                                "Failed to attach streaming watcher for credential '%s' (source '%s'): %m",
                                lc->id, lc->path);
                        continue;
                }

                r = hashmap_ensure_put(&u->credential_stream_watchers,
                                       &credential_stream_watcher_hash_ops,
                                       w->id, w);
                if (r < 0) {
                        credential_stream_watcher_free(w);
                        log_unit_warning_errno(u, r,
                                "Failed to register streaming credential watcher for '%s': %m", lc->id);
                        continue;
                }
        }

        return 0;
}

void unit_teardown_credential_streams(Unit *u) {
        if (!u)
                return;

        u->credential_stream_watchers = hashmap_free(u->credential_stream_watchers);
}
