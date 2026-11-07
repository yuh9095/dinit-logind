/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>

#include "../platform/linux/pam_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef DL_PAM_SOCKET_PATH
#define DL_PAM_SOCKET_PATH DL_PAM_SOCKET_DEFAULT
#endif

#define DL_PAM_DATA_KEY "dinit-logind-session"

struct pam_session_data { int fd; };

static void session_cleanup(pam_handle_t *pamh, void *data, int status)
{
    struct pam_session_data *session = data;
    (void)pamh; (void)status;
    if (session == NULL) return;
    if (session->fd >= 0) (void)close(session->fd);
    free(session);
}

static int copy_item(char dst[DL_PAM_FIELD_MAX], const char *src)
{
    size_t length;
    if (src == NULL) { dst[0] = '\0'; return PAM_SUCCESS; }
    length = strnlen(src, DL_PAM_FIELD_MAX);
    if (length >= DL_PAM_FIELD_MAX) return PAM_SERVICE_ERR;
    memcpy(dst, src, length);
    dst[length] = '\0';
    return PAM_SUCCESS;
}

static int lookup_uid(const char *name, uint32_t *uid)
{
    struct passwd pwd, *result = NULL;
    long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t size = suggested > 0 && suggested < 1024 * 1024
                      ? (size_t)suggested : 16384;
    char *buffer = malloc(size);
    int error;
    if (buffer == NULL) return PAM_BUF_ERR;
    error = getpwnam_r(name, &pwd, buffer, size, &result);
    if (error != 0 || result == NULL) {
        free(buffer);
        return PAM_USER_UNKNOWN;
    }
    *uid = (uint32_t)pwd.pw_uid;
    free(buffer);
    return PAM_SUCCESS;
}

static int connect_daemon(void)
{
    struct sockaddr_un address;
    int fd;
    if (strlen(DL_PAM_SOCKET_PATH) >= sizeof(address.sun_path)) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, DL_PAM_SOCKET_PATH, strlen(DL_PAM_SOCKET_PATH) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        (void)close(fd); return -1;
    }
    return fd;
}

static int read_response(int fd, dl_pam_open_response *response)
{
    size_t received = 0;
    while (received < sizeof(*response)) {
        ssize_t n = recv(fd, (char *)response + received,
                         sizeof(*response) - received, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        received += (size_t)n;
    }
    if (response->magic != DL_PAM_RESPONSE_MAGIC ||
        response->version != DL_PAM_PROTOCOL_VERSION ||
        response->size != sizeof(*response) || response->status != 0 ||
        memchr(response->session_id, '\0', sizeof(response->session_id)) == NULL)
        return -1;
    return 0;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    const char *user = NULL, *service = NULL, *tty = NULL;
    const char *ruser = NULL, *rhost = NULL, *display = NULL;
    const char *type = NULL, *session_class = NULL;
    struct pam_session_data *session;
    dl_pam_open_request request;
    dl_pam_open_response response;
    uint32_t uid;
    int fd, status;
    size_t sent = 0;
    (void)flags; (void)argc; (void)argv;

    status = pam_get_user(pamh, &user, NULL);
    if (status != PAM_SUCCESS || user == NULL)
        return status == PAM_SUCCESS ? PAM_USER_UNKNOWN : status;
    status = lookup_uid(user, &uid);
    if (status != PAM_SUCCESS) return status;

    memset(&request, 0, sizeof(request));
    request.magic = DL_PAM_PROTOCOL_MAGIC;
    request.version = DL_PAM_PROTOCOL_VERSION;
    request.size = (uint16_t)sizeof(request);
    request.uid = uid;

    (void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    (void)pam_get_item(pamh, PAM_TTY, (const void **)&tty);
    (void)pam_get_item(pamh, PAM_RUSER, (const void **)&ruser);
    (void)pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);
    if (copy_item(request.service, service) != PAM_SUCCESS ||
        copy_item(request.tty, tty) != PAM_SUCCESS ||
        copy_item(request.ruser, ruser) != PAM_SUCCESS ||
        copy_item(request.rhost, rhost) != PAM_SUCCESS) return PAM_SERVICE_ERR;

    display = pam_getenv(pamh, "DISPLAY");
    type = pam_getenv(pamh, "XDG_SESSION_TYPE");
    session_class = pam_getenv(pamh, "XDG_SESSION_CLASS");
    if (copy_item(request.display, display) != PAM_SUCCESS ||
        copy_item(request.type, type) != PAM_SUCCESS ||
        copy_item(request.session_class, session_class) != PAM_SUCCESS)
        return PAM_SERVICE_ERR;
    request.remote = rhost != NULL && rhost[0] != '\0';

    fd = connect_daemon();
    if (fd < 0) return PAM_SESSION_ERR;
    while (sent < sizeof(request)) {
        ssize_t n = send(fd, (const char *)&request + sent,
                         sizeof(request) - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { (void)close(fd); return PAM_SESSION_ERR; }
        sent += (size_t)n;
    }
    if (read_response(fd, &response) != 0) {
        (void)close(fd);
        return PAM_SESSION_ERR;
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL) { (void)close(fd); return PAM_BUF_ERR; }
    session->fd = fd;
    status = pam_set_data(pamh, DL_PAM_DATA_KEY, session, session_cleanup);
    if (status != PAM_SUCCESS) { session_cleanup(pamh, session, status); return status; }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    const void *data = NULL;
    struct pam_session_data *session;
    int status;
    (void)flags; (void)argc; (void)argv;
    status = pam_get_data(pamh, DL_PAM_DATA_KEY, &data);
    if (status == PAM_NO_MODULE_DATA) return PAM_SUCCESS;
    if (status != PAM_SUCCESS) return status;
    session = (struct pam_session_data *)data;
    if (session != NULL && session->fd >= 0) {
        (void)close(session->fd);
        session->fd = -1;
    }
    return pam_set_data(pamh, DL_PAM_DATA_KEY, NULL, NULL);
}
