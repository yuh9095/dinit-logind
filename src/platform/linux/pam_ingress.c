/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 dinit-logind contributors
 */
#define _GNU_SOURCE
#include "pam_ingress.h"

#include "pam_protocol.h"
#include "pam_session.h"
#include "peer_credentials.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct dl_pam_ingress {
    dl_manager *manager;
    int fd;
    uint32_t allowed_peer_uid;
    size_t received;
    size_t response_sent;
    dl_pam_open_request request;
    dl_pam_open_response response;
    dl_pam_session *session;
};

static bool field_valid(const char field[DL_PAM_FIELD_MAX])
{
    const char *end = memchr(field, '\0', DL_PAM_FIELD_MAX);
    const unsigned char *p;
    if (end == NULL) return false;
    for (p = (const unsigned char *)field; p < (const unsigned char *)end; ++p)
        if (*p < 0x20 || *p == 0x7f) return false;
    return true;
}

static bool request_valid(const dl_pam_open_request *r)
{
    static const uint8_t zero[sizeof(r->reserved)] = {0};
    return r->magic == DL_PAM_PROTOCOL_MAGIC &&
           r->version == DL_PAM_PROTOCOL_VERSION &&
           r->size == sizeof(*r) && r->remote <= 1 &&
           memcmp(r->reserved, zero, sizeof(zero)) == 0 &&
           field_valid(r->service) && field_valid(r->tty) &&
           field_valid(r->ruser) && field_valid(r->rhost) &&
           field_valid(r->display) && field_valid(r->type) &&
           field_valid(r->session_class);
}

static uint32_t tty_vtnr(const char *tty)
{
    const char *digits;
    uint32_t value;
    if (tty == NULL || strncmp(tty, "/dev/tty", 8) != 0) return 0;
    digits = tty + 8;
    if (digits[0] < '1' || digits[0] > '9') return 0;
    value = (uint32_t)(digits[0] - '0');
    if (digits[1] != '\0') {
        if (digits[1] < '0' || digits[1] > '9' || digits[2] != '\0')
            return 0;
        value = value * 10u + (uint32_t)(digits[1] - '0');
    }
    return value <= 63u ? value : 0;
}

static bool uid_exists(uint32_t uid)
{
    struct passwd pwd, *result = NULL;
    long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t size = suggested > 0 && suggested < 1024 * 1024
                      ? (size_t)suggested : 16384;
    char *buffer = malloc(size);
    bool found;
    if (buffer == NULL) return false;
    found = getpwuid_r((uid_t)uid, &pwd, buffer, size, &result) == 0 &&
            result != NULL && (uint32_t)pwd.pw_uid == uid;
    free(buffer);
    return found;
}

dl_result dl_pam_ingress_accept(dl_manager *manager, int listen_fd,
                                uint32_t allowed_peer_uid,
                                dl_pam_ingress **out_ingress)
{
    dl_pam_ingress *ingress;
    dl_linux_peer_credentials peer;
    int fd;
    dl_result result;

    if (out_ingress != NULL) *out_ingress = NULL;
    if (manager == NULL || listen_fd < 0 || out_ingress == NULL)
        return DL_ERR_INVALID;
    fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0) return DL_ERR_STATE;
    result = dl_linux_peer_credentials_read(fd, &peer);
    if (result != DL_OK || peer.uid != allowed_peer_uid) {
        (void)close(fd);
        return result == DL_OK ? DL_ERR_INVALID : result;
    }
    ingress = calloc(1, sizeof(*ingress));
    if (ingress == NULL) { (void)close(fd); return DL_ERR_NOMEM; }
    ingress->manager = manager;
    ingress->fd = fd;
    ingress->allowed_peer_uid = allowed_peer_uid;
    *out_ingress = ingress;
    return DL_OK;
}

static dl_result flush_response(dl_pam_ingress *ingress, bool *complete)
{
    ssize_t n;
    while (ingress->response_sent < sizeof(ingress->response)) {
        n = send(ingress->fd,
                 (const char *)&ingress->response + ingress->response_sent,
                 sizeof(ingress->response) - ingress->response_sent,
                 MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return DL_OK;
        if (n <= 0) return DL_ERR_STATE;
        ingress->response_sent += (size_t)n;
    }
    (void)close(ingress->fd);
    ingress->fd = -1;
    *complete = true;
    return DL_OK;
}

dl_result dl_pam_ingress_step(dl_pam_ingress *ingress, bool *complete)
{
    dl_result result;
    dl_session_spec spec;
    uint32_t parsed_vtnr;
    ssize_t n;

    if (complete != NULL) *complete = false;
    if (ingress == NULL || complete == NULL) return DL_ERR_INVALID;
    if (ingress->session != NULL) return flush_response(ingress, complete);
    if (ingress->fd < 0) return DL_ERR_STATE;

    while (ingress->received < sizeof(ingress->request)) {
        n = recv(ingress->fd, (char *)&ingress->request + ingress->received,
                 sizeof(ingress->request) - ingress->received, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return DL_OK;
        if (n < 0) return DL_ERR_STATE;
        if (n == 0) return DL_ERR_INVALID;
        ingress->received += (size_t)n;
    }

    if (!request_valid(&ingress->request) || !uid_exists(ingress->request.uid))
        return DL_ERR_INVALID;

    parsed_vtnr = tty_vtnr(ingress->request.tty);
    if (ingress->request.vtnr != 0 &&
        ingress->request.vtnr != parsed_vtnr)
        return DL_ERR_INVALID;

    memset(&spec, 0, sizeof(spec));
    spec.uid = ingress->request.uid;
    spec.vtnr = parsed_vtnr;
    spec.seat = (!ingress->request.remote && parsed_vtnr != 0)
                    ? "seat0" : NULL;
    spec.remote = ingress->request.remote != 0;
    spec.service = ingress->request.service;
    spec.tty = ingress->request.tty;
    spec.remote_user = ingress->request.ruser;
    spec.remote_host = ingress->request.rhost;
    spec.display = ingress->request.display;
    spec.type = ingress->request.type;
    spec.session_class = ingress->request.session_class;

    result = dl_pam_session_begin(ingress->manager, ingress->fd, &spec,
                                  &ingress->session);
    if (result != DL_OK) return result;

    memset(&ingress->response, 0, sizeof(ingress->response));
    ingress->response.magic = DL_PAM_RESPONSE_MAGIC;
    ingress->response.version = DL_PAM_PROTOCOL_VERSION;
    ingress->response.size = (uint16_t)sizeof(ingress->response);
    (void)snprintf(ingress->response.session_id,
                   sizeof(ingress->response.session_id), "%s",
                   dl_pam_session_id(ingress->session));
    return flush_response(ingress, complete);
}

dl_result dl_pam_ingress_peer_closed(dl_pam_ingress *ingress, bool *closed)
{
    if (closed != NULL) *closed = false;
    if (ingress == NULL || closed == NULL || ingress->session == NULL)
        return DL_ERR_INVALID;
    return dl_pam_session_peer_closed(ingress->session, closed);
}

const char *dl_pam_ingress_session_id(const dl_pam_ingress *ingress)
{
    return ingress == NULL ? NULL : dl_pam_session_id(ingress->session);
}

void dl_pam_ingress_destroy(dl_pam_ingress *ingress)
{
    if (ingress == NULL) return;
    if (ingress->fd >= 0) (void)close(ingress->fd);
    dl_pam_session_destroy(ingress->session);
    free(ingress);
}
