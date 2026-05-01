#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>

static void die_session(ssh_session session, const char *message) {
    fprintf(stderr, "%s: %s\n", message, ssh_get_error(session));
    exit(1);
}

static void die_channel(ssh_channel channel, const char *message) {
    fprintf(stderr, "%s: %s\n", message, ssh_get_error(ssh_channel_get_session(channel)));
    exit(1);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <host> <port> <user> <password>\n", argv[0]);
        return 2;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *user = argv[3];
    const char *password = argv[4];
    int verbosity = SSH_LOG_NOLOG;
    long timeout = 5;

    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "ssh_new failed\n");
        return 1;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_PORT, &port) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_USER, user) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout) != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, "curve25519-sha256") != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519") != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, "aes256-ctr") != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, "aes256-ctr") != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, "hmac-sha2-256") != SSH_OK ||
        ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "hmac-sha2-256") != SSH_OK) {
        die_session(session, "ssh_options_set failed");
    }

    if (ssh_connect(session) != SSH_OK) {
        die_session(session, "ssh_connect failed");
    }

    if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
        die_session(session, "ssh_userauth_password failed");
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        die_session(session, "ssh_channel_new failed");
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        die_channel(channel, "ssh_channel_open_session failed");
    }

    if (ssh_channel_request_shell(channel) != SSH_OK) {
        die_channel(channel, "ssh_channel_request_shell failed");
    }

    const char *payload = "misshod-libssh-probe\n";
    int written = ssh_channel_write(channel, payload, (uint32_t)strlen(payload));
    if (written != (int)strlen(payload)) {
        die_channel(channel, "ssh_channel_write failed");
    }

    char buffer[512];
    int received = ssh_channel_read_timeout(channel, buffer, sizeof(buffer) - 1, 0, 5000);
    if (received <= 0) {
        die_channel(channel, "ssh_channel_read_timeout failed");
    }
    buffer[received] = '\0';
    fputs(buffer, stdout);

    if (strstr(buffer, "You said 'misshod-libssh-probe") == NULL) {
        fprintf(stderr, "unexpected response: %s\n", buffer);
        return 1;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}
