#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>

static int check_algorithm(const char *name, const char *actual, const char *expected) {
    if (actual == NULL || strcmp(actual, expected) != 0) {
        fprintf(stderr,
                "unexpected negotiated %s: expected %s, got %s\n",
                name,
                expected,
                actual == NULL ? "(null)" : actual);
        return -1;
    }
    return 0;
}

static int write_all(ssh_channel channel, const char *data, size_t length) {
    size_t offset = 0;

    while (offset < length) {
        int written = ssh_channel_write(channel,
                                        data + offset,
                                        (uint32_t)(length - offset));
        if (written <= 0) {
            fprintf(stderr,
                    "ssh_channel_write failed after %zu of %zu bytes: %s\n",
                    offset,
                    length,
                    ssh_get_error(ssh_channel_get_session(channel)));
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <host> <port> <user> <private-key>\n", argv[0]);
        return 2;
    }

    const char *host = argv[1];
    const char *user = argv[3];
    const char *private_key_path = argv[4];
    char *port_end = NULL;
    unsigned long parsed_port = strtoul(argv[2], &port_end, 10);
    if (argv[2][0] == '\0' || *port_end != '\0' || parsed_port == 0 || parsed_port > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }
    unsigned int port = (unsigned int)parsed_port;
    int verbosity = SSH_LOG_NOLOG;
    long timeout = 5;
    int status = 1;
    int connected = 0;
    int channel_closed = 0;
    ssh_key private_key = NULL;
    ssh_key server_key = NULL;
    ssh_channel channel = NULL;

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
        fprintf(stderr, "ssh_options_set failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, "ssh_connect failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }
    connected = 1;

    if (check_algorithm("key exchange", ssh_get_kex_algo(session), "curve25519-sha256") != 0 ||
        check_algorithm("incoming cipher", ssh_get_cipher_in(session), "aes256-ctr") != 0 ||
        check_algorithm("outgoing cipher", ssh_get_cipher_out(session), "aes256-ctr") != 0 ||
        check_algorithm("incoming MAC", ssh_get_hmac_in(session), "hmac-sha2-256") != 0 ||
        check_algorithm("outgoing MAC", ssh_get_hmac_out(session), "hmac-sha2-256") != 0) {
        goto cleanup;
    }

    if (ssh_get_server_publickey(session, &server_key) != SSH_OK) {
        fprintf(stderr, "ssh_get_server_publickey failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }
    if (ssh_key_type(server_key) != SSH_KEYTYPE_ED25519) {
        fprintf(stderr,
                "unexpected negotiated host key type: %s\n",
                ssh_key_type_to_char(ssh_key_type(server_key)));
        goto cleanup;
    }

    if (ssh_pki_import_privkey_file(private_key_path, NULL, NULL, NULL, &private_key) != SSH_OK) {
        fprintf(stderr, "could not import fixture private key: %s\n", private_key_path);
        goto cleanup;
    }
    if (ssh_key_type(private_key) != SSH_KEYTYPE_ED25519) {
        fprintf(stderr, "fixture private key is not Ed25519\n");
        goto cleanup;
    }
    if (ssh_userauth_publickey(session, NULL, private_key) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "ssh_userauth_publickey failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        fprintf(stderr, "ssh_channel_new failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "ssh_channel_open_session failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    if (ssh_channel_request_shell(channel) != SSH_OK) {
        fprintf(stderr, "ssh_channel_request_shell failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    const char *payload =
        "sshz-libssh-probe:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n";
    if (write_all(channel, payload, strlen(payload)) != 0) {
        goto cleanup;
    }

    if (ssh_channel_send_eof(channel) != SSH_OK) {
        fprintf(stderr, "ssh_channel_send_eof failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }

    char response[4096];
    size_t response_length = 0;
    while (response_length < sizeof(response) - 1) {
        char chunk[17];
        int received = ssh_channel_read_timeout(channel,
                                                chunk,
                                                sizeof(chunk),
                                                0,
                                                5000);
        if (received == SSH_ERROR) {
            fprintf(stderr, "ssh_channel_read_timeout failed: %s\n", ssh_get_error(session));
            goto cleanup;
        }
        if (received == 0) {
            if (!ssh_channel_is_eof(channel)) {
                fprintf(stderr, "timed out waiting for channel data or EOF\n");
                goto cleanup;
            }
            break;
        }
        if (received < 0) {
            fprintf(stderr,
                    "unexpected ssh_channel_read_timeout return value: %d\n",
                    received);
            goto cleanup;
        }
        memcpy(response + response_length, chunk, (size_t)received);
        response_length += (size_t)received;
    }
    response[response_length] = '\0';

    if (!ssh_channel_is_eof(channel)) {
        fprintf(stderr, "response exceeded buffer before channel EOF\n");
        goto cleanup;
    }

    char expected[256];
    int expected_length = snprintf(expected, sizeof(expected), "You said '%s'\r\n", payload);
    if (expected_length < 0 || (size_t)expected_length >= sizeof(expected) ||
        strstr(response, expected) == NULL) {
        fprintf(stderr, "unexpected response (%zu bytes): %s\n", response_length, response);
        goto cleanup;
    }

    if (fwrite(response, 1, response_length, stdout) != response_length) {
        fprintf(stderr, "could not write probe response to stdout\n");
        goto cleanup;
    }
    printf("negotiated kex=%s hostkey=%s cipher-in=%s cipher-out=%s "
           "hmac-in=%s hmac-out=%s\n",
           ssh_get_kex_algo(session),
           ssh_key_type_to_char(ssh_key_type(server_key)),
           ssh_get_cipher_in(session),
           ssh_get_cipher_out(session),
           ssh_get_hmac_in(session),
           ssh_get_hmac_out(session));

    if (ssh_channel_close(channel) != SSH_OK) {
        fprintf(stderr, "ssh_channel_close failed: %s\n", ssh_get_error(session));
        goto cleanup;
    }
    channel_closed = 1;
    if (!ssh_channel_is_closed(channel)) {
        fprintf(stderr, "channel was not closed after ssh_channel_close\n");
        goto cleanup;
    }
    ssh_channel_free(channel);
    channel = NULL;

    ssh_disconnect(session);
    connected = 0;
    if (ssh_is_connected(session)) {
        fprintf(stderr, "session remained connected after ssh_disconnect\n");
        goto cleanup;
    }
    status = 0;

cleanup:
    if (channel != NULL) {
        if (!channel_closed) {
            (void)ssh_channel_close(channel);
        }
        ssh_channel_free(channel);
    }
    ssh_key_free(server_key);
    ssh_key_free(private_key);
    if (connected) {
        ssh_disconnect(session);
    }
    ssh_free(session);
    return status;
}
