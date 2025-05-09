#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <pthread.h>

#define PORT 8443
#define BUFFER_SIZE 2048


// #define CERT_PATH "./certs/expired.crt"
// #define KEY_PATH "./certs/expired.key"

#define CERT_PATH "./certs/proxy.crt"
#define KEY_PATH "./certs/proxy.key"
#define SERVER_CERT "./certs/server.crt"
#define SERVER_KEY "./certs/server.key"
#define CA_CERT "./certs/CA.cert"

#define HTTPS_HOST "127.0.0.1"
#define HTTPS_PORT "443"

pthread_key_t password_key;

typedef struct {
    int client_fd;
    SSL *ssl;
} client_args;

int pam_conversation(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *reply = calloc(num_msg, sizeof(struct pam_response));
    if (!reply) return PAM_CONV_ERR;

    char *password = (char *)pthread_getspecific(password_key);
    if (!password) return PAM_CONV_ERR;

    for (int i = 0; i < num_msg; ++i) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            reply[i].resp = strdup(password);
        } else {
            reply[i].resp = strdup("");
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

int pam_authenticate_user(const char *username, const char *password) {
    pthread_setspecific(password_key, (void *)password);

    struct pam_conv conv = { pam_conversation, NULL };
    pam_handle_t *pamh = NULL;

    int retval = pam_start("login", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) return retval;

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return retval;
    }

    retval = pam_acct_mgmt(pamh, 0);
    pam_end(pamh, retval);
    return retval;
}

SSL_CTX* InitServerCTX(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("SSL_CTX_new failed");
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_PATH, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_certificate_file failed");
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_PATH, SSL_FILETYPE_PEM) <= 0) {
        perror("SSL_CTX_use_PrivateKey_file failed");
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the public certificate");
        exit(1);
    }

    return ctx;
}

SSL *connect_to_server() {
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    if (!client_ctx || !SSL_CTX_load_verify_locations(client_ctx, CA_CERT, NULL)) {
        fprintf(stderr, "Failed to set up client context\n");
        return NULL;
    }

    int sockfd;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo("localhost", "443", &hints, &res) != 0) {
        fprintf(stderr, "DNS resolution failed\n");
        return NULL;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0 || connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        fprintf(stderr, "Connection to Apache2 failed\n");
        return NULL;
    }

    SSL *client_ssl = SSL_new(client_ctx);
    SSL_set_fd(client_ssl, sockfd);

    if (SSL_connect(client_ssl) != 1) {
        fprintf(stderr, "TLS connect to Apache failed\n");
        SSL_free(client_ssl);
        close(sockfd);
        return NULL;
    }

    return client_ssl;
}

void handle_client_commands(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int n;

    SSL_write(ssl, "HTTPS_SERVER> ", 14);

    while (1) {
        n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            fprintf(stderr, "Client disconnected\n");
            break;
        }

        buffer[n] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0;
        printf("Received command: %s\n", buffer);

        if (strncmp(buffer, "ls", 2) == 0) {
            SSL *backend_ssl = connect_to_server();
            if (!backend_ssl) {
                SSL_write(ssl, "Failed to connect to backend server.\n", 37);
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            SSL_write(backend_ssl, request, strlen(request));

            char response_buffer[BUFFER_SIZE];
            int bytes;
            while ((bytes = SSL_read(backend_ssl, response_buffer, sizeof(response_buffer) - 1)) > 0) {
                response_buffer[bytes] = '\0';
                SSL_write(ssl, response_buffer, bytes);
            }

            SSL_shutdown(backend_ssl);
            SSL_free(backend_ssl);

            SSL_write(ssl, "HTTPS_SERVER> ", 14);
        }

        else if (strncmp(buffer, "get ", 4) == 0) {
            char *filename = buffer + 4;
            filename[strcspn(filename, "\r\n")] = 0;

            SSL *backend_ssl = connect_to_server();
            if (!backend_ssl) {
                SSL_write(ssl, "ERROR: Failed to connect to backend server.\n", 43);
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            char request[BUFFER_SIZE];
            snprintf(request, sizeof(request),
                    "GET /%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    filename);

            SSL_write(backend_ssl, request, strlen(request));

            char *response_data = NULL;
            size_t response_size = 0;
            size_t total_bytes = 0;
            char temp_buffer[BUFFER_SIZE];
            int bytes_read;

            while ((bytes_read = SSL_read(backend_ssl, temp_buffer, sizeof(temp_buffer))) > 0) {
                response_data = realloc(response_data, total_bytes + bytes_read);
                if (!response_data) {
                    SSL_write(ssl, "ERROR: Memory allocation failed.\n", 33);
                    SSL_shutdown(backend_ssl);
                    SSL_free(backend_ssl);
                    SSL_write(ssl, "HTTPS_SERVER> ", 14);
                    continue;
                }

                memcpy(response_data + total_bytes, temp_buffer, bytes_read);
                total_bytes += bytes_read;
            }

            SSL_shutdown(backend_ssl);
            SSL_free(backend_ssl);

            if (total_bytes == 0) {
                SSL_write(ssl, "ERROR: Empty response from backend server.\n", 42);
                free(response_data);
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            char header[64];
            snprintf(header, sizeof(header), "FILE_SIZE:%zu\n", total_bytes);
            SSL_write(ssl, header, strlen(header));

            SSL_write(ssl, response_data, total_bytes);

            free(response_data);

            usleep(10000);
            SSL_write(ssl, "HTTPS_SERVER> ", 14);
        }

        else if (strncmp(buffer, "put ", 4) == 0) {
            char *filename = buffer + 4;
            filename[strcspn(filename, "\r\n")] = 0;

            char local_filename[256];
            strncpy(local_filename, buffer + 4, sizeof(local_filename) - 1);
            local_filename[sizeof(local_filename) - 1] = '\0';
            local_filename[strcspn(local_filename, "\r\n")] = 0;

            if (strstr(filename, "..") || strchr(filename, '/')) {
                const char *err_msg = "ERROR: Invalid filename. Cannot contain '..' or '/'\n";
                SSL_write(ssl, err_msg, strlen(err_msg));
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            SSL_write(ssl, "READY_FOR_FILE\n", 15);

            memset(buffer, 0, BUFFER_SIZE);
            n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (n <= 0) {
                fprintf(stderr, "Error reading file size from client\n");
                continue;
            }
            buffer[n] = '\0';

            long file_size = 0;
            if (sscanf(buffer, "FILE_SIZE:%ld", &file_size) != 1) {
                const char *err_msg = "ERROR: Invalid file size format\n";
                SSL_write(ssl, err_msg, strlen(err_msg));
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            if (file_size <= 0 ){
                char err_msg[100];

                snprintf(err_msg, sizeof(err_msg),"ERROR: Invalid file size: %ld\n", file_size);
                SSL_write(ssl, err_msg, strlen(err_msg));
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            char temp_path[256];
            snprintf(temp_path, sizeof(temp_path), "/tmp/%s", local_filename);

            FILE *fp = fopen(temp_path, "wb");
            if (!fp) {
                const char *err_msg = "ERROR: Cannot create temporary file\n";
                SSL_write(ssl, err_msg, strlen(err_msg));
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            SSL_write(ssl, "START_TRANSFER\n", 15);

            long bytes_received = 0;
            while (bytes_received < file_size) {
                int to_read = (file_size - bytes_received > BUFFER_SIZE) ?
                    BUFFER_SIZE : (file_size - bytes_received);

                n = SSL_read(ssl, buffer, to_read);
                if (n <= 0) {
                    fprintf(stderr, "Connection closed while receiving file\n");
                    break;
                }

                fwrite(buffer, 1, n, fp);
                bytes_received += n;
            }

            fclose(fp);

            if (bytes_received != file_size) {
                char err_msg[100];
                snprintf(err_msg, sizeof(err_msg),
                        "ERROR: Incomplete file transfer. Got %ld of %ld bytes\n",
                        bytes_received, file_size);
                SSL_write(ssl, err_msg, strlen(err_msg));
                unlink(temp_path);
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            char curl_cmd[1024];
            snprintf(curl_cmd, sizeof(curl_cmd),
                    "curl -k -X POST -F \"file=@%s\" https://localhost/cgi-bin/upload.cgi",
                    temp_path);

            FILE *curl_output = popen(curl_cmd, "r");
            if (!curl_output) {
                const char *err_msg = "ERROR: Failed to execute curl command\n";
                SSL_write(ssl, err_msg, strlen(err_msg));
                unlink(temp_path);
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            char curl_result[BUFFER_SIZE] = {0};
            size_t curl_bytes_read = fread(curl_result, 1, BUFFER_SIZE - 1, curl_output);
            int curl_status = pclose(curl_output);

            unlink(temp_path);

            if (curl_status != 0) {
                char err_msg[BUFFER_SIZE];
                snprintf(err_msg, sizeof(err_msg),
                        "ERROR: Upload to server failed (curl returned %d)\n%s\n",
                        curl_status, curl_result);
                SSL_write(ssl, err_msg, strlen(err_msg));
                SSL_write(ssl, "HTTPS_SERVER> ", 14);
                continue;
            }

            char success_msg[BUFFER_SIZE + 100];
            snprintf(success_msg, sizeof(success_msg),
                    "SUCCESS: File '%s' uploaded to server (%ld bytes)\nServer response:\n%s\n",
                    filename, file_size, curl_result);
            SSL_write(ssl, success_msg, strlen(success_msg));
            SSL_write(ssl, "HTTPS_SERVER> ", 14);
        }

        else if (strncmp(buffer, "exit", 4) == 0) {
            SSL_write(ssl, "Goodbye!\n", 9);
            break;
        }
        else {
            SSL_write(ssl, "Unknown command. Available commands: ls, get, put, exit\n", 56);
            SSL_write(ssl, "HTTPS_SERVER> ", 14);
        }
    }
}

void *handle_client(void *arg) {
    client_args *args = (client_args *)arg;
    int client_fd = args->client_fd;
    SSL *ssl = args->ssl;
    free(args);

    char username[100] = {0};
    char pwd[100] = {0};

    SSL_write(ssl, "Username: ", 10);
    SSL_read(ssl, username, sizeof(username));
    username[strcspn(username, "\r\n")] = 0;

    SSL_write(ssl, "Password: ", 10);
    SSL_read(ssl, pwd, sizeof(pwd));
    pwd[strcspn(pwd, "\r\n")] = 0;

    int auth_result = pam_authenticate_user(username, pwd);

    if (auth_result == PAM_SUCCESS) {
        SSL_write(ssl, "Authentication successful!\n", 27);
        handle_client_commands(ssl);
    } else {
        SSL_write(ssl, "Authentication failed.\n", 22);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);

    pthread_exit(NULL);
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    pthread_key_create(&password_key, NULL);

    SSL_CTX *ctx = InitServerCTX();
    int server_fd, client_fd;
    struct sockaddr_in addr;
    SSL *ssl;
    pthread_t tid;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    listen(server_fd, 10);
    printf("TLS Server listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("Client connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        client_args *args = malloc(sizeof(client_args));
        if (!args) {
            perror("malloc");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        args->client_fd = client_fd;
        args->ssl = ssl;

        if (pthread_create(&tid, NULL, handle_client, (void *)args) != 0) {
            perror("pthread_create");
            free(args);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        pthread_detach(tid);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    pthread_key_delete(password_key);

    return 0;
}
