#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>


#define PORT 8443
#define BUFFER_SIZE 1024
#define CERT_PATH "./certs/CA.cert"

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char input[100];
    setbuf(stdout, NULL);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("SSL_CTX_new failed");
        exit(1);
    }

    if (!SSL_CTX_load_verify_locations(ctx, CERT_PATH, NULL)) {
        perror("SSL_CTX_load_verify_locations failed");
        exit(1);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("192.168.0.155");


    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    } else {
        printf("SSL/TLS handshake completed successfully!\n");

        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert == NULL) {
            printf("No server certificate found.\n");
            exit(1);
        } else {
            long cert_verify_result = SSL_get_verify_result(ssl);
            if (cert_verify_result != X509_V_OK) {
                printf("Certificate verification failed: %ld\n", cert_verify_result);
                exit(1);
            } else {
                printf("Server certificate verified successfully!\n");
            }
            X509_free(cert);
        }

        for (int i = 0; i < 2; i++) {
            int n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (n <= 0) {
                printf("Error reading from server or connection closed\n");
                break;
            }
            buffer[n] = '\0';
            printf("%s", buffer);
            fgets(input, sizeof(input), stdin);
            SSL_write(ssl, input, strlen(input));
        }

        int n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            printf("Error reading authentication result\n");
            exit(1);
        }
        buffer[n] = '\0';
        printf("%s", buffer);





        memset(buffer,0,sizeof(buffer));
        n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            printf("Connection closed by server\n");
            exit(1);
        }
        buffer[n] = '\0';
        printf("%s", buffer);

        fflush(stdout);

        while (1) {
            memset(buffer,0,sizeof(buffer));


            if (!fgets(buffer, sizeof(buffer), stdin)) {
                printf("Error reading from stdin\n");
                break;
            }



            SSL_write(ssl, buffer, strlen(buffer));

            if (strncmp(buffer, "exit", 4) == 0) {
                n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (n > 0) {
                    buffer[n] = '\0';
                    printf("%s", buffer);
                }
                break;
            }


            if (strncmp(buffer, "get ", 4) == 0) {
                char *filename = buffer + 4;
                filename[strcspn(filename, "\r\n")] = 0;

                char *local_filename = "downloaded.file";

                n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (n <= 0) {
                    printf("Failed to read file size from server\n");
                    continue;
                }
                buffer[n] = '\0';

                if (strncmp(buffer, "ERROR:", 6) == 0) {
                    printf("%s", buffer);
                }

                else{

                    long file_size;
                    if (sscanf(buffer, "FILE_SIZE:%ld", &file_size) != 1) {
                        printf("Invalid file size header: %s\n", buffer);
                        continue;
                    }

                    printf("Receiving file (%ld bytes)...\n", file_size);

                    FILE *fp = fopen(local_filename, "wb");
                    if (!fp) {
                        perror("fopen");
                        continue;
                    }

                    long bytes_received = 0;
                    while (bytes_received < file_size) {
                        int to_read = (file_size - bytes_received > BUFFER_SIZE) ? BUFFER_SIZE : file_size - bytes_received;
                        n = SSL_read(ssl, buffer, to_read);
                        if (n <= 0) {
                            printf("Connection closed while receiving file\n");
                            break;
                        }
                        fwrite(buffer, 1, n, fp);
                        bytes_received += n;
                    }

                    fclose(fp);
                    if (bytes_received == file_size) {
                        printf("File downloaded successfully as '%s'\n", local_filename);
                    } else {
                        printf("File download incomplete\n");
                    }

                }
            }
            else if (strncmp(buffer, "put ", 4) == 0) {
                char *filename = buffer + 4;
                filename[strcspn(filename, "\r\n")] = 0;

                char original_filename[256];
                strncpy(original_filename, filename, sizeof(original_filename)-1);
                original_filename[sizeof(original_filename)-1] = '\0';

                FILE *fp = fopen(original_filename, "rb");
                if (!fp) {
                    fprintf(stderr, "Cannot open file '%s': %s\n", filename, strerror(errno));
                    continue;
                }

                fseek(fp, 0, SEEK_END);
                long file_size = ftell(fp);
                rewind(fp);

                printf("Uploading file '%s' (%ld bytes)...\n", filename, file_size);

                n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (n <= 0) {
                    fprintf(stderr, "Failed to read from server\n");
                    fclose(fp);
                    continue;
                }
                buffer[n] = '\0';

                if (strcmp(buffer, "READY_FOR_FILE\n") != 0) {
                    fprintf(stderr, "Unexpected server response: %s\n", buffer);
                    fclose(fp);
                    continue;
                }

                snprintf(buffer, sizeof(buffer), "FILE_SIZE:%ld", file_size);
                SSL_write(ssl, buffer, strlen(buffer));

                n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (n <= 0) {
                    fprintf(stderr, "Failed to read from server\n");
                    fclose(fp);
                    continue;
                }
                buffer[n] = '\0';

                if (strcmp(buffer, "START_TRANSFER\n") != 0) {
                    fprintf(stderr, "Server rejected file transfer: %s\n", buffer);
                    fclose(fp);
                    continue;
                }

                long bytes_sent = 0;
                while (bytes_sent < file_size) {
                    size_t to_read = (file_size - bytes_sent > BUFFER_SIZE) ?
                        BUFFER_SIZE : (file_size - bytes_sent);

                    size_t bytes_read = fread(buffer, 1, to_read, fp);
                    if (bytes_read <= 0) {
                        if (ferror(fp)) {
                            fprintf(stderr, "Error reading from file\n");
                        }
                        break;
                    }

                    int sent = SSL_write(ssl, buffer, bytes_read);
                    if (sent <= 0) {
                        fprintf(stderr, "Error sending data to server\n");
                        break;
                    }

                    bytes_sent += sent;

                }

                fclose(fp);

                n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (n <= 0) {
                    fprintf(stderr, "Failed to read server's confirmation\n");
                    continue;
                }
                buffer[n] = '\0';

                printf("%s", buffer);

            }

            char response[BUFFER_SIZE * 10] = "";
            int total_bytes = 0;
            int prompt_found = 0;

            while (!prompt_found) {
                n = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (n <= 0) {
                    printf("Connection closed by server\n");
                    return 1;
                }

                buffer[n] = '\0';
                printf("%s", buffer);
                if (strstr(buffer, "HTTPS_SERVER>") != NULL) {
                    prompt_found = 1;
                }
            }

        }



    }

    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

