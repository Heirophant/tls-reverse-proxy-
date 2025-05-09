## Assignment 3 - Reverse TLS Proxy

> [!CAUTION]
> HTTPS Server would have to be configured (I used apache) and you would have to configure cgi-bin thing for uploading.

### Description
In this assignment we had to implement a TLS reverse proxy for a server using OpenSSL and PAM libraries.

### Building
I have test Reverse Proxy in a VM with apache2 webserver serving on 443. Accordingly change the IPs for you VM system. Both RP and Server are on the same VM.

To build reverse proxy run
```bash
$ make proxy
```

To build client run
```bash
$ make client
```
Run proxy with
```
$ ./rev
```

and client with
```
$ client_tls
```


### Testing

Upon running ```./client_tls``` you would authentication prompt for your username password.

If the credentials are correct. Then ```HTTPS_SERVER> ``` prompt will be printed and following commands can be used.


#### Commands

1) ``ls``

2) ```get <filename>```

3) ```put <filename>```

4) ```exit```


CAUTION: You need to have a bridged adapter in the VM so that you host can send requests to the VM.

### Assumptions
- Using ```ls``` you can see the "html" file directory of only "/" for the webserver. There are no arguments in this. There should be but due to time limitation.

- Get file is downloaded as ```download.file``` and would be overwritten on new `get` request

- Any file not on the server will still be downloaded but would have the apache 404 html downloaded.

- The file you are trying to ```put``` should be in ``pwd``


### Corner Cases

1) You can't get the prompt without valid PAM authentiaction. If authentication fails server would disconnect you.

2) There is not retry option thus preventing brute force.

3) If Proxy has expired certificated the client would get appropriate message and would not even connect.

4) Client can't directly reach server and only through reverse proxy and reverse proxy would not let session access if PAM is not authentiacted.





