proxy:
	gcc reverse_proxy.c -o rev -lssl -lcrypto -lpam -lpam_misc

client:
	gcc client_tls.c -o client_tls -lssl -lcrypto -lpam -lpam_misc

c_proxy:
	rm ./rev

c_client:
	rm ./client_tls

