
fornow:	server client

server:	tcp-basic-echo-server.c tcp-concur-echo-server.c
		gcc -o tcp-basic-echo-server tcp-basic-echo-server.c
		gcc -o tcp-concur-echo-server tcp-concur-echo-server.c

client:	tcp-client.c
		gcc -o tcp-echo-client tcp-client.c

clean:
		rm tcp-concur-echo-server tcp-basic-echo-server tcp-echo-client
