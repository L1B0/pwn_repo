#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
 
int main (){
 
        // Stage 5
        sleep(5);
        int sockfd;
        struct sockaddr_in server;
        sockfd = socket(AF_INET,SOCK_STREAM,0);
        if ( sockfd < 0){
            perror("Cannot create the socket");
            exit(1);
        }
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr("127.0.0.1");
	printf("%d\n",server.sin_addr.s_addr);
        server.sin_port = htons(55555);
        if ( connect(sockfd, (struct sockaddr*) &server, sizeof(server)) < 0 ){
            perror("Problem connecting");
            exit(1);
        }
        printf("Connected\n");
        char buf[4] = "\xde\xad\xbe\xef";
        write(sockfd,buf,4);
        close(sockfd);
        return 0;
}
