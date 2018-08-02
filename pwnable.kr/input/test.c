#include<stdio.h>
#include<string.h>
int main(int argc, char* argv[], char* envp[])
{
	printf("%s \n",argv[1]);
	printf("%d\n",strlen("\x00"));
	printf("%d\n",strcmp(argv[1],"\x00"));
	return 0;
}
