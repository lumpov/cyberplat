#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>


int java(const char* clazz,const char* param,char* dst,int len)
{
    int fd[2];
    if(pipe(fd))
	return -1;

    pid_t pid=fork();
    if(pid>0)
    {
	close(fd[1]);
	int l=0;
	while(l<len)
	{
	    int n=read(fd[0],dst+l,len-l-1);
	    if(n<=0)
		break;
	    l+=n;
	}
	dst[l]=0;
	waitpid(pid,0,0);
	close(fd[0]);
	return l;
    }else if(!pid)
    {
	for(int i=0;i<3;i++)
	    close(i);
	dup2(fd[1],1);
	for(int i=0;i<2;i++)
	    close(fd[i]);
	execlp("java","java",clazz,param,0);
	exit(0);
    }
    for(int i=0;i<2;i++)
	close(fd[i]);
    return 0;
}


int main(int argc,char** argv)
{
    if(argc<2)
	return 0;

    if(!strcmp(argv[1],"include"))
    {
	char java_home[2048];
	int l=java("jenv","java.home",java_home,sizeof(java_home));
	if(l>0)
	{
	    if(java_home[l-1]=='/')
		java_home[l-1]=0;

	    char* p=strrchr(java_home,'/');
	    if(p && !strcmp(p+1,"jre"))
		*p=0;
	
	    strcat(java_home,"/include");
	    printf("-I%s",java_home);

	    strcat(java_home,"/linux");
	    printf(" -I%s",java_home);
	}
    }else if(!strcmp(argv[1],"jdk"))
    {
	char java_home[2048];
	int l=java("jenv","java.home",java_home,sizeof(java_home));
	if(l>0)
	{
	    if(java_home[l-1]=='/')
		java_home[l-1]=0;

	    char* p=strrchr(java_home,'/');
	    if(p && !strcmp(p+1,"jre"))
		*p=0;
	
	    printf("%s",java_home);
	}
    }

    return 0;
}
