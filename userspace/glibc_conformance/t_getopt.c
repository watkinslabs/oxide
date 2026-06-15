#include <stdio.h>
#include <unistd.h>
int main(void){
    char *argv[] = {"prog","-a","-b","val","-c","arg1",0};
    int argc = 6; int opt;
    while((opt = getopt(argc, argv, "ab:c")) != -1){
        if(opt=='b') printf("b=%s ", optarg); else printf("%c ", opt);
    }
    printf("| optind=%d nonopt=%s\n", optind, optind<argc?argv[optind]:"none");
    return 0;
}
