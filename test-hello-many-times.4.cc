#include <iostream>
#include "vm_app.h"

using namespace std;

int main(){
    printf("hello, world!\n");
    char* messages[10];
    for(int i=0; i<10; ++i){
        char *p;
        messages[i] = (char *) vm_extend();
        messages[i][0] = 'h';
        messages[i][1] = 'e';
        messages[i][2] = 'l';
        messages[i][3] = 'l';
        messages[i][4] = 'o';
        messages[i][5] = i+48;
        messages[i][6] = '\0';
        //vm_syslog(messages[i], 6);
    }
    for(int i=0; i<10; ++i){
        vm_syslog(messages[i], 6);
    }
}
