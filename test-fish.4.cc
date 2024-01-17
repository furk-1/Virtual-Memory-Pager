#include <iostream>
#include <cstring>
#include "vm_app.h"

using namespace std;

int main(){
    char *p;
    p = (char *) vm_extend();
    p += 100;
    if(p == NULL){
        printf("vm_extend returned NULL!\n");
    }
    // assuming the VM_PAGESIZE is bigger than 447 bytes
    strcpy(p, "Let any fish who meets my gaze learn the true meaning of fear, for I am the harbinger of death. I am the bane of all creatures subaqueous. As I cast into the aquatic abyss, my rod is true and unwavering. A man, scorned by this uncaring earth finds solace in the sea. My only friend, the worm on my hook, wriggling, writhing, struggling to surmount the moral pointlessness that permeates this barren earth. I am alone. I am empty. And yet, I fish.");
    vm_syslog(p, 447);
}
