#include <iostream>
#include "vm_app.h"

using namespace std;

//unsigned int N = VM_PAGESIZE-1;
unsigned int N = 5*VM_PAGESIZE;

int main(){
    printf("hello, world!\n");
    int num_pages_required = N / VM_PAGESIZE;
    if(N % VM_PAGESIZE){ // if there is remainder
        num_pages_required++;
    }
    char* p = (char*)vm_extend();
    p += 100;
    num_pages_required++;
    for(int i=0; i < num_pages_required - 1; ++i){
        vm_extend();
    }
    for(int i=0; i<N; ++i){
        p[i] = i%48 + 48;
    }
    vm_syslog(p, N);
}
