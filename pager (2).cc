#include <map>
#include <queue>
#include <stdexcept>
#include <string>
#include <assert.h>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include "vm_pager.h"

using namespace std;

#define PAGE_TABLE_SIZE VM_ARENA_SIZE/VM_PAGESIZE // 65536
#define NO_PID (pid_t)(-1)
#define NO_BLOCK (disk_block_num)(-1)
#define NO_VPN (vpage_num)(-1)
#define NO_PPN (ppage_num)(-1)
#define DEBUG false
#define printf_debug(format, ...) (DEBUG ? (void)printf(format, ##__VA_ARGS__) : (void)0)
#define printf_and_die(format, ...) (printf(format, ##__VA_ARGS__), throw runtime_error(""))
#define key_exists(map, key) (map.find(key) != map.end())

typedef unsigned long vpage_num;
typedef unsigned int ppage_num;
typedef unsigned int disk_block_num;

struct page_info_table_entry_t{
    bool valid = false; // am I in the arena?
    bool resident = false; // am I written to physical memory?
    bool dirty = false; // set true on first write
    bool referenced = false; // set true on first read
    bool written_to_disk = false; // have I ever been written to disk?
    disk_block_num my_disk_block = NO_BLOCK; // if on disk, which disk block is it written to?
    ppage_num stored_ppage = NO_PPN; // if on RAM, which physical page is it written to?
};

struct page_info_table_t{
    // both tables indexed by vpage number
    page_info_table_entry_t ptes[PAGE_TABLE_SIZE];
};

struct process{
    pid_t pid;
    page_table_t* page_table;
    page_info_table_t* page_info_table;
};

struct physical_page{
    // owner process tells you in which page table the VPN is relevant
    vpage_num vpn = NO_VPN;
    pid_t owner_pid = NO_PID;
};

struct disk_block{
    bool is_free = true;
};

physical_page* PHYSICAL_PAGES;
ppage_num NUM_PHYSICAL_PAGES;
std::queue<ppage_num> FREE_PHYSICAL_PAGES;
std::queue<ppage_num> EVICTION_QUEUE;
disk_block* DISK_BLOCKS;
disk_block_num NUM_DISK_BLOCKS = 0;
std::map<pid_t, process> PROCESSES;
process* ACTIVE_PROCESS = NULL;

void vm_init(unsigned int memory_pages, unsigned int disk_blocks);
void vm_create(pid_t pid);
void vm_switch(pid_t pid);
int vm_fault(void* addr, bool write_flag);
void vm_destroy();
void* vm_extend();
int vm_syslog(void* message, unsigned int len);
ppage_num claim_ppage();
disk_block_num claim_disk_block();
vpage_num claim_vpage();
void evict_ppage(ppage_num ppn);
void zero_fill_ppage(ppage_num ppn);
pid_t active_pid();
void assert_ppn_index_exists(ppage_num ppn);
void assert_pid_created(pid_t pid);
void make_sure_vpage_resident(vpage_num vpn);
bool ptr_vm_in_arena(void* ptr);
bool vpn_in_arena(vpage_num vpn);
page_info_table_entry_t* get_vpage_info(vpage_num vpn);
page_table_entry_t* get_vpage(vpage_num vpn);
page_info_table_entry_t* get_vpage_info_pid(vpage_num vpn, pid_t pid);
page_table_entry_t* get_vpage_pid(vpage_num vpn, pid_t pid);
page_info_table_entry_t* get_vpage_info_from_ppn(ppage_num ppn);
page_table_entry_t* get_vpage_from_ppn(ppage_num ppn);
unsigned int ptr_vm_to_page_offset(void* ptr);
void* ppn_to_ptr_pm(ppage_num ppn);
void* vpn_to_ptr_pm(vpage_num vpn);
void* vpn_to_ptr_vm(vpage_num vpn);
vpage_num ptr_vm_to_vpn(void* ptr);
void print_phys_page_info();
void print_vpage(vpage_num vpn, pid_t pid);

void vm_init(unsigned int memory_pages, unsigned int disk_blocks){
    printf_debug("vm_init %u mem pages, %u disk blocks\n", memory_pages, disk_blocks);
    PHYSICAL_PAGES = new physical_page[memory_pages];
    NUM_PHYSICAL_PAGES = memory_pages;
    DISK_BLOCKS = new disk_block[disk_blocks];
    NUM_DISK_BLOCKS = disk_blocks;
    for(unsigned int i = 0; i<memory_pages; ++i){
        FREE_PHYSICAL_PAGES.push(i);
    }
}

void vm_create(pid_t pid){
    if(key_exists(PROCESSES, pid)){
        printf_and_die("cannot vm_create pid %d that is already in the process map!\n", pid);
    }
    page_table_t* new_page_table = new page_table_t;
    page_info_table_t* new_page_info_table = new page_info_table_t;
    process new_process;
    new_process.pid = pid;
    new_process.page_table = new_page_table;
    new_process.page_info_table = new_page_info_table;
    PROCESSES[pid] = new_process;
}

void vm_switch(pid_t pid){
    if(!key_exists(PROCESSES, pid)){
        printf_and_die("cannot switch to nonexistent process %d!\n", pid);
    }
    if(ACTIVE_PROCESS != NULL && active_pid() == pid){
        printf_and_die("active process %d tried to switch to itself! (%d)\n", active_pid(), pid);
    }
    ACTIVE_PROCESS = &PROCESSES[pid];
    page_table_base_register = ACTIVE_PROCESS->page_table;
}

int vm_fault(void* addr, bool write_flag){
    /*
    either update permissions or page this address into physical memory
    */
    if(!ptr_vm_in_arena(addr)){
        return -1;
    }
    if(DEBUG){
        print_phys_page_info();
    }
    vpage_num vpn = ptr_vm_to_vpn(addr);
    page_table_entry_t* vpage = get_vpage(vpn);
    page_info_table_entry_t* vpage_info = get_vpage_info(vpn);
    if(!vpage_info->valid){
        printf_debug("reference to valid==false vpage %lu! returning -1.\n", vpn);
        return -1;
    }
    if(!vpage_info->resident){
        ppage_num destination_ppn = claim_ppage();
        if(!vpage_info->written_to_disk){
            zero_fill_ppage(destination_ppn);
        }else{
            disk_block_num block = vpage_info->my_disk_block;
           // assert(block != NO_BLOCK);
            if (block == NO_BLOCK) {
                return -1;
            }
            disk_read(block, destination_ppn);
        }
        vpage_info->resident = true;
        vpage_info->stored_ppage = destination_ppn;
        vpage->ppage = destination_ppn;
        PHYSICAL_PAGES[destination_ppn].vpn = vpn;
        PHYSICAL_PAGES[destination_ppn].owner_pid = active_pid();
    }
    printf_debug("setting referenced bit on vpage %lu to 1!\n", vpn);
    vpage_info->referenced = true;
    vpage->read_enable = 1;
    // if already dirty but the clock algorithm has unset write_enable, put it back
    if(!vpage_info->referenced && vpage_info->dirty){
        printf_debug("setting write_enable on vpage %lu back to 1!\n", vpn);
        vpage->write_enable = 1;
    }
    if(write_flag){
        printf_debug("setting dirty bit on vpage %lu to 1!\n", vpn);
        vpage_info->dirty = true;
        vpage->write_enable = 1;
    }
    return 0;
}

void vm_destroy(){
    // loop over valid virtual memory and free any allocated physical pages
    for(vpage_num i = 0; i<PAGE_TABLE_SIZE; ++i){
        page_info_table_entry_t* this_vpage_info = get_vpage_info(i);
        if(!this_vpage_info->valid){
            break;
        }
        ppage_num this_stored_ppn = this_vpage_info->stored_ppage;
        if(this_stored_ppn != NO_PPN){
            PHYSICAL_PAGES[this_stored_ppn].vpn = NO_VPN;
            PHYSICAL_PAGES[this_stored_ppn].owner_pid = NO_PID;
            FREE_PHYSICAL_PAGES.push(this_stored_ppn);
        }
    }
    // loop over valid virtual memory and free any allocated disk blocks
    for(vpage_num i = 0; i<PAGE_TABLE_SIZE; ++i){
        page_info_table_entry_t* this_vpage_info = get_vpage_info(i);
        if(!this_vpage_info->valid){
            break;
        }
        disk_block_num this_my_disk_block = this_vpage_info->my_disk_block;
        if(this_my_disk_block != 0){
            DISK_BLOCKS[this_my_disk_block].is_free = true;
        }
    }
    delete ACTIVE_PROCESS->page_info_table;
    delete ACTIVE_PROCESS->page_table;
    // remove from PROCESSES map based on pid
    for(std::map<pid_t, process>::iterator i = PROCESSES.begin(); i != PROCESSES.end(); ++i){
        if((*i).second.pid == active_pid()){
            PROCESSES.erase(i);
            break;
        }
    }
    assert(!key_exists(PROCESSES, active_pid()));
    ACTIVE_PROCESS = NULL;
    page_table_base_register = NULL;
    return;
}

void* vm_extend(){
    vpage_num vpn = claim_vpage();
    if(vpn == NO_VPN){
        printf_debug("unable to find invalid page!\n");
        return NULL;
    }
    printf_debug("allocated vpage %lu\n", vpn);
    page_info_table_entry_t* this_vpage_info = get_vpage_info(vpn);
    page_table_entry_t* this_vpage = get_vpage(vpn);
    this_vpage_info->valid = true;
    this_vpage->read_enable = 0;
    this_vpage->write_enable = 0;
    disk_block_num destination_disk_block = claim_disk_block();
    if(destination_disk_block == NO_BLOCK){
        printf_debug("unable to allocate disk block!\n");
        return NULL;
    }
    printf_debug("allocated disk block %d\n", destination_disk_block);
    this_vpage_info->my_disk_block = destination_disk_block;
    // return fake ptr to newly validated virtual address
    void* ptr = vpn_to_ptr_vm(vpn);
    return ptr;
}

int vm_syslog(void* message, unsigned int len){
    if(len==0){
        printf_debug("syslog with length 0! Returning -1\n");
        return -1;
    }
    if(!ptr_vm_in_arena(message)){
        printf_debug("message base address %p not in arena! Returning -1\n", message);
        return -1;
    }
    char* last_byte_of_message = (char*)message + len - 1;
    if(!ptr_vm_in_arena(last_byte_of_message)){
        printf_debug("last byte of message %p not in arena!\n", last_byte_of_message);
        return -1;
    }
    // start the cursor at the location of the start of the message
    // this is defind by the page and the offset within page
    vpage_num start_vpn = ptr_vm_to_vpn(message);
    make_sure_vpage_resident(start_vpn); // this is required for vpn_to_ptr_pm
    char* cursor = (char*)vpn_to_ptr_pm(start_vpn) + ptr_vm_to_page_offset(message);
    string message_copy;
    unsigned int index = 0;
    vpage_num end_vpn = ptr_vm_to_vpn(last_byte_of_message);
    for (vpage_num current_vpn = start_vpn; current_vpn <= end_vpn; ++current_vpn){
        make_sure_vpage_resident(current_vpn);
        page_table_entry_t* current_vpage = get_vpage(current_vpn);
        if(!current_vpage->read_enable){
            current_vpage->read_enable = 1;
            get_vpage_info(current_vpn)->referenced = true;
        }
        // when we move on to a new page, update the cursor to the base of that page in phys mem
        // if this is the very first page, cursor was set based on the message's page offset
        if(current_vpn != start_vpn){
            cursor = (char*)vpn_to_ptr_pm(current_vpn);
        }
        char* last_byte_of_page = (char*)vpn_to_ptr_pm(current_vpn) + VM_PAGESIZE - 1;
        for(; cursor <= last_byte_of_page && index < len; ++cursor, ++index){
            message_copy.push_back(*cursor);
        }
    }
    cout << "syslog \t\t\t" << message_copy << endl;
    return 0;
}

ppage_num claim_ppage(){
    /*
    either pop a page off the free list, or evict another page to make room for this one
    "clock algorithm"
    */
    ppage_num this_ppn;
    if(FREE_PHYSICAL_PAGES.size() > 0){
        this_ppn = FREE_PHYSICAL_PAGES.front();
        FREE_PHYSICAL_PAGES.pop();
        EVICTION_QUEUE.push(this_ppn);
        return this_ppn;
    }
    assert(EVICTION_QUEUE.size() > 0);
    while(true){
        this_ppn = EVICTION_QUEUE.front();
        EVICTION_QUEUE.pop();
        EVICTION_QUEUE.push(this_ppn);
        page_info_table_entry_t* this_vpage_info = get_vpage_info_from_ppn(this_ppn);
        page_table_entry_t* this_vpage = get_vpage_from_ppn(this_ppn);
        if(this_vpage_info->referenced){
            this_vpage_info->referenced = false;
            this_vpage->read_enable = 0;
            this_vpage->write_enable = 0; // a page should never be ~r+w
        }else{
            evict_ppage(this_ppn);
            return this_ppn;
        }
    }
}

disk_block_num claim_disk_block(){
    for(disk_block_num i = 0; i < NUM_DISK_BLOCKS; ++i){
        if(DISK_BLOCKS[i].is_free){
            DISK_BLOCKS[i].is_free = false;
            return i;
        }
    }
    return NO_BLOCK;
}

vpage_num claim_vpage(){
    for(vpage_num i = 0; i < PAGE_TABLE_SIZE; ++i){
        page_info_table_entry_t* vpage_info = get_vpage_info(i);
        if(!vpage_info->valid){
            vpage_info->valid = true;
            return i;
        }
    }
    return NO_VPN;
}

void evict_ppage(ppage_num ppn){
    printf_debug("evict_ppage %d\n", ppn);
    physical_page* this_ppage = &PHYSICAL_PAGES[ppn];
    vpage_num vpn = this_ppage->vpn;
    pid_t owner_pid = this_ppage->owner_pid;
    printf_debug("vpn: %lu owner: %d\n", vpn, owner_pid);
    page_info_table_entry_t* this_vpage_info = get_vpage_info_pid(vpn, owner_pid);
    page_table_entry_t* this_vpage = get_vpage_pid(vpn, owner_pid);
    assert(this_vpage_info->resident);
    assert(this_vpage_info->stored_ppage == ppn);
    if(this_vpage_info->dirty){
        disk_write(this_vpage_info->my_disk_block, this_vpage_info->stored_ppage);
        this_vpage_info->dirty = false;
        this_vpage_info->written_to_disk = true;
    }
    this_vpage_info->stored_ppage = NO_PPN;
    this_vpage_info->resident = false;

    this_ppage->vpn = NO_VPN;
    this_ppage->owner_pid = NO_PID;

    this_vpage->ppage = NO_PPN;
    this_vpage->read_enable = 0;
    this_vpage->write_enable = 0;
}

void zero_fill_ppage(ppage_num ppn){
    printf_debug("zero fill ppage %d\n", ppn);
    assert_ppn_index_exists(ppn);
    memset(ppn_to_ptr_pm(ppn), 0, VM_PAGESIZE);
}

pid_t active_pid(){
    assert(ACTIVE_PROCESS != NULL);
    return ACTIVE_PROCESS->pid;
}

void assert_ppn_index_exists(ppage_num ppn){
    if(ppn >= NUM_PHYSICAL_PAGES){
        printf_and_die("ppn %d is outside max index %d!\n", ppn, NUM_PHYSICAL_PAGES);
    }
}

void assert_pid_created(pid_t pid){
    if(!key_exists(PROCESSES, pid)){
        printf_and_die("pid %d is not in the PROCESSES map!\n", pid);
    }
}

void make_sure_vpage_resident(vpage_num vpn){
    printf_debug("make_sure_vpage_resident %lu\n", vpn);
    assert(vpn_in_arena(vpn));
    page_info_table_entry_t* vpage_info = get_vpage_info(vpn);
    if(!vpage_info->resident){
        // I can't remember why we do two of these
        printf_debug("vpn %lu not resident, making two vm_fault's!\n", vpn);
        vm_fault(vpn_to_ptr_vm(vpn), false);
        vm_fault(vpn_to_ptr_vm(vpn), false);
    }
    assert(vpage_info->resident);
}

bool ptr_vm_in_arena(void* ptr){
    void* arena_begin = vpn_to_ptr_vm(0);
    vpage_num last_valid_vpn;
    vpage_num i = 0;
    while(get_vpage_info(i)->valid){
        last_valid_vpn = i;
        i++;
    }
    void* arena_last_byte = (char*)vpn_to_ptr_vm(last_valid_vpn) + VM_PAGESIZE - 1;
    return(ptr >= arena_begin && ptr <= arena_last_byte);
}

bool vpn_in_arena(vpage_num vpn){
    return ptr_vm_in_arena(vpn_to_ptr_vm(vpn));
}

page_info_table_entry_t* get_vpage_info(vpage_num vpn){
    return get_vpage_info_pid(vpn, active_pid());
}

page_table_entry_t* get_vpage(vpage_num vpn){
    return get_vpage_pid(vpn, active_pid());
}

page_info_table_entry_t* get_vpage_info_pid(vpage_num vpn, pid_t pid){
    assert_pid_created(pid);
    return &PROCESSES[pid].page_info_table->ptes[vpn];
}

page_table_entry_t* get_vpage_pid(vpage_num vpn, pid_t pid){
    assert_pid_created(pid);
    return &PROCESSES[pid].page_table->ptes[vpn];
}

page_info_table_entry_t* get_vpage_info_from_ppn(ppage_num ppn){
    assert_ppn_index_exists(ppn);
    return get_vpage_info_pid(PHYSICAL_PAGES[ppn].vpn, PHYSICAL_PAGES[ppn].owner_pid);
}

page_table_entry_t* get_vpage_from_ppn(ppage_num ppn){
    assert_ppn_index_exists(ppn);
    return get_vpage_pid(PHYSICAL_PAGES[ppn].vpn, PHYSICAL_PAGES[ppn].owner_pid);
}

unsigned int ptr_vm_to_page_offset(void* ptr) {
    unsigned long arena_byte_num = (char*)ptr - (char*)VM_ARENA_BASEADDR;
    unsigned int arena_offset = arena_byte_num % VM_PAGESIZE;
    return arena_offset;
}

void* ppn_to_ptr_pm(ppage_num ppn){
    assert_ppn_index_exists(ppn);
    //printf_debug("ppn_to_ptr_pm %d\n", ppn);
    unsigned long byte_offset = ppn*VM_PAGESIZE;
    return (char*)pm_physmem + byte_offset;
}

void* vpn_to_ptr_pm(vpage_num vpn){
    assert(get_vpage_info(vpn)->resident);
    assert(get_vpage_info(vpn)->stored_ppage != NO_PPN);
    return ppn_to_ptr_pm(get_vpage_info(vpn)->stored_ppage);
}

void* vpn_to_ptr_vm(vpage_num vpn){
    //assert(vpn_in_arena(vpn)); // vpn_in_arena calls this function!
    void* my_ptr = (void*)((char*)VM_ARENA_BASEADDR + vpn * VM_PAGESIZE);
    return my_ptr;
}

vpage_num ptr_vm_to_vpn(void* ptr) {
    unsigned long arena_byte_num = (char*)ptr - (char*)VM_ARENA_BASEADDR;
    vpage_num vpn = arena_byte_num / VM_PAGESIZE;
    //printf_debug("ptr %p -> vpn %lu\n", ptr, vpn);
    return vpn;
}

void print_phys_page_info(){
    physical_page this_ppage;
    for(ppage_num i = 0; i < NUM_PHYSICAL_PAGES; ++i){
        this_ppage = PHYSICAL_PAGES[i];
        printf("ppage %d ", i);
        if(this_ppage.owner_pid == NO_PID){
            printf("page has no owner\n");
            continue;
        }
        printf("owner_pid: %d vpage: %lu\n", this_ppage.owner_pid, this_ppage.vpn);
    }
}

void print_vpage(vpage_num vpn, pid_t pid){
    page_info_table_entry_t* this_vpage = get_vpage_info_pid(vpn, pid);
    printf("vpage %lu\n", vpn);
    printf("valid: %d ", this_vpage->valid);
    printf("resident: %d ", this_vpage->resident);
    printf("dirty: %d ", this_vpage->dirty);
    printf("referenced: %d ", this_vpage->referenced);
    printf("written_to_disk: %d ", this_vpage->written_to_disk);
    printf("my_disk_block: %d ", this_vpage->my_disk_block);
    printf("stored_phys_page: %u\n", this_vpage->stored_ppage);
}



// Test 14 is Syslog - when the reference bit has been cleared due to the clock algorithm but it is a dirty page, when the page is referenced again (read faults), the protection bit should be set to read AND write
//20-24 - large uniprocess pages - evicting lots of pages- more virtual 64 than physical pages 32- stressing the clock algorithm
// ----
// 27 - Write a test that runs out of swap space - remove assertion for submission, have extend return -1 so we don't fail assertions
