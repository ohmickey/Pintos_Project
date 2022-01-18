#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"


/* project3 */
#include "devices/disk.h"
#define INVALID_SLOT_IDX SIZE_MAX
/* project3 */

struct page;
enum vm_type;

struct anon_page {
    /* project3 */
   int swap_index;
    /* project3 */
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
