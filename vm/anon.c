/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
//project3
#include "bitmap.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"


/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* project3 */
struct bitmap *swap_table;
const size_t SECTORS_PER_PAGE = PGSIZE / DISK_SECTOR_SIZE;
// struct lock bitmap_lock;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */

    /* project3 */
    swap_disk = disk_get(1, 1);
    size_t swap_size = disk_size(swap_disk) / SECTORS_PER_PAGE;
    swap_table = bitmap_create(swap_size);
    // lock_init(&bitmap_lock);
    /* project3 */

}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;

  /* project3 */
  return true;
}
/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
    /* project3 */
	int page_no = anon_page->swap_index;

    if (bitmap_test(swap_table, page_no) == false) {
        return false;
    }

    for (int i = 0; i < SECTORS_PER_PAGE; ++i) {
        disk_read(swap_disk, page_no * SECTORS_PER_PAGE + i, kva + DISK_SECTOR_SIZE * i);
    }
    bitmap_set(swap_table, page_no, false);
    return true;
    /* project3 */
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
  /* project3 */
  // lock_acquire(&bitmap_lock);
  int page_no = bitmap_scan(swap_table, 0, 1, false);
  // lock_release(&bitmap_lock);
  if (page_no == BITMAP_ERROR) {
      return false;
  }

  for (int i = 0; i < SECTORS_PER_PAGE; ++i) {
      disk_write(swap_disk, page_no * SECTORS_PER_PAGE + i, page->va + DISK_SECTOR_SIZE * i);
  }
  bitmap_set(swap_table, page_no, true);

  pml4_clear_page(thread_current()->pml4, page->va);
  anon_page->swap_index = page_no;
  if (!page->frame){
    page->frame->page = NULL;
    page->frame = NULL; //p3mtp need?
  }

	return true;
    /* project3 */
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {

    /* project3 */
    if(&page->frame != NULL)
		return;
  	// Swapped anon page case
  	struct anon_page *anon_page = &page->anon;

    /* project3 */
}
