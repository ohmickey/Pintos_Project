/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

//project3
#include "userprog/process.h"


static struct list frame_table;
static struct list_elem* start;


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
    //project3
    list_init(&frame_table);
    start = list_begin(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
  /*project 3*/
  struct page* page = (struct page*)malloc(sizeof(struct page)); //tmp

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

    /*project 3*/
		// struct page* page = (struct page*)malloc(sizeof(struct page));

    typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
    initializerFunc initializer = NULL;

    switch(VM_TYPE(type)) {
        case VM_ANON:
            initializer = anon_initializer;
            break;
        case VM_FILE:
            initializer = file_backed_initializer;
            break;
		}

    uninit_new(page, upage, init, type, aux, initializer);
    page->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
    /*project 3*/
	}
  free(page);
  free(aux);
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */

    /*project 3*/
  struct hash_elem *e;
  struct page page;
  page.va = pg_round_down(va);
  e = hash_find(&spt->pages, &page.hash_elem);
  if (!e) return NULL;

  return hash_entry (e, struct page, hash_elem);
  /*project 3*/
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* TODO: Fill this function. */
  /*project 3*/
  return insert_page(&spt->pages, page);
  /*project 3*/
}

// void
// spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
// 	vm_dealloc_page (page);
// 	return true;
// }

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
    /*project 3*/
    struct thread *curr = thread_current();
    struct list_elem *e = start;

    //clock 알고리즘
    for (start = e; start != list_end(&frame_table); start = list_next(start)) {
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed (curr->pml4, victim->page->va, 0);
        else
            return victim;
    }

    for (start = list_begin(&frame_table); start != e; start = list_next(start)) {
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed (curr->pml4, victim->page->va, 0);
        else
            return victim;
    }
    /*project 3*/
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
  /*project 3*/
  swap_out(victim->page);
  /*project 3*/
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	// /* TODO: Fill this function. */

    /* project3 */
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));

	frame->kva = palloc_get_page(PAL_USER);
  if(frame->kva == NULL) { //할당할 frame이 가득찬 상태
    free(frame); //tmp
    frame = vm_evict_frame();
    frame->page = NULL;
    return frame;
  }
  list_push_back (&frame_table, &frame->frame_elem);
  frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;

  /* project3 */
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
  /* project3 */
  if(vm_alloc_page(VM_ANON | VM_MARKER_0, addr, 1)) {
      vm_claim_page(addr);
      thread_current()->stack_bottom -= PGSIZE;
  }
  /* project3 */
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
  /* project3 */
  return false;
  /* project3 */
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

  /* project3 */

  if (is_kernel_vaddr (addr) && user) return false;

  void *rsp_stack = is_kernel_vaddr(f->rsp) ? thread_current()->rsp_stack : f->rsp; // f->rsp 가 커널스페이스의 주소라면
  if (not_present){
    if (!vm_claim_page(addr)) {
      if (rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr && addr <= USER_STACK) { //1MB까지만
        vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
        return true;
      }
      return false;
    }
    else
      return true;
  }
  /* project3 */
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function */

  /* project3 */
  struct page *page = spt_find_page (&thread_current()->spt, va);
	if (page == NULL) return false;
  /* project3 */

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

  /* project3 */
	if (install_page(page->va, frame->kva, page->writable)) {
    return swap_in(page, frame->kva);
  }
  /* project3 */

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	return false;
}


/* project3 */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry (p_, struct page, hash_elem);
    return hash_bytes (&p->va, sizeof p->va);
}

bool
page_less (const struct hash_elem *a_,
            const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}
/* project3 */


/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
    /* project3 */
    hash_init(&spt->pages, page_hash, page_less, NULL);
    /* project3 */
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
    /* project3 */
    struct hash_iterator i;
    hash_first (&i, &src->pages);
    while (hash_next (&i)) {
        struct page *parent_page = hash_entry (hash_cur (&i), struct page, hash_elem);
        enum vm_type type = page_get_type(parent_page);
        void *upage = parent_page->va;
        bool writable = parent_page->writable;
        vm_initializer *init = parent_page->uninit.init;
        void* aux = parent_page->uninit.aux;

        if(parent_page->operations->type == VM_UNINIT) {
            if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux))
                return false;
        }
        else {
            if(!vm_alloc_page(type, upage, writable))
                return false;
            if(!vm_claim_page(upage))
                return false;
        }

        if (parent_page->operations->type != VM_UNINIT) {
            struct page* child_page = spt_find_page(dst, upage);
            memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
        }
    }
    return true;
}
/* project3 */


/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

    /* project3 */
	struct hash_iterator i;

  hash_first (&i, &spt->pages);
  while (hash_next (&i)) {
    struct page *page = hash_entry (hash_cur (&i), struct page, hash_elem);

    if (page->operations->type == VM_FILE) {
      do_munmap(page->va);
    }
  }
  hash_destroy(&spt->pages, spt_destructor);
  /* project3 */
}
    /* project3 */
bool insert_page(struct hash *pages, struct page *p) {
    if (!hash_insert(pages, &p->hash_elem))
      return true;
    else{
      free(p);
      return false;
    }
}

bool delete_page(struct hash *pages, struct page *p) {
    if (!hash_delete(pages, &p->hash_elem))
        return true;
    else
        return false;
}

void spt_destructor(struct hash_elem *e, void* aux) {
    const struct page *p = hash_entry(e, struct page, hash_elem);
    free(p);
}
    /* project3 */
