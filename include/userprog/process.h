#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* project3 */
#include "filesys/off_t.h"
#include <stdbool.h>
/* project3 */

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
void argument_stack_for_user(char ** argv, int argc, struct intr_frame *if_); /* project2 */
struct thread* thread_child(int); /* project2 - put tid and return child thread ptr */

/* project3 */
bool install_page (void *upage, void *kpage, bool writable);
bool lazy_load_segment (struct page *page, void *aux);
struct file *process_get_file(int fd);

struct container {
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};
/* project3 */


#endif /* userprog/process.h */
