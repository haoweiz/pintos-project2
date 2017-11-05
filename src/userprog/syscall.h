#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include <debug.h>
#include <list.h>

/* Process identifier. */
typedef int pid_t;
struct file_info{
  struct list_elem elem;
  struct file *file;
  int handle;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
