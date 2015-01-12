#include <cstdarg>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/capability.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <cstdarg>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <pthread.h>
#include <sys/capability.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <iostream>
using namespace std;


template <typename ... Varargs> FILE * _fopen(Varargs ... varargs);
template <typename ... Varargs> DIR * _opendir(Varargs ... varargs);
template <typename ... Varargs> int _nfct_query(Varargs ... varargs);
template <typename ... Varargs> int _nfct_callback_register(Varargs ... varargs);
template <typename ... Varargs> int _fseek(Varargs ... varargs);
template <typename ... Varargs> int _fclose(Varargs ... varargs);
template <typename ... Varargs> int _fputs(Varargs ... varargs);
template <typename ... Varargs> int _fputc(Varargs ... varargs);
template <typename ... Varargs> int _stat(Varargs ... varargs);
template <typename ... Varargs> int _system(Varargs ... varargs);
template <typename ... Varargs> int _nfq_unbind_pf(Varargs ... varargs);
template <typename ... Varargs> int _nfq_bind_pf(Varargs ... varargs);
template <typename ... Varargs> int _nfq_set_mode(Varargs ... varargs);
template <typename ... Varargs> int _nfq_set_queue_maxlen(Varargs ... varargs);
template <typename ... Varargs> struct nf_conntrack* _nfct_new(Varargs ... varargs);
template <typename ... Varargs> struct nfct_handle* _nfct_open(Varargs ... varargs);
template <typename ... Varargs> struct nfq_q_handle * _nfq_create_queue(Varargs ... varargs);
template <typename ... Varargs> struct nfq_handle * _nfq_open(Varargs ... varargs);
template <typename ... Varargs> int _fileno(Varargs ... varargs);
template <typename ... Varargs> int _pthread_mutex_lock(Varargs ... varargs);
template <typename ... Varargs> int _pthread_mutex_unlock(Varargs ... varargs);
template <typename ... Varargs> cap_t _cap_get_proc(Varargs ... varargs);
template <typename ... Varargs> int _cap_set_proc(Varargs ... varargs);
template <typename ... Varargs> int _cap_clear(Varargs ... varargs);
template <typename ... Varargs> int _cap_free(Varargs ... varargs);
template <typename ... Varargs> int _cap_set_flag(Varargs ... varargs);
template <typename ... Varargs> int _nfq_close(Varargs ... varargs);
template <typename ... Varargs> void * _malloc(Varargs ... varargs);
template <typename ... Varargs> int _closedir(Varargs ... varargs);
template <typename ... Varargs> int _pthread_cond_signal(Varargs ... varargs);
template <typename ... Varargs> int _open(Varargs ... varargs);
template <typename ... Varargs> off_t _lseek(Varargs ... varargs);
template <typename ... Varargs> ssize_t _read(Varargs ... varargs);
template <typename ... Varargs> int _remove(Varargs ... varargs);
template <typename ... Varargs> int _readlink(Varargs ... varargs);
template <typename ... Varargs> void * _mmap(Varargs ... varargs);
template <typename ... Varargs> int _pthread_create(Varargs ... varargs);
template <typename ... Varargs> int _close(Varargs ... varargs);
template <typename ... Varargs> int _munmap(Varargs ... varargs);


//This is a hack. Templates can be included by multiple source file without causing an error
template <typename string>
int die_syscall(string message){
  fprintf(stderr, "Error %d - %s\n", errno, strerror(errno));
  cout << message << "\n";
  cout << "Dumping a core file. Make sure to sudo chmod 0777 it to make it user-readable \n";
  abort(); //dump corefile - to get a decent backtrace via gcc
}


template <typename ... Varargs>
FILE * _fopen(Varargs ... varargs) {
  FILE *retval = fopen(varargs ...);
  if (retval == NULL){
    die_syscall("fopen returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
DIR * _opendir(Varargs ... varargs) {
  DIR *retval = opendir(varargs ...);
  if (retval == NULL){
    die_syscall ("opendir returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
int _nfct_query(Varargs ... varargs) {
  int retval = nfct_query(varargs ...);
  if (retval == -1){
    printf("nfct_query: %s,\n", strerror ( errno ));
    die_syscall ("nfct_query returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _nfct_callback_register(Varargs ... varargs) {
  int retval = nfct_callback_register(varargs ...);
  if (retval == -1){
    printf("nfct_callback_register: %s,\n", strerror ( errno ));
    die_syscall ("nfct_callback_register returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _fseek(Varargs ... varargs) {
  int retval = fseek(varargs ...);
  if (retval == -1){
    die_syscall ("fseek returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _fclose(Varargs ... varargs) {
  int retval = fclose(varargs ...);
  if (retval == -1){
    die_syscall ("fclose returned -1");
  }
  return retval;
}

//can be deleted
template <typename ... Varargs>
int _fputs(Varargs ... varargs) {
  int retval = fputs(varargs ...);
  if (retval == EOF){
    die_syscall ("fputs returned EOF");
  }
  return retval;
}


//can be deleted
template <typename ... Varargs>
int _fputc(Varargs ... varargs) {
  int retval = fputc(varargs ...);
  if (retval == EOF){
    die_syscall ("fputc returned EOF");
  }
  return retval;
}


template <typename ... Varargs>
int _stat(Varargs ... varargs) {
  int retval = stat(varargs ...);
  if (retval == -1){
    die_syscall ("stat returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _system(Varargs ... varargs) {
  int retval = system(varargs ...);
  if (retval == -1){
    die_syscall ("system returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _nfq_unbind_pf(Varargs ... varargs) {
  int retval = nfq_unbind_pf(varargs ...);
  if (retval != 0){
    die_syscall ("nfq_unbind_pf returned non 0");
  }
  return retval;
}


template <typename ... Varargs>
int _nfq_bind_pf(Varargs ... varargs) {
  int retval = nfq_bind_pf(varargs ...);
  if (retval < 0){
    die_syscall ("nfq_bind_pf returned < 0");
  }
  return retval;
}


template <typename ... Varargs>
int _nfq_set_mode(Varargs ... varargs) {
  int retval = nfq_set_mode(varargs ...);
  if (retval == -1){
    die_syscall ("nfq_set_mode returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _nfq_set_queue_maxlen(Varargs ... varargs) {
  int retval = nfq_set_queue_maxlen(varargs ...);
  if (retval == -1){
    die_syscall ("nfq_set_queue_maxlen returned -1");
  }
  return retval;
}


template <typename ... Varargs>
struct nf_conntrack* _nfct_new(Varargs ... varargs) {
  struct nf_conntrack* retval = nfct_new(varargs ...);
  if (retval == NULL){
    printf("nfct_new: %s,\n", strerror ( errno ));
    die_syscall ("nfct_new returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
struct nfct_handle* _nfct_open(Varargs ... varargs) {
  struct nfct_handle* retval = nfct_open(varargs ...);
  if (retval == NULL){
    printf("nfct_open: %s,\n", strerror ( errno ));
    die_syscall ("nfct_open returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
struct nfq_q_handle * _nfq_create_queue(Varargs ... varargs) {
  struct nfq_q_handle *retval = nfq_create_queue(varargs ...);
  if (retval == NULL){
    die_syscall ("nfq_create_queue returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
struct nfq_handle * _nfq_open(Varargs ... varargs) {
  struct nfq_handle *retval = nfq_open(varargs ...);
  if (retval == NULL){
    die_syscall ("nfq_open returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
int _fileno(Varargs ... varargs) {
  int retval = fileno(varargs ...);
  if (retval == -1){
    die_syscall ("fileno returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _pthread_mutex_lock(Varargs ... varargs) {
  int retval = pthread_mutex_lock(varargs ...);
  if (retval != 0){
    die_syscall ("pthread_mutex_lock returned non 0");
  }
  return retval;
}


template <typename ... Varargs>
int _pthread_mutex_unlock(Varargs ... varargs) {
  int retval = pthread_mutex_unlock(varargs ...);
  if (retval != 0){
    die_syscall ("pthread_mutex_unlock returned non 0");
  }
  return retval;
}


template <typename ... Varargs>
cap_t _cap_get_proc(Varargs ... varargs) {
  cap_t retval = cap_get_proc(varargs ...);
  if (retval == NULL){
    die_syscall ("cap_get_proc returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
int _cap_set_proc(Varargs ... varargs) {
  int retval = cap_set_proc(varargs ...);
  if (retval == -1){
    die_syscall ("cap_set_proc returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _cap_clear(Varargs ... varargs) {
  int retval = cap_clear(varargs ...);
  if (retval == -1){
    die_syscall ("cap_clear returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _cap_free(Varargs ... varargs) {
  int retval = cap_free(varargs ...);
  if (retval == -1){
    die_syscall ("cap_free returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _cap_set_flag(Varargs ... varargs) {
  int retval = cap_set_flag(varargs ...);
  if (retval == -1){
    die_syscall ("cap_set_flag returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _nfq_close(Varargs ... varargs) {
  int retval = nfq_close(varargs ...);
  if (retval != 0){
    die_syscall ("nfq_close returned non 0");
  }
  return retval;
}


template <typename ... Varargs>
void * _malloc(Varargs ... varargs) {
  void * retval = malloc(varargs ...);
  if (retval == NULL){
    die_syscall ("malloc returned NULL");
  }
  return retval;
}


template <typename ... Varargs>
int _closedir(Varargs ... varargs) {
  int retval = closedir(varargs ...);
  if (retval == -1){
    die_syscall ("closedir returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _pthread_cond_signal(Varargs ... varargs) {
  int retval = pthread_cond_signal(varargs ...);
  if (retval == -1){
    die_syscall ("pthread_cond_signal returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _open(Varargs ... varargs) {
  int retval = open(varargs ...);
  if (retval == -1){
    die_syscall ("open returned -1");
  }
  return retval;
}


template <typename ... Varargs>
off_t _lseek(Varargs ... varargs) {
  off_t retval = lseek(varargs ...);
  if ((off_t)retval == -1){
    die_syscall ("lseek returned -1");
  }
  return retval;
}


template <typename ... Varargs>
ssize_t _read(Varargs ... varargs) {
  ssize_t retval = read(varargs ...);
  if (int(retval) == -1){
    die_syscall ("read returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _remove(Varargs ... varargs) {
  int retval = remove(varargs ...);
  if (int(retval) == -1){
    die_syscall ("remove returned -1");
  }
  return retval;
}


template <typename ... Varargs>
int _readlink(Varargs ... varargs) {
  int retval = readlink(varargs ...);
  if (retval == -1){
    die_syscall ("readlink returned -1");
  }
  return retval;
}


template <typename ... Varargs>
void * _mmap(Varargs ... varargs) {
  void * retval = mmap(varargs ...);
  if (retval == MAP_FAILED){
    die_syscall ("mmap returned MAP_FAILED");
  }
  return retval;
}


template <typename ... Varargs>
int _pthread_create(Varargs ... varargs) {
  int retval = pthread_create(varargs ...);
  if (retval != 0){
    die_syscall ("pthread_create returned non 0");
  }
  return retval;
}


template <typename ... Varargs>
int _close(Varargs ... varargs) {
  int retval = close(varargs ...);
  if (retval != 0){
    die_syscall ("close returned non 0");
  }
  return retval;
}


template <typename ... Varargs>
int _munmap(Varargs ... varargs) {
  int retval = munmap(varargs ...);
  if (retval != 0){
    die_syscall ("munmap returned non 0");
  }
  return retval;
}

