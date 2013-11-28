#ifndef FUNCTYPE_H_
#define FUNCTYPE_H_

// auto generated header file
#define perror_orig_type (void (*)(const char *))
#define strerror_orig_type (char * (*)(int))
#define strerror_r_orig_type (char * (*)(int, char *, size_t))
#define error_orig_type (void (*)(int, int, const char *, ...))
#define mmap_orig_type (void * (*)(void *, size_t, int, int, int, off_t))
#define mmap64_orig_type (void * (*)(void *, size_t, int, int, int, off64_t))

#endif /* FUNCTYPE_H_ */
