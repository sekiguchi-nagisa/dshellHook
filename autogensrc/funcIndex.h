#ifndef FUNCINDEX_H_
#define FUNCINDEX_H_

// this is a stub file
#define FUNC_INDEX(funcname) funcname ## _orig_index

typedef enum {
	FUNC_INDEX(perror),
	FUNC_INDEX(strerror),
	FUNC_INDEX(strerror_r),
	FUNC_INDEX(error),
	func_index_size,
} FuncIndex;

#endif /* FUNCINDEX_H_ */
