#ifndef DEFINE_H_
#define DEFINE_H_

#include "autogensrc/funcType.h"
#include "autogensrc/funcIndex.h"

#define FUNC_TYPE(funcname) funcname ## _orig_type
#define __INVOKE_ORIG_FUNC(funcname) (FUNC_TYPE(funcname)(getOriginalFunction(FUNC_INDEX(funcname))))

#endif /* DEFINE_H_ */
