#include "axl_err_Error.h"

#if (_AXL_OS_WIN)
#	include <windows.h>
#	include <dbghelp.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

using namespace axl;
