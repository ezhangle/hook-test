﻿#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <dbghelp.h>
#include <assert.h>

#define ASSERT assert
// #define _PRINT_UNWIND_INFO 0

//..............................................................................

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME  10

union UNWIND_CODE {
	struct {
	UCHAR OffsetInPrologue;
	UCHAR UnwindCode    : 4;
	UCHAR OperationInfo : 4;
	};
	USHORT AllocLargeInfo;
};

struct UNWIND_INFO {
    UCHAR Version       : 3;
    UCHAR Flags         : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset   : 4;
    UNWIND_CODE UnwindCode[3];

    union {
        //
        // If (Flags & UNW_FLAG_EHANDLER)
        //
		struct
		{
			OPTIONAL ULONG ExceptionHandler;
		    OPTIONAL ULONG ExceptionData[1];
		};

		//
        // Else if (Flags & UNW_FLAG_CHAININFO)
        //
		RUNTIME_FUNCTION ChainUnwindRuntimeFunction;
    };
};

const char* getUnwindCodeString(UCHAR code)
{
	static const char* stringTable[] =
	{
		"UWOP_PUSH_NONVOL",     // 0
		"UWOP_ALLOC_LARGE",     // 1
		"UWOP_ALLOC_SMALL",     // 2
		"UWOP_SET_FPREG",       // 3
		"UWOP_SAVE_NONVOL",     // 4
		"UWOP_SAVE_NONVOL_FAR", // 5
		"<UNUSED>",             // 6
		"<UNUSED>",             // 7
		"UWOP_SAVE_XMM128",     // 8
		"UWOP_SAVE_XMM128_FAR", // 9
		"UWOP_PUSH_MACHFRAME",  // 10
	};

	return code < _countof(stringTable) ? stringTable[code] : "<UNDEFINED>";
}

void printUnwindInfo(uint64_t rip)
{
	DWORD64 base = SymGetModuleBase64(INVALID_HANDLE_VALUE, rip);
	RUNTIME_FUNCTION* func = (RUNTIME_FUNCTION*)SymFunctionTableAccess64(INVALID_HANDLE_VALUE, rip);
	UNWIND_INFO* unwind = (UNWIND_INFO*) (base + func->UnwindInfoAddress);

	printf(
		"RIP: %zu\n"
		"RUNTIME_FUNCTION.BeginAddress: 0x%08x (0x%016llx)\n"
		"RUNTIME_FUNCTION.EndAddress:   0x%08x (0x%016llx)\n"
		"UNWIND_INFO.Version:           0x%08x\n"
		"UNWIND_INFO.Flags:             0x%08x\n"
		"UNWIND_INFO.SizeOfProlog:      %d\n"
		"UNWIND_INFO.FrameRegister:     %d\n"
		"UNWIND_INFO.FrameOffset:       0x%02x\n"
		"UNWIND_INFO.CountOfCodes:      %d\n",
		rip,
		func->BeginAddress,
		base + func->BeginAddress,
		func->EndAddress,
		base + func->EndAddress,
		unwind->Version,
		unwind->Flags,
		unwind->SizeOfProlog,
		unwind->FrameRegister,
		unwind->FrameOffset,
		unwind->CountOfCodes
		);

	for (UINT i = 0; i < unwind->CountOfCodes; i++)
	{
		printf(
			"  UNWIND_CODE[%d]:\n"
			"    OffsetInPrologue: %d\n"
			"    UnwindCode:       0x%02x (%s)\n"
			"    OperationInfo:    0x%02x\n",
			i,
			unwind->UnwindCode[i].OffsetInPrologue,
			unwind->UnwindCode[i].UnwindCode,
			getUnwindCodeString(unwind->UnwindCode[i].UnwindCode),
			unwind->UnwindCode[i].OperationInfo
			);
	}

	if (unwind->Flags & UNW_FLAG_EHANDLER)
	{
		printf("  UNWIND_");
	}
}

RUNTIME_FUNCTION*
getRuntimeFunction(
    uint64_t address,
    void* context
    )
{
	printf("getRuntimeFunction(%016zx)\n", address);
	return (RUNTIME_FUNCTION*)context;
}

inline
uint8_t
getUnwindAllocSmallOpInfo(uint8_t size)
{
	ASSERT(size >= 8 && size <= 128 && (size & 0x7) == 0);
	return (size - 8) / 8;
}

inline
uint16_t
getUnwindAllocLargeInfo(uint32_t size)
{
	ASSERT(size >= 136 && size <= 0x7fff8);
	return size / 8;
}

//..............................................................................

//..............................................................................

#pragma pack(push, 1)

union JmpThunkCode
{
	enum
	{
		StackFrameSize = 8 + 4 * 8 + 4 * 16, // padding + 4 gp regs + 4 xmm regs
	};

	uint8_t m_code[0xd7];

	struct
	{
		uint8_t m_offset1[0x31];
		uint64_t m_targetFunc1;
	};

	struct
	{
		uint8_t m_offset2[0x42];
		uint64_t m_hookEnterFunc;
	};

	struct
	{
		uint8_t m_offset3[0x7f];
		uint64_t m_hookRet;
	};

	struct
	{
		uint8_t m_offset4[0x8d];
		uint64_t m_targetFunc2;
	};

	struct
	{
		uint8_t m_offset5[0xac];
		uint64_t m_targetFunc3;
	};

	struct
	{
		uint8_t m_offset6[0xbc];
		uint64_t m_hookLeaveFunc;
	};
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

// nasm -f win64 -l thunk.asm.lst thunk.asm

JmpThunkCode g_jmpThunkCodeTemplate =
{{
	/* 00000000 */ 0x55,                                            // push    rbp
	/* 00000001 */ 0x48, 0x89, 0xE5,                                // mov     rbp, rsp
	/* 00000004 */ 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00,        // sub     rsp, STACK_FRAME_SIZE
	/* 0000000B */ 0x48, 0x89, 0x4D, 0xF0,                          // mov     [rbp - 16 - 8 * 0], rcx
	/* 0000000F */ 0x48, 0x89, 0x55, 0xE8,                          // mov     [rbp - 16 - 8 * 1], rdx
	/* 00000013 */ 0x4C, 0x89, 0x45, 0xE0,                          // mov     [rbp - 16 - 8 * 2], r8
	/* 00000017 */ 0x4C, 0x89, 0x4D, 0xD8,                          // mov     [rbp - 16 - 8 * 3], r9
	/* 0000001B */ 0x66, 0x0F, 0x7F, 0x45, 0xD0,                    // movdqa  [rbp - 16 - 8 * 4 - 16 * 0], xmm0
	/* 00000020 */ 0x66, 0x0F, 0x7F, 0x4D, 0xC0,                    // movdqa  [rbp - 16 - 8 * 4 - 16 * 1], xmm1
	/* 00000025 */ 0x66, 0x0F, 0x7F, 0x55, 0xB0,                    // movdqa  [rbp - 16 - 8 * 4 - 16 * 2], xmm2
	/* 0000002A */ 0x66, 0x0F, 0x7F, 0x5D, 0xA0,                    // movdqa  [rbp - 16 - 8 * 4 - 16 * 3], xmm3
	/* 0000002F */ 0x48, 0xB9,                                      // mov     rcx, targetFunc
	/* 00000031 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 00000039 */ 0x48, 0x89, 0xEA,                                // mov     rdx, rbp
	/* 0000003C */ 0x4C, 0x8B, 0x45, 0x08,                          // mov     r8, [rbp + 8]
	/* 00000040 */ 0x48, 0xB8,                                      // mov     rax, hookEnterFunc
	/* 00000042 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0000004A */ 0xFF, 0xD0,                                      // call    rax
	/* 0000004C */ 0x48, 0x8B, 0x4D, 0xF0,                          // mov     rcx,  [rbp - 16 - 8 * 0]
	/* 00000050 */ 0x48, 0x8B, 0x55, 0xE8,                          // mov     rdx,  [rbp - 16 - 8 * 1]
	/* 00000054 */ 0x4C, 0x8B, 0x45, 0xE0,                          // mov     r8,   [rbp - 16 - 8 * 2]
	/* 00000058 */ 0x4C, 0x8B, 0x4D, 0xD8,                          // mov     r9,   [rbp - 16 - 8 * 3]
	/* 0000005C */ 0x66, 0x0F, 0x6F, 0x45, 0xD0,                    // movdqa  xmm0, [rbp - 16 - 8 * 4 - 16 * 0]
	/* 00000061 */ 0x66, 0x0F, 0x6F, 0x4D, 0xC0,                    // movdqa  xmm1, [rbp - 16 - 8 * 4 - 16 * 1]
	/* 00000066 */ 0x66, 0x0F, 0x6F, 0x55, 0xB0,                    // movdqa  xmm2, [rbp - 16 - 8 * 4 - 16 * 2]
	/* 0000006B */ 0x66, 0x0F, 0x6F, 0x5D, 0xA0,                    // movdqa  xmm3, [rbp - 16 - 8 * 4 - 16 * 3]
	/* 00000070 */ 0x66, 0x0F, 0x6F, 0x5D, 0xA0,                    // movdqa  xmm3, [rbp - 16 - 8 * 4 - 16 * 3]
	/* 00000075 */ 0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00,        // add     rsp, STACK_FRAME_SIZE
	/* 0000007C */ 0x5D,                                            // pop     rbp
	/* 0000007D */ 0x48, 0xB8,                                      // mov     rax, hookRet
	/* 0000007F */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 00000087 */ 0x48, 0x89, 0x04, 0x24,                          // mov     [rsp], rax
	/* 0000008B */ 0x48, 0xB8,                                      // mov     rax, targetFunc
	/* 0000008D */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 00000095 */ 0xFF, 0xE0,                                      // jmp     rax
	/* 00000097 */ 0x48, 0x83, 0xEC, 0x08,                          // sub     rsp, 8                 ; <<< hookThunkRet
	/* 0000009B */ 0x55,                                            // push    rbp
	/* 0000009C */ 0x48, 0x89, 0xE5,                                // mov     rbp, rsp
	/* 0000009F */ 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00,        // sub     rsp, STACK_FRAME_SIZE
	/* 000000A6 */ 0x48, 0x89, 0x45, 0xF8,                          // mov     [rbp - 8], rax
	/* 000000AA */ 0x48, 0xB9,                                      // mov     rcx, targetFunc
	/* 000000AC */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 000000B4 */ 0x48, 0x89, 0xEA,                                // mov     rdx, rbp
	/* 000000B7 */ 0x49, 0x89, 0xC0,                                // mov     r8, rax
	/* 000000BA */ 0x48, 0xB8,                                      // mov     rax, hookLeaveFunc
	/* 000000BC */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 000000C4 */ 0xFF, 0xD0,                                      // call    rax
	/* 000000C6 */ 0x48, 0x89, 0x45, 0x08,                          // mov     [rbp + 8], rax
	/* 000000CA */ 0x48, 0x8B, 0x45, 0xF8,                          // mov     rax, [rbp - 8]
	/* 000000CE */ 0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00,        // add     rsp, STACK_FRAME_SIZE
	/* 000000D5 */ 0x5D,                                            // pop     rbp
	/* 000000D6 */ 0xC3,                                            // ret
}};

#pragma pack(pop)

struct JmpThunk
{
	JmpThunkCode m_code;
	RUNTIME_FUNCTION m_runtimeFunction;
	UNWIND_INFO m_unwindInfo;
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

void* g_originalRet;

void hookEnter(
	void* func,
	void* rbp,
	void* originalRet
	)
{
	printf("hookEnter(func: %p, rbp: %p, [rsp]: %p)\n", func, rbp, originalRet);
	g_originalRet = originalRet;
}

void* hookLeave(
	void* id,
	void* rbp,
	void* rax
	)
{
	printf("hookLeave(func: %p, rbp: %p, rax: %lld / 0x%p)\n", id, rbp, (uint64_t)rax, rax);
	return g_originalRet;
}

JmpThunk*
createJmpThunk(void* targetFunc)
{
	JmpThunk* thunk = (JmpThunk*)::VirtualAlloc(
		NULL,
		sizeof(JmpThunk),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);

	thunk->m_code = g_jmpThunkCodeTemplate;
	thunk->m_code.m_targetFunc1 = (uint64_t)targetFunc;
	thunk->m_code.m_targetFunc2 = (uint64_t)targetFunc;
	thunk->m_code.m_targetFunc3 = (uint64_t)targetFunc;
	thunk->m_code.m_hookRet = (uint64_t)((char*)thunk + 0x97);
	thunk->m_code.m_hookEnterFunc = (uint64_t)hookEnter;
	thunk->m_code.m_hookLeaveFunc = (uint64_t)hookLeave;

	thunk->m_runtimeFunction.BeginAddress = 0;
	thunk->m_runtimeFunction.EndAddress = sizeof(JmpThunkCode);
	thunk->m_runtimeFunction.UnwindInfoAddress = (DWORD)((char*)&thunk->m_unwindInfo - (char*)thunk);

	thunk->m_unwindInfo.Version = 1;
	thunk->m_unwindInfo.Flags = 0;
	thunk->m_unwindInfo.SizeOfProlog = 0x4;
	thunk->m_unwindInfo.FrameRegister = 0;
	thunk->m_unwindInfo.FrameOffset = 0;
	thunk->m_unwindInfo.CountOfCodes = 1;

	thunk->m_unwindInfo.UnwindCode[0].UnwindCode = UWOP_ALLOC_SMALL;
	thunk->m_unwindInfo.UnwindCode[0].OffsetInPrologue = 0x4;
	thunk->m_unwindInfo.UnwindCode[0].OperationInfo = getUnwindAllocSmallOpInfo(JmpThunkCode::StackFrameSize);

	uint64_t base = (uint64_t)thunk;

	RtlAddFunctionTable(&thunk->m_runtimeFunction, 1, base);
	return thunk;
}

//..............................................................................

// uses up all register arguments and spills to stack

typedef int FooFunc(int, double, int, double, int, double, int, double, int, double);

int bar(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("bar(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);
	int* p = NULL;
//	*p = 10;
	return 456;
}

int foo(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("foo(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);
	return bar(a, b, c, d, e, f, g, h, i, j);
}

static CONTEXT g_context = { 0 }; // global so it doesn't affect function

int test(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("test(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);

#if (_PRINT_UNWIND_INFO)
	g_context.ContextFlags = CONTEXT_CONTROL;
	RtlCaptureContext(&g_context);
	printUnwindInfo(g_context.Rip);
#endif

	int result;

	JmpThunk* jmpThunk = createJmpThunk(foo);
	result = ((FooFunc*)&jmpThunk->m_code)(a, b, c, d, e, f, g, h, i, j);
	printf("jmpThunk -> %d\n", result);
	return result;
}

//..............................................................................

int main()
{
	BOOL result = SymInitialize(INVALID_HANDLE_VALUE, NULL, true);

	__try
	{
		g_context.ContextFlags = CONTEXT_CONTROL;
		RtlCaptureContext(&g_context);
		printUnwindInfo(g_context.Rip);

		test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
	}
	__except(1)
	{
		printf("exception caught in main()\n");
	}

	return 0;
}

//..............................................................................