#include "pch.h"

#if (_AXL_OS_WIN)

//..............................................................................

// #define _PRINT_UNWIND_INFO 0

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

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

	/*

    OPTIONAL union {
        //
        // If (Flags & UNW_FLAG_EHANDLER)
        //
		struct
		{
			ULONG ExceptionHandler;
			ULONG ExceptionData[1];
		};

		//
        // Else if (Flags & UNW_FLAG_CHAININFO)
        //
		RUNTIME_FUNCTION ChainUnwindRuntimeFunction;
    };

	*/
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
		"RIP: 0x%016llx\n"
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

	const UNWIND_CODE* unwindCode = (UNWIND_CODE*)(unwind + 1);

	for (UINT i = 0; i < unwind->CountOfCodes; i++, unwindCode++)
	{
		printf(
			"  UNWIND_CODE[%d]:\n"
			"    OffsetInPrologue: %d\n"
			"    UnwindCode:       0x%02x (%s)\n"
			"    OperationInfo:    0x%02x\n",
			i,
			unwindCode->OffsetInPrologue,
			unwindCode->UnwindCode,
			getUnwindCodeString(unwindCode->UnwindCode),
			unwindCode->OperationInfo
			);
	}

	const void* extra = unwindCode;

	if (unwind->Flags & UNW_FLAG_EHANDLER)
	{
		ULONG ExceptionHandler = *(ULONG*)extra;

		printf(
			"UNWIND_INFO.ExceptionHandler: 0x%08x (0x%016llx)\n",
			ExceptionHandler,
			base + ExceptionHandler
			);
	}
	else if (unwind->Flags & UNW_FLAG_CHAININFO)
	{
		RUNTIME_FUNCTION* chainFunc = (RUNTIME_FUNCTION*)extra;

		printf(
			"UNWIND_INFO.ChainUnwindRuntimeFunction.BeginAddress: 0x%08x (0x%016llx)\n"
			"UNWIND_INFO.ChainUnwindRuntimeFunction.EndAddress:   0x%08x (0x%016llx)\n",
			chainFunc->BeginAddress,
			base + chainFunc->BeginAddress,
			chainFunc->EndAddress,
			base + chainFunc->EndAddress
			);
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

#endif

//..............................................................................

#if (_AXL_OS_WIN)

#pragma pack(push, 1)

union JmpThunkCode
{
	enum
	{
		StackFrameSize = 8 + 4 * 8 + 4 * 16, // padding + 4 gp regs + 4 xmm regs
	};

	uint8_t m_code[0xea];

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
		uint8_t m_offset3[0x7a];
		uint64_t m_hookRet;
	};

	struct
	{
		uint8_t m_offset4[0x88];
		uint64_t m_targetFunc2;
	};

	uint8_t m_hookRetOffset[0x92];

	struct
	{
		uint8_t m_offset5[0xa7];
		uint64_t m_targetFunc3;
	};

	struct
	{
		uint8_t m_offset6[0xb7];
		uint64_t m_hookLeaveFunc;
	};

	uint8_t m_hookSehHandlerOffset[0xd2];

	struct
	{
		uint8_t m_offset7[0xd5];
		uint64_t m_hookExceptionFunc;
	};
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

// nasm -f win64 -l thunk_win_amd64.asm.lst thunk_win_amd64.asm

JmpThunkCode g_jmpThunkCodeTemplate =
{{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x4D, 0xF0,                          // 0000000B  mov     [rbp - 16 - 8 * 0], rcx
	0x48, 0x89, 0x55, 0xE8,                          // 0000000F  mov     [rbp - 16 - 8 * 1], rdx
	0x4C, 0x89, 0x45, 0xE0,                          // 00000013  mov     [rbp - 16 - 8 * 2], r8
	0x4C, 0x89, 0x4D, 0xD8,                          // 00000017  mov     [rbp - 16 - 8 * 3], r9
	0x66, 0x0F, 0x7F, 0x45, 0xD0,                    // 0000001B  movdqa  [rbp - 16 - 8 * 4 - 16 * 0], xmm0
	0x66, 0x0F, 0x7F, 0x4D, 0xC0,                    // 00000020  movdqa  [rbp - 16 - 8 * 4 - 16 * 1], xmm1
	0x66, 0x0F, 0x7F, 0x55, 0xB0,                    // 00000025  movdqa  [rbp - 16 - 8 * 4 - 16 * 2], xmm2
	0x66, 0x0F, 0x7F, 0x5D, 0xA0,                    // 0000002A  movdqa  [rbp - 16 - 8 * 4 - 16 * 3], xmm3
	0x48, 0xB9,                                      // 0000002F  mov     rcx, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000031
	0x48, 0x89, 0xEA,                                // 00000039  mov     rdx, rbp
	0x4C, 0x8B, 0x45, 0x08,                          // 0000003C  mov     r8, [rbp + 8]
	0x48, 0xB8,                                      // 00000040  mov     rax, hookEnterFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000042
	0xFF, 0xD0,                                      // 0000004A  call    rax
	0x48, 0x8B, 0x4D, 0xF0,                          // 0000004C  mov     rcx,  [rbp - 16 - 8 * 0]
	0x48, 0x8B, 0x55, 0xE8,                          // 00000050  mov     rdx,  [rbp - 16 - 8 * 1]
	0x4C, 0x8B, 0x45, 0xE0,                          // 00000054  mov     r8,   [rbp - 16 - 8 * 2]
	0x4C, 0x8B, 0x4D, 0xD8,                          // 00000058  mov     r9,   [rbp - 16 - 8 * 3]
	0x66, 0x0F, 0x6F, 0x45, 0xD0,                    // 0000005C  movdqa  xmm0, [rbp - 16 - 8 * 4 - 16 * 0]
	0x66, 0x0F, 0x6F, 0x4D, 0xC0,                    // 00000061  movdqa  xmm1, [rbp - 16 - 8 * 4 - 16 * 1]
	0x66, 0x0F, 0x6F, 0x55, 0xB0,                    // 00000066  movdqa  xmm2, [rbp - 16 - 8 * 4 - 16 * 2]
	0x66, 0x0F, 0x6F, 0x5D, 0xA0,                    // 0000006B  movdqa  xmm3, [rbp - 16 - 8 * 4 - 16 * 3]
	0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00,        // 00000070  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 00000077  pop     rbp
	0x48, 0xB8,                                      // 00000078  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0000007A
	0x48, 0x89, 0x04, 0x24,                          // 00000082  mov     [rsp], rax
	0x48, 0xB8,                                      // 00000086  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000088
	0xFF, 0xE0,                                      // 00000090  jmp     rax
	0x48, 0x83, 0xEC, 0x08,                          // 00000092  sub     rsp, 8  ; <<< hook_ret
	0x55,                                            // 00000096  push    rbp
	0x48, 0x89, 0xE5,                                // 00000097  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00,        // 0000009A  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x45, 0xF8,                          // 000000A1  mov     [rbp - 8], rax
	0x48, 0xB9,                                      // 000000A5  mov     rcx, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000A7
	0x48, 0x89, 0xEA,                                // 000000AF  mov     rdx, rbp
	0x49, 0x89, 0xC0,                                // 000000B2  mov     r8, rax
	0x48, 0xB8,                                      // 000000B5  mov     rax, hookLeaveFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000B7
	0xFF, 0xD0,                                      // 000000BF  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 000000C1  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0xF8,                          // 000000C5  mov     rax, [rbp - 8]
	0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00,        // 000000C9  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 000000D0  pop     rbp
	0xC3,                                            // 000000D1  ret
	0x52,                                            // 000000D2  push    rdx  ; <<< seh_handler
	0x48, 0xB8,                                      // 000000D3  mov     rax, hookExceptionFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000D5
	0xFF, 0xD0,                                      // 000000DD  call    rax
	0x5A,                                            // 000000DF  pop     rdx
	0x48, 0x89, 0x42, 0xF8,                          // 000000E0  mov     [rdx - 16 + 8], rax
	0xB8, 0x00, 0x00, 0x00, 0x00,                    // 000000E4  mov     rax, 0
	0xC3,                                            // 000000E9  ret
}};

#pragma pack(pop)

struct JmpThunk
{
	JmpThunkCode m_code;
#if (_AXL_OS_WIN)
	RUNTIME_FUNCTION m_runtimeFunction;
	UNWIND_INFO m_unwindInfo;
	ULONG m_exceptionHandler;
#endif
};

//..............................................................................

#else

#pragma pack(push, 1)

union JmpThunkCode
{
	enum
	{
		StackFrameSize = 8 + 6 * 8 + 8 * 16, // padding + 6 gp regs + 8 xmm regs
	};

	uint8_t m_code[0x11c];

	struct
	{
		uint8_t m_offset1[0x56];
		uint64_t m_targetFunc1;
	};

	struct
	{
		uint8_t m_offset2[0x67];
		uint64_t m_hookEnterFunc;
	};

	struct
	{
		uint8_t m_offset3[0xc4];
		uint64_t m_hookRet;
	};

	struct
	{
		uint8_t m_offset4[0xd2];
		uint64_t m_targetFunc2;
	};

	struct
	{
		uint8_t m_hookRetOffset[0xdc];
	};

	struct
	{
		uint8_t m_offset5[0xf1];
		uint64_t m_targetFunc3;
	};

	struct
	{
		uint8_t m_offset6[0x101];
		uint64_t m_hookLeaveFunc;
	};
};

// nasm -f elf64 -l thunk_systemv_amd64.asm.lst thunk_systemv_amd64.asm

JmpThunkCode g_jmpThunkCodeTemplate =
{{
	0x55,                                            // 00000000  push    rbp
	0x48, 0x89, 0xE5,                                // 00000001  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,        // 00000004  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x7D, 0xF0,                          // 0000000B  mov     [rbp - 16 - 8 * 0], rdi
	0x48, 0x89, 0x75, 0xE8,                          // 0000000F  mov     [rbp - 16 - 8 * 1], rsi
	0x48, 0x89, 0x55, 0xE0,                          // 00000013  mov     [rbp - 16 - 8 * 2], rdx
	0x48, 0x89, 0x4D, 0xD8,                          // 00000017  mov     [rbp - 16 - 8 * 3], rcx
	0x4C, 0x89, 0x45, 0xD0,                          // 0000001B  mov     [rbp - 16 - 8 * 4], r8
	0x4C, 0x89, 0x4D, 0xC8,                          // 0000001F  mov     [rbp - 16 - 8 * 5], r9
	0x66, 0x0F, 0x7F, 0x45, 0xC0,                    // 00000023  movdqa  [rbp - 16 - 8 * 6 - 16 * 0], xmm0
	0x66, 0x0F, 0x7F, 0x4D, 0xB0,                    // 00000028  movdqa  [rbp - 16 - 8 * 6 - 16 * 1], xmm1
	0x66, 0x0F, 0x7F, 0x55, 0xA0,                    // 0000002D  movdqa  [rbp - 16 - 8 * 6 - 16 * 2], xmm2
	0x66, 0x0F, 0x7F, 0x5D, 0x90,                    // 00000032  movdqa  [rbp - 16 - 8 * 6 - 16 * 3], xmm3
	0x66, 0x0F, 0x7F, 0x65, 0x80,                    // 00000037  movdqa  [rbp - 16 - 8 * 6 - 16 * 4], xmm4
	0x66, 0x0F, 0x7F, 0xAD, 0x70, 0xFF, 0xFF, 0xFF,  // 0000003C  movdqa  [rbp - 16 - 8 * 6 - 16 * 5], xmm5
	0x66, 0x0F, 0x7F, 0xB5, 0x60, 0xFF, 0xFF, 0xFF,  // 00000044  movdqa  [rbp - 16 - 8 * 6 - 16 * 6], xmm6
	0x66, 0x0F, 0x7F, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,  // 0000004C  movdqa  [rbp - 16 - 8 * 6 - 16 * 7], xmm7
	0x48, 0xBF,                                      // 00000054  mov     rdi, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000056
	0x48, 0x89, 0xEE,                                // 0000005E  mov     rsi, rbp
	0x48, 0x8B, 0x55, 0x08,                          // 00000061  mov     rdx, [rbp + 8]
	0x48, 0xB8,                                      // 00000065  mov     rax, hookEnterFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000067
	0xFF, 0xD0,                                      // 0000006F  call    rax
	0x48, 0x8B, 0x7D, 0xF0,                          // 00000071  mov     rdi,  [rbp - 16 - 8 * 0]
	0x48, 0x8B, 0x75, 0xE8,                          // 00000075  mov     rsi,  [rbp - 16 - 8 * 1]
	0x48, 0x8B, 0x55, 0xE0,                          // 00000079  mov     rdx,  [rbp - 16 - 8 * 2]
	0x48, 0x8B, 0x4D, 0xD8,                          // 0000007D  mov     rcx,  [rbp - 16 - 8 * 3]
	0x4C, 0x8B, 0x45, 0xD0,                          // 00000081  mov     r8,   [rbp - 16 - 8 * 4]
	0x4C, 0x8B, 0x4D, 0xC8,                          // 00000085  mov     r9,   [rbp - 16 - 8 * 5]
	0x66, 0x0F, 0x6F, 0x45, 0xC0,                    // 00000089  movdqa  xmm0, [rbp - 16 - 8 * 6 - 16 * 0]
	0x66, 0x0F, 0x6F, 0x4D, 0xB0,                    // 0000008E  movdqa  xmm1, [rbp - 16 - 8 * 6 - 16 * 1]
	0x66, 0x0F, 0x6F, 0x55, 0xA0,                    // 00000093  movdqa  xmm2, [rbp - 16 - 8 * 6 - 16 * 2]
	0x66, 0x0F, 0x6F, 0x5D, 0x90,                    // 00000098  movdqa  xmm3, [rbp - 16 - 8 * 6 - 16 * 3]
	0x66, 0x0F, 0x6F, 0x65, 0x80,                    // 0000009D  movdqa  xmm4, [rbp - 16 - 8 * 6 - 16 * 4]
	0x66, 0x0F, 0x6F, 0xAD, 0x70, 0xFF, 0xFF, 0xFF,  // 000000A2  movdqa  xmm5, [rbp - 16 - 8 * 6 - 16 * 5]
	0x66, 0x0F, 0x6F, 0xB5, 0x60, 0xFF, 0xFF, 0xFF,  // 000000AA  movdqa  xmm6, [rbp - 16 - 8 * 6 - 16 * 6]
	0x66, 0x0F, 0x6F, 0xBD, 0x50, 0xFF, 0xFF, 0xFF,  // 000000B2  movdqa  xmm7, [rbp - 16 - 8 * 6 - 16 * 7]
	0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,        // 000000BA  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 000000C1  pop     rbp
	0x48, 0xB8,                                      // 000000C2  mov     rax, hookRet
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000C4
	0x48, 0x89, 0x04, 0x24,                          // 000000CC  mov     [rsp], rax
	0x48, 0xB8,                                      // 000000D0  mov     rax, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000D2
	0xFF, 0xE0,                                      // 000000DA  jmp     rax
	0x48, 0x83, 0xEC, 0x08,                          // 000000DC  sub     rsp, 8                 ; <<< hookRet
	0x55,                                            // 000000E0  push    rbp
	0x48, 0x89, 0xE5,                                // 000000E1  mov     rbp, rsp
	0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,        // 000000E4  sub     rsp, STACK_FRAME_SIZE
	0x48, 0x89, 0x45, 0xF8,                          // 000000EB  mov     [rbp - 8], rax
	0x48, 0xBF,                                      // 000000EF  mov     rdi, targetFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 000000F1
	0x48, 0x89, 0xEE,                                // 000000F9  mov     rsi, rbp
	0x48, 0x89, 0xC2,                                // 000000FC  mov     rdx, rax
	0x48, 0xB8,                                      // 000000FF  mov     rax, hookLeaveFunc
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00000101
	0xFF, 0xD0,                                      // 00000109  call    rax
	0x48, 0x89, 0x45, 0x08,                          // 0000010B  mov     [rbp + 8], rax
	0x48, 0x8B, 0x45, 0xF8,                          // 0000010F  mov     rax, [rbp - 8]
	0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,        // 00000113  add     rsp, STACK_FRAME_SIZE
	0x5D,                                            // 0000011A  pop     rbp
	0xC3,                                            // 0000011B  ret
}};

#pragma pack(pop)

struct JmpThunk
{
	JmpThunkCode m_code;
};

#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int* g_p = NULL;
int g_x;

thread_local void* g_originalRet;

void
hookEnter(
	void* func,
	void* rbp,
	void* originalRet
	)
{
	printf("hookEnter(func: %p, rbp: %p, [rsp]: %p)\n", func, rbp, originalRet);
	g_originalRet = originalRet;
}

void*
hookLeave(
	void* func,
	void* rbp,
	void* rax
	)
{
	printf("hookLeave(func: %p, rbp: %p, rax: %lld / 0x%p)\n", func, rbp, (uint64_t)rax, rax);
	return g_originalRet;
}

#if (_AXL_OS_WIN)

void*
hookException(
	EXCEPTION_RECORD* exceptionRecord,
	void* establisherFrame,
	CONTEXT* contextRecord,
	DISPATCHER_CONTEXT* dispatcherContext
	)
{
	void* rbp = (void**)establisherFrame - 2;
	printf("hookException: rbp: %p\n", rbp);
	contextRecord->Rax = (uint64_t)&g_x;
	g_p = &g_x;
	return g_originalRet;
}

#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

JmpThunk*
createJmpThunk(void* targetFunc)
{
#if (_AXL_OS_WIN)
	JmpThunk* thunk = (JmpThunk*)::VirtualAlloc(
		NULL,
		sizeof(JmpThunk),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);
#else
	JmpThunk* thunk = AXL_MEM_NEW(JmpThunk);
	int pageSize = getpagesize();
	size_t pageAddr = (size_t)thunk & ~(pageSize - 1);
	int result = mprotect((void*)pageAddr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (result != 0)
	{
		err::setLastSystemError();
		printf("mprotect failed: %s\n", err::getLastErrorDescription().sz());
		exit(-1);
	}
#endif

	thunk->m_code = g_jmpThunkCodeTemplate;
	thunk->m_code.m_targetFunc1 = (uint64_t)targetFunc;
	thunk->m_code.m_targetFunc2 = (uint64_t)targetFunc;
	thunk->m_code.m_targetFunc3 = (uint64_t)targetFunc;
	thunk->m_code.m_hookRet = (uint64_t)((char*)thunk + sizeof(JmpThunkCode::m_hookRetOffset));
	thunk->m_code.m_hookEnterFunc = (uint64_t)hookEnter;
	thunk->m_code.m_hookLeaveFunc = (uint64_t)hookLeave;
	thunk->m_code.m_hookExceptionFunc = (uint64_t)hookException;

#if (_AXL_OS_WIN)
	thunk->m_runtimeFunction.BeginAddress = 0;
	thunk->m_runtimeFunction.EndAddress = sizeof(JmpThunkCode);
	thunk->m_runtimeFunction.UnwindInfoAddress = (DWORD)((char*)&thunk->m_unwindInfo - (char*)thunk);

	thunk->m_unwindInfo.Version = 1;
	thunk->m_unwindInfo.Flags = UNW_FLAG_EHANDLER;
	thunk->m_unwindInfo.SizeOfProlog = 0;
	thunk->m_unwindInfo.FrameRegister = 0;
	thunk->m_unwindInfo.FrameOffset = 0;
	thunk->m_unwindInfo.CountOfCodes = 0;

	thunk->m_exceptionHandler = sizeof(JmpThunkCode::m_hookSehHandlerOffset);

	uint64_t base = (uint64_t)thunk;
	RtlAddFunctionTable(&thunk->m_runtimeFunction, 1, base);
#endif

	return thunk;
}

//..............................................................................

// uses up all register arguments and spills to stack

typedef int FooFunc(int, double, int, double, int, double, int, double, int, double);

int bar(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("bar(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);

#if (_AXL_OS_WIN)
	*g_p = 10;
#endif

	return 456;
}

int foo(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("foo(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);
	return bar(a, b, c, d, e, f, g, h, i, j);
}

#if (_AXL_OS_WIN)
static CONTEXT g_context = { 0 }; // global so it doesn't affect function
#endif

int test(int a, double b, int c, double d, int e, double f, int g, double h, int i, double j)
{
	printf("test(%d, %f, %d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h, i, j);

#if (_PRINT_UNWIND_INFO)
	g_context.ContextFlags = CONTEXT_CONTROL;
	RtlCaptureContext(&g_context);
	printUnwindInfo(g_context.Rip);
#endif

	int result = -1;

	JmpThunk* jmpThunk = createJmpThunk((void*)foo);

	__try
	{
		result = ((FooFunc*)&jmpThunk->m_code)(a, b, c, d, e, f, g, h, i, j);
		printf("jmpThunk -> %d\n", result);
	}
	__except(1)
	{
		printf("exception caught in test()\n");
	}

	return result;
}

//..............................................................................

int main()
{
#if (_AXL_OS_WIN)
	BOOL result = SymInitialize(INVALID_HANDLE_VALUE, NULL, true);

	__try
	{
#if (_PRINT_UNWIND_INFO)
		g_context.ContextFlags = CONTEXT_CONTROL;
		RtlCaptureContext(&g_context);
		printUnwindInfo(g_context.Rip);
#endif
		test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
	}
	__except(1)
	{
		printf("exception caught in main()\n");
	}
#else
	setvbuf(stdout, NULL, _IOLBF, 1024);

	test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
#endif

	return 0;
}

//..............................................................................
