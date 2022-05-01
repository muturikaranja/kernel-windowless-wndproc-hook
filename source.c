#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include <stdint.h>
#include <stdarg.h>

/*
   Compatible with Windows 11 21H2 RTM. You'll have to get offsets for your windows version..
   Useful for game cheats..
*/

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	VOID* ExceptionTable;                                                   //0x10
	ULONG ExceptionTableSize;                                               //0x18
	VOID* GpValue;                                                          //0x20
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	union
	{
		USHORT SignatureLevel : 4;                                            //0x6e
		USHORT SignatureType : 3;                                             //0x6e
		USHORT Frozen : 2;                                                    //0x6e
		USHORT HotPatch : 1;                                                  //0x6e
		USHORT Unused : 6;                                                    //0x6e
		USHORT EntireField;                                                 //0x6e
	} u1;                                                                   //0x6e
	VOID* SectionPointer;                                                   //0x70
	ULONG CheckSum;                                                         //0x78
	ULONG CoverageSectionSize;                                              //0x7c
	VOID* CoverageSection;                                                  //0x80
	VOID* LoadedImports;                                                    //0x88
	union
	{
		VOID* Spare;                                                        //0x90
		struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
	};
	ULONG SizeOfImageNotRounded;                                            //0x98
	ULONG TimeDateStamp;                                                    //0x9c
} _KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


typedef struct tagPOINT {
	LONG x;
	LONG y;
} POINT, * PPOINT, * NPPOINT, * LPPOINT;

#define RGB(r,g,b)          ((COLORREF)(((BYTE)(r)|((WORD)((BYTE)(g))<<8))|(((DWORD)(BYTE)(b))<<16)))
#define PALETTERGB(r,g,b)   (0x02000000 | RGB(r,g,b))
#define PALETTEINDEX(i)     ((COLORREF)(0x01000000 | (DWORD)(WORD)(i)))

#define GetRValue(rgb)      (LOBYTE(rgb))
#define GetGValue(rgb)      (LOBYTE(((WORD)(rgb)) >> 8))
#define GetBValue(rgb)      (LOBYTE((rgb)>>16))


__forceinline PVOID get_ntoskrnl_export(PCWSTR export_name)
{
	UNICODE_STRING export_string;
	RtlInitUnicodeString(&export_string, export_name);

	return MmGetSystemRoutineAddress(&export_string);
}

__forceinline PKLDR_DATA_TABLE_ENTRY get_ldr_entry(PCWSTR base_dll_name)
{
	UNICODE_STRING base_dll_name_string;
	RtlInitUnicodeString(&base_dll_name_string, base_dll_name);

	PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)get_ntoskrnl_export(L"PsLoadedModuleList");

	/* Is PsLoadedModuleList null? */
	if (!PsLoadedModuleList)
	{
		return NULL;
	}

	/* Start iterating at LIST_ENTRY.Flink */
	PKLDR_DATA_TABLE_ENTRY iter_ldr_entry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink;

	/* If LIST_ENTRY.Flink = beginning, then it's the last entry */
	while ((PLIST_ENTRY)iter_ldr_entry != PsLoadedModuleList)
	{
		if (!RtlCompareUnicodeString(&iter_ldr_entry->BaseDllName, &base_dll_name_string, TRUE))
		{
			return iter_ldr_entry;
		}

		/* Move on to the next entry */
		iter_ldr_entry = (PKLDR_DATA_TABLE_ENTRY)iter_ldr_entry->InLoadOrderLinks.Flink;
	}

	return NULL;
}


ULONG64 count = 0;

__forceinline void log_success(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vDbgPrintExWithPrefix("[SUCCESS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
	va_end(args);

	count++;
}

__forceinline void log_debug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vDbgPrintExWithPrefix("[DEBUG] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
	va_end(args);

	count++;
}

__forceinline void log_error(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vDbgPrintExWithPrefix("[ERROR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, args);
	va_end(args);

	count++;
}


#define LF_FACESIZE 32

typedef struct tagLOGFONTW {
	LONG  lfHeight;
	LONG  lfWidth;
	LONG  lfEscapement;
	LONG  lfOrientation;
	LONG  lfWeight;
	UCHAR  lfItalic;
	UCHAR  lfUnderline;
	UCHAR  lfStrikeOut;
	UCHAR  lfCharSet;
	UCHAR  lfOutPrecision;
	UCHAR  lfClipPrecision;
	UCHAR  lfQuality;
	UCHAR  lfPitchAndFamily;
	WCHAR lfFaceName[LF_FACESIZE];
} LOGFONTW, * PLOGFONTW, * NPLOGFONTW, * LPLOGFONTW;

PVOID hdc = NULL;

ULONG previous_text_color = 0;
ULONG current_text_color = 0;

ULONG previous_text_background_color = 0;
ULONG current_text_background_color = 0;

ULONG previous_background_mode = 0;
ULONG current_background_mode = 0;

POINT previous_position = { 0, 0 };

PVOID current_font = NULL;

PVOID(__stdcall* NtGdiCreateSolidBrush)(ULONG, PVOID) = NULL;

PVOID create_solid_brush(ULONG color)
{
	return NtGdiCreateSolidBrush(color, NULL);
}

PVOID(__fastcall* GreCreatePen)(INT, INT, ULONG, PVOID) = NULL;

PVOID create_pen(INT style, INT width, ULONG color)
{
	return GreCreatePen(style, width, color, NULL);
}

PVOID(__fastcall* GreSelectPen)(PVOID, PVOID) = NULL;

void select_pen(PVOID pen)
{
	GreSelectPen(hdc, pen);
}

BOOLEAN(__fastcall* GreMoveTo)(PVOID, INT, INT, PVOID) = NULL;

BOOLEAN move_to(int x, int y)
{
	return GreMoveTo(hdc, x, y, &previous_position);
}

BOOLEAN(__fastcall* GreLineTo)(PVOID, INT, INT) = NULL;

BOOLEAN line_to(int x, int y)
{
	return GreLineTo(hdc, x, y);
}

BOOLEAN line(POINT* from, POINT* to)
{
	BOOLEAN error = FALSE;

	error = move_to(from->x, from->y);
	error = line_to(to->x, to->y);

	return error;
}

ULONG(__fastcall* GreGetTextColor)(PVOID) = NULL;

ULONG get_text_color()
{
	return GreGetTextColor(hdc);;
}

ULONG(__fastcall* GreSetTextColor)(PVOID, ULONG) = NULL;

ULONG set_text_color(ULONG color)
{
	previous_text_color = GreSetTextColor(hdc, color);
	current_text_color = color;
	return previous_text_color;
}

ULONG(__fastcall* GreGetBkColor)(PVOID) = NULL;

ULONG get_text_background_color()
{
	return GreGetBkColor(hdc);
}

ULONG(__fastcall* GreSetBkColor)(PVOID, ULONG) = NULL;

ULONG set_text_background_color(ULONG color)
{
	previous_text_background_color = GreSetBkColor(hdc, color);
	current_text_background_color = color;
	return previous_text_background_color;
}

INT(__fastcall* GreSetBkMode)(PVOID, INT) = NULL;

INT set_background_mode(INT mode)
{
	previous_background_mode = GreSetBkMode(hdc, mode);
	current_background_mode = mode;
	return previous_background_mode;
}

PVOID(__fastcall* GreCreateFontIndirectW)(PVOID) = NULL;

PVOID create_font(PVOID logfontw)
{
	return GreCreateFontIndirectW(logfontw);
}

PVOID(__fastcall* NtGdiSelectFont)(PVOID, PVOID) = NULL;

void select_font(PVOID hfont)
{
	NtGdiSelectFont(hdc, hfont);
}

BOOLEAN(__fastcall* GreExtTextOutWInternal)(PVOID hdc, int x, int y, UINT32 flOpts, PVOID prcl, LPWSTR pwsz, int cwc, PVOID pdx, PVOID pvBuffer, ULONG dwCodePage) = NULL;

BOOLEAN text(POINT* tl, UNICODE_STRING* string)
{
	return GreExtTextOutWInternal(hdc, tl->x, tl->y, 0, NULL, string->Buffer, string->Length, NULL, NULL, 0);
}


typedef struct _LARGE_UNICODE_STRING
{
	ULONG Length;           // 000
	ULONG MaximumLength : 31; // 004
	ULONG bAnsi : 1;          // 004
	PWSTR Buffer;           // 008
} LARGE_UNICODE_STRING, * PLARGE_UNICODE_STRING;

LARGE_UNICODE_STRING*(__fastcall* getStrName)(PVOID wnd, LARGE_UNICODE_STRING* name) = NULL;
LONG(__fastcall* o_xxxEventWndProc)(PVOID wnd, UINT32 message, ULONG64 wparam, ULONG64 lparam) = NULL;

UNICODE_STRING game_window_name = { 0 };
LPSTR ansi_game_window_name = "Fortnite  ";

UNICODE_STRING wnd_name = { 0 };
LARGE_UNICODE_STRING large_string_wnd_name = { 0 };

ULONG64 game_base_address = 0;
BOOLEAN got_game_base = FALSE;

#define WM_NULL                         0x0000
#define WM_CREATE                       0x0001
#define WM_DESTROY                      0x0002
#define WM_MOVE                         0x0003
#define WM_SIZE                         0x0005

#define WM_ACTIVATE                     0x0006
/*
 * WM_ACTIVATE state values
 */
#define     WA_INACTIVE     0
#define     WA_ACTIVE       1
#define     WA_CLICKACTIVE  2

#define WM_SETFOCUS                     0x0007
#define WM_KILLFOCUS                    0x0008
#define WM_ENABLE                       0x000A
#define WM_SETREDRAW                    0x000B
#define WM_SETTEXT                      0x000C
#define WM_GETTEXT                      0x000D
#define WM_GETTEXTLENGTH                0x000E
#define WM_PAINT                        0x000F
#define WM_CLOSE                        0x0010
#define WM_QUIT                         0x0012
#define WM_ERASEBKGND                   0x0014
#define WM_SYSCOLORCHANGE               0x0015
#define WM_SHOWWINDOW                   0x0018
#define WM_WININICHANGE                 0x001A

BOOLEAN large_to_unicode(LARGE_UNICODE_STRING* large_string, UNICODE_STRING* unicode_string)
{
	if (!large_string->bAnsi)
	{
		unicode_string->MaximumLength = large_string->MaximumLength;
		unicode_string->Length = large_string->Length;

		memcpy(unicode_string->Buffer, large_string->Buffer, large_string->MaximumLength * 2ULL);

		return TRUE;
	}

	return FALSE;
}

BOOLEAN compare_wnd_name(PVOID wnd, UNICODE_STRING* unicode_name, LPSTR ansi_name, LARGE_UNICODE_STRING* large_string_wnd_name)
{
	// Is the window name ANSI?
	if (!large_to_unicode(large_string_wnd_name, &wnd_name))
	{
		if (strcmp(ansi_name, (LPSTR)large_string_wnd_name->Buffer) == 0)
		{
			return TRUE;
		}
	}
	else
	{
		if (RtlCompareUnicodeString(unicode_name, &wnd_name, FALSE) == 0)
		{
			return TRUE;
		}
	}

	// How did we get here?
	return FALSE;
}

/*
	We're attached to the process of the calling thread.
	We can read/write the memory of the calling process's memory like an internal cheat.
	Also, since the calling thread is a win32 thread, we can call win32k functions.
*/
LONG __fastcall hk_xxxEventWndProc(PVOID wnd, UINT32 message, ULONG64 wparam, ULONG64 lparam)
{
	getStrName(wnd, &large_string_wnd_name);

	// Is the window the game window we're looking for?
	if (!compare_wnd_name(wnd, &game_window_name, ansi_game_window_name, &large_string_wnd_name))
	{
		if (!got_game_base)
		{
			game_base_address = PsGetProcessSectionBaseAddress(IoGetCurrentProcess());

			if (!game_base_address)
			{
				log_error("Failed to obtain base address.. Forcing BSOD via KeBugCheckEx(0x1000, 0x1000, 0x1000, 0x1000)..\n");
				KeBugCheckEx(0x1000, 0x1000, 0x1000, 0x1000, 0x1000);
			}
		}

		return o_xxxEventWndProc(wnd, message, wparam, lparam);
	}

	// Is the window closing and/or being destroyed? If so, we wont render..
	if ((message == WM_CLOSE) || (message == WM_QUIT) || (message == WM_DESTROY))
	{
		return o_xxxEventWndProc(wnd, message, wparam, lparam);
	}

	// Do whatever we want..

	return o_xxxEventWndProc(wnd, message, wparam, lparam);
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driver_object, UNICODE_STRING* registry_path)
{
	PKLDR_DATA_TABLE_ENTRY win32kfull_base = get_ldr_entry(L"win32kfull.sys");
	if (!win32kfull_base)
	{
		log_error("Failed to get win32kfull.sys loader entry.\n");
		return STATUS_UNSUCCESSFUL;
	}

	PKLDR_DATA_TABLE_ENTRY win32kbase_base = get_ldr_entry(L"win32kbase.sys");
	if (!win32kbase_base)
	{
		log_error("Failed to get win32kbase.sys loader entry.\n");
		return STATUS_UNSUCCESSFUL;
	}

	o_xxxEventWndProc = *(ULONG64*)((ULONG64)win32kfull_base->DllBase + 0x2DFD20ULL);
	getStrName = (ULONG64)win32kfull_base->DllBase + 0x4CC60ULL;

	log_debug
	(
		"Resolved:\n\t-> xxxEventWndProc: %llX\n\t-> tagWND::ProtectedLargeUnicodeStringWNDstrName::getStrName: %llX"
		, o_xxxEventWndProc
		, getStrName 
	);

	NtGdiCreateSolidBrush = (ULONG64)win32kfull_base->DllBase + 0x1075C0ULL;

	GreCreatePen = (ULONG64)win32kfull_base->DllBase + 0xEA488ULL;
	GreSelectPen = (ULONG64)win32kbase_base->DllBase + 0x17FEFULL;
	
	GreMoveTo = (ULONG64)win32kfull_base->DllBase + 0x2A04D4ULL;
	GreLineTo = (ULONG64)win32kfull_base->DllBase + 0x12DD30ULL;

	log_debug
	(
		"\n\t-> NtGdiCreateSolidBrush: %llX\n\t-> GreCreatePen: %llX\n\t-> GreSelectPen: %llX\n\t-> GreMoveTo: %llX\n\t-> GreLineTo: %llX"
		, NtGdiCreateSolidBrush
		, GreCreatePen
		, GreSelectPen
		, GreMoveTo
		, GreLineTo
	);

	GreGetTextColor = (ULONG64)win32kfull_base->DllBase + 0x83454ULL;
	GreSetTextColor = (ULONG64)win32kfull_base->DllBase + 0x8CEDCULL;

	GreGetBkColor = (ULONG64)win32kfull_base->DllBase + 0x83404ULL;
	GreSetBkColor = (ULONG64)win32kfull_base->DllBase + 0x8CF70ULL;

	GreSetBkMode = (ULONG64)win32kfull_base->DllBase + 0x89344ULL;

	log_debug
	(
		"\n\t-> GreGetTextColor: %llX\n\t-> GreSetTextColor: %llX\n\t-> GreGetBkColor: %llX\n\t-> GreSetBkColor: %llX\n\t-> GreSetBkMode: %llX"
		, GreGetTextColor
		, GreSetTextColor
		, GreGetBkColor
		, GreSetBkColor
		, GreSetBkMode
	);

	GreCreateFontIndirectW = (ULONG64)win32kfull_base->DllBase + 0xB83C0ULL;
	NtGdiSelectFont = (ULONG64)win32kfull_base->DllBase + 0x89180ULL;
	GreExtTextOutWInternal = (ULONG64)win32kfull_base->DllBase + 0x6BD94ULL;

	log_debug
	(
		"\n\t-> GreCreateFontIndirectW: %llx\n\t-> NtGdiSelectFont: %llX\n\t-> GreExtTextOutWInternal: %llX\n\n"
		, GreCreateFontIndirectW
		, NtGdiSelectFont
		, GreExtTextOutWInternal
	);

	wnd_name.MaximumLength = (USHORT)260;
	wnd_name.Length = 0;
	wnd_name.Buffer = ExAllocatePool(NonPagedPoolNx, 260ULL * 2ULL);

	if (!wnd_name.Buffer)
	{
		log_error("Failed to pre-allocate buffer for the WND's unicode string.\n");
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&game_window_name, L"Fortnite  ");

	PVOID rw_memory = MmMapIoSpace(MmGetPhysicalAddress(&o_xxxEventWndProc), 4096, MmNonCached);
	_InterlockedExchangePointer(rw_memory, &hk_xxxEventWndProc);

	log_success("Swapped xxxEventWndProc pointer within gServerHandlers!\n");

	return STATUS_SUCCESS;
}