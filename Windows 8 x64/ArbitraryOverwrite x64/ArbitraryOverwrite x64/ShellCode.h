#pragma once

void ShellCode();

typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(
	IN ULONG ProfileSource,
	OUT PULONG Interval
	);