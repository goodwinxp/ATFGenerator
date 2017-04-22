#pragma once

#include <Windows.h>
#include <stdint.h>

#define START_ATF_NAMESPACE namespace ATF {
#define END_ATF_NAMESPACE };

START_ATF_NAMESPACE
	const uint16_t usVersion = 0x0001;
	const wchar_t wszVersion[] = L"0.1";
END_ATF_NAMESPACE