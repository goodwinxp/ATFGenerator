#pragma once

#include <Windows.h>
#include <stdint.h>

#define START_ATF_NAMESPACE namespace ATF {
#define END_ATF_NAMESPACE };

START_ATF_NAMESPACE
	const uint16_t usVersion = 0x0001;
	const wchar_t wszVersion[] = L"0.1";
	
	#include "ATFRegistry.hpp"
	
	struct _hook_record {
		LPVOID pTrgAppOrig;	// Адрес в целевом приложении
		LPVOID* ppOrig;		// clbk
		LPVOID* ppTramp;	// tramp
		LPVOID  pWrapper;	// tramp
		LPVOID  pBind;		// bind
	};
END_ATF_NAMESPACE
