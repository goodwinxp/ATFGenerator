#pragma once

#include <Windows.h>
#include <stdint.h>

#define START_ATF_NAMESPACE namespace ATF {
#define END_ATF_NAMESPACE };

START_ATF_NAMESPACE
	const uint16_t usVersion = 0x0002;
	const wchar_t wszVersion[] = L"0.2";
	
	#include "ATFRegistry.hpp"
	
	struct _hook_record {
		LPVOID pTrgAppOrig;	// Адрес в целевом приложении
		LPVOID* ppOrig;		// clbk
		LPVOID* ppTramp;	// tramp
		LPVOID  pWrapper;	// tramp
		LPVOID  pBind;			// bind
	};
	
	template<typename _Ty, size_t _Need, size_t _Have = sizeof(_Ty)>
	constexpr bool checkSize()
	{
		static_assert(_Have == _Need, "Invalid size");
		return true;
	}
END_ATF_NAMESPACE
