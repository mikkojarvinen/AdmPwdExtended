
//
// Copyright (C) 2016 IT Services of the University of Turku
//
// This file is based on a version of the file "Config.cpp" that
// was created by Jiri Formacek and published under Apache license version 2.0.
//

#include "stdafx.h"
#include <exception>
#include "Config.h"

const TCHAR * const Config::wcpDefaultDelimiters = DFLT_WCP_DELIMITERS;

Config::Config()
{
	DWORD data;
	HKEY hPolicyKey = 0;
	HKEY hGPExtKey = 0;

	// Initialize default values
	_logLevel = 0;

	_AccountManagementEnabled = false;
	_pwdExpirationProtectionRequired = false;
	_pwdAge = DFLT_PWD_AGE_DAYS;
	_adminName = nullptr;
	_pwdGenTypeNo = DFLT_PWD_GEN_TYPE_NO;

	_pwdComplexity = DFLT_PWD_COMPLEXITY;
	_pwdLength = DFLT_PWD_LENGTH;

	_wcpWordListFileNonexpanded = nullptr;
	_wcpWordListFileExpanded = nullptr;
	_wcpMinWordListLength = DFLT_WCP_MIN_WORD_LIST_LENGTH;
	_wcpNonDefaultDelimiters = nullptr;
	_wcpWordCount = DFLT_WCP_WORD_COUNT;
	_wcpMinNumSeqLength = DFLT_WCP_MIN_NUM_SEQ_LENGTH;
	_wcpMinLength = DFLT_WCP_MIN_LENGTH;
	// End of init

#ifndef _DEBUG
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, GPEXT_REG_PATH, 0, KEY_QUERY_VALUE, &hGPExtKey);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, GPEXT_REG_POLICY_PATH, 0, KEY_QUERY_VALUE, &hPolicyKey);
#else
	RegOpenKeyEx(DEBUG_GPEXT_REG_ROOT_KEY, DEBUG_GPEXT_REG_PATH, 0, KEY_QUERY_VALUE, &hGPExtKey);
	RegOpenKeyEx(DEBUG_GPEXT_REG_ROOT_KEY, DEBUG_GPEXT_REG_POLICY_PATH, 0, KEY_QUERY_VALUE, &hPolicyKey);
#endif

	if (hGPExtKey != 0)
	{
		GetRegistryDWORD(hGPExtKey, LOG_LEVEL_REG_VALUE, &_logLevel);
		if (_logLevel >= LOGLEVEL_INVALID)
			_logLevel = LOGLEVEL_ALL_EVENTS;

		RegCloseKey(hGPExtKey);
	}

	if (hPolicyKey != 0)
	{
		data = 0;
		GetRegistryDWORD(hPolicyKey, ADMIN_ACCOUNT_MANAGEMENT_ENABLED, &data);
		_AccountManagementEnabled = (data != 0);

		data = 0;
		GetRegistryString(hPolicyKey, ADMIN_ACCOUNT_NAME, &_adminName, &data);

		data = 0;
		GetRegistryDWORD(hPolicyKey, PWD_EXPIRATION_PROTECTION_ENABLED_REG_VALUE, &data);
		_pwdExpirationProtectionRequired = (data != 0);

		GetRegistryDWORD(hPolicyKey, PWD_AGE_REG_VALUE, &_pwdAge);
		CheckParam(_pwdAge, DFLT_PWD_AGE_DAYS, MIN_PWD_AGE_DAYS, MAX_PWD_AGE_DAYS);

		GetRegistryDWORD(hPolicyKey, PWD_GEN_TYPE_NO_REG_VALUE, &_pwdGenTypeNo);
		CheckParam(_pwdGenTypeNo, DFLT_PWD_GEN_TYPE_NO, MIN_PWD_GEN_TYPE_NO, MAX_PWD_GEN_TYPE_NO);

		// ---- PasswordGenerator specific () ----
		// Load these parameter values always so that this generator can be used as a fallback generator.
		
		GetRegistryDWORD(hPolicyKey, PWD_LEN_REG_VALUE, &_pwdLength);
		CheckParam(_pwdLength, DFLT_PWD_LENGTH, MIN_PWD_LENGTH, MAX_PWD_LENGTH);

		GetRegistryDWORD(hPolicyKey, PWD_COMPLEXITY_REG_VALUE, &_pwdComplexity);
		CheckParam(_pwdComplexity, DFLT_PWD_COMPLEXITY, MIN_PWD_COMPLEXITY, MAX_PWD_COMPLEXITY);
		
		// ---- WordChainPasswordGenerator specific ----
		if (_pwdGenTypeNo == PWD_GEN_TYPE_NO__WCP)
		{
			GetRegistryString(hPolicyKey, WCP_WORD_LIST_FILE_REG_VALUE, &_wcpWordListFileNonexpanded, &data);

			// Expand to _wcpWordListFileExpanded.
			if (_wcpWordListFileNonexpanded)
			{	
				try
				{
					DWORD capacityNeeded = ExpandEnvironmentStrings(_wcpWordListFileNonexpanded, nullptr, 0);
					// capacityNeeded == 0 means error (_wcpWordListFileNonexpanded cannot be expanded). In that case,
					// leave _wcpWordListFileExpanded to nullptr but keep the original value in _wcpWordListFileNonexpanded.
					if (capacityNeeded)
					{
						_wcpWordListFileExpanded = new TCHAR[capacityNeeded];
						DWORD capacityNeeded2 =
							ExpandEnvironmentStrings(_wcpWordListFileNonexpanded, _wcpWordListFileExpanded, capacityNeeded);
						// Just to be safe:
						if (capacityNeeded2 != capacityNeeded)
						{
							delete[] _wcpWordListFileExpanded;
							_wcpWordListFileExpanded = nullptr;
						}
					}
				}
				catch (std::bad_alloc&) {}
			}

			// _wcpNonDefaultDelimiters
			try
			{
				GetRegistryString(hPolicyKey, WCP_DELIMITERS_REG_VALUE, &_wcpNonDefaultDelimiters, &data);

				if (_wcpNonDefaultDelimiters != nullptr) {
					const size_t wcpDelimitersLen = _tcslen(_wcpNonDefaultDelimiters);

					if (wcpDelimitersLen < MIN_WCP_DELIMITERS_LENGTH || wcpDelimitersLen > MAX_WCP_DELIMITERS_LENGTH)
						throw std::invalid_argument("");
					
					// Check that characters are ASCII characters from the interval [TEXT(' '), TEXT('~')].
					for (size_t i = 0; i < wcpDelimitersLen; ++i)
					{
						const TCHAR &currChar = _wcpNonDefaultDelimiters[i];
						if (currChar < _T(' ') || currChar > _T('~'))
							throw std::invalid_argument("");
					}

				}
			}
			catch (std::invalid_argument&)
			{
				delete[] _wcpNonDefaultDelimiters;
				_wcpNonDefaultDelimiters = nullptr;
			}
			catch (...)
			{
				delete[] _wcpNonDefaultDelimiters;
				_wcpNonDefaultDelimiters = nullptr;
				throw;
			}

			GetRegistryDWORD(hPolicyKey, WCP_MIN_WORD_LIST_LENGTH_REG_VALUE, &_wcpMinWordListLength);
			CheckParam(_wcpMinWordListLength, DFLT_WCP_MIN_WORD_LIST_LENGTH,
				MIN_WCP_MIN_WORD_LIST_LENGTH, MAX_WCP_MIN_WORD_LIST_LENGTH);

			GetRegistryDWORD(hPolicyKey, WCP_WORD_COUNT_REG_VALUE, &_wcpWordCount);
			CheckParam(_wcpWordCount, DFLT_WCP_WORD_COUNT, MIN_WCP_WORD_COUNT, MAX_WCP_WORD_COUNT);

			GetRegistryDWORD(hPolicyKey, WCP_MIN_NUM_SEQ_LENGTH_REG_VALUE, &_wcpMinNumSeqLength);
			CheckParam(_wcpMinNumSeqLength, DFLT_WCP_MIN_NUM_SEQ_LENGTH,
				MIN_WCP_MIN_NUM_SEQ_LENGTH, MAX_WCP_MIN_NUM_SEQ_LENGTH);

			GetRegistryDWORD(hPolicyKey, WCP_MIN_LENGTH_REG_VALUE, &_wcpMinLength);
			CheckParam(_wcpMinLength, DFLT_WCP_MIN_LENGTH, MIN_WCP_MIN_LENGTH, MAX_WCP_MIN_LENGTH);
		} // if (_pwdGenTypeNo == PWD_GEN_TYPE_NO__WCP)

		RegCloseKey(hPolicyKey);
	} // if (hPolicyKey != 0)
}

Config::~Config()
{
	delete[] _adminName;
	delete[] _wcpNonDefaultDelimiters;
	delete[] _wcpWordListFileExpanded;
	delete[] _wcpWordListFileNonexpanded;
}

HRESULT Config::GetRegistryDWORD(HKEY hReg, LPCTSTR regValueName, DWORD *retVal) {
	LONG lResult;
	DWORD dwBuffLen = sizeof(*retVal);

	if (!hReg)
		HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

	lResult = RegQueryValueEx(hReg, regValueName, NULL, NULL, (LPBYTE) retVal, &dwBuffLen);

	if (lResult == ERROR_MORE_DATA)
	{
		lResult = ERROR_BAD_ARGUMENTS;	//value stored in registry is not REG_DWORD
	}

	return HRESULT_FROM_WIN32(lResult);
}

HRESULT Config::GetRegistryString(HKEY hReg, LPCTSTR regValueName, TCHAR **retVal, DWORD *dwStringCapacity)
{
	LONG lResult;
	DWORD dwBuffLen = 0;

	lResult = RegQueryValueEx(hReg, regValueName, NULL, NULL, NULL, &dwBuffLen);

	if (lResult == ERROR_MORE_DATA || lResult == ERROR_SUCCESS)
	{
		//seems to return ERROR_SUCCESS instead of ERROR_MORE_DATA when trying to get buffer length (at least on W2K8R2)

		// Round up and leave space for a normally extra null character at the end of the final buffer to increase safety.
		// The safety null character will be created during the initialization of the buffer.
		const size_t round = sizeof(TCHAR) - 1;
		*dwStringCapacity = ( (dwBuffLen + round) / sizeof(TCHAR) )  +  1;
		*retVal = new(std::nothrow) TCHAR[*dwStringCapacity]();	//allocate buffer; caller is responsible for releasing it
		if (*retVal == NULL)
			return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		
		lResult = RegQueryValueEx(hReg, regValueName, NULL, NULL, (LPBYTE) *retVal, &dwBuffLen);
	}
	return HRESULT_FROM_WIN32(lResult);
}

