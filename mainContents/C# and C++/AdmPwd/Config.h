#pragma once
#ifndef ADMPWD_CONFIG
#define ADMPWD_CONFIG

//
// Copyright (C) 2016 IT Services of the University of Turku
//
// This file is based on a version of the file "Config.h" that
// was created by Jiri Formacek and published under Apache license version 2.0.
//


// Registry keys:

// extension registration place
#define GPEXT_REG_PATH L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}"
// extension policy store
#define GPEXT_REG_POLICY_PATH L"Software\\Policies\\Microsoft Services\\AdmPwd"


// Registry keys for debugging (only defined when _DEBUG is defined):
#ifdef _DEBUG

#ifndef DEBUG_GPEXT_REG_ROOT_KEY
#define DEBUG_GPEXT_REG_ROOT_KEY HKEY_CURRENT_USER
#endif
#ifndef DEBUG_GPEXT_REG_PATH
#define DEBUG_GPEXT_REG_PATH L"Software\\AdmPwd_DEV\\GPExt"
#endif
#ifndef DEBUG_GPEXT_REG_POLICY_PATH
#define DEBUG_GPEXT_REG_POLICY_PATH L"Software\\AdmPwd_DEV\\AdmPwd"
#endif

#endif  // ifdef _DEBUG


// Registry value names:

// Name of registry value storing the logging level
#define LOG_LEVEL_REG_VALUE L"ExtensionDebugLevel"

// Name of registry value storing flag that disables password management.
#define ADMIN_ACCOUNT_MANAGEMENT_ENABLED L"AdmPwdEnabled"
// Name of registry value storing flag whether or not to enforce password age policy on expiration time
#define PWD_EXPIRATION_PROTECTION_ENABLED_REG_VALUE L"PwdExpirationProtectionEnabled"
// Name of registry value storing desired password age in days.
#define PWD_AGE_REG_VALUE L"PasswordAgeDays"
// Name of registry value storing the admin account name.
#define ADMIN_ACCOUNT_NAME L"AdminAccountName"
// Registry value name. Selected password generator type number.
#define PWD_GEN_TYPE_NO_REG_VALUE L"PasswordGeneratorType"

// Name of registry value storing desired password length.
#define PWD_LEN_REG_VALUE L"PasswordLength"
// Name of registry value storing desired password complexity.
#define PWD_COMPLEXITY_REG_VALUE L"PasswordComplexity"

// Registry value name. The filepath of the word list used by word chain password generators.
#define WCP_WORD_LIST_FILE_REG_VALUE L"WcpWordListFile"
// Registry value name. The minimum number of words in the word list.
#define WCP_MIN_WORD_LIST_LENGTH_REG_VALUE L"WcpMinWordListLength"
// Registry value name. The delimiter characters to be used after words in a word chain password.
#define WCP_DELIMITERS_REG_VALUE L"WcpDelimiters"
// Registry value name. Number of words in a word chain password.
#define WCP_WORD_COUNT_REG_VALUE L"WcpWordCount"
// Registry value name. The minimum and default number of decimal numbers in a word chain password.
#define WCP_MIN_NUM_SEQ_LENGTH_REG_VALUE L"WcpMinNumSeqLength"
// Registry value name. Minimum password length for a word chain password.
#define WCP_MIN_LENGTH_REG_VALUE L"WcpMinLength"



// Logging levels
enum : DWORD {
	LOGLEVEL_ERRORS_ONLY = 0,
	LOGLEVEL_ERRORS_WARNINGS,
	LOGLEVEL_ALL_EVENTS,
	LOGLEVEL_INVALID	//always at the end of enum
};

// Password generator type numbers
enum : DWORD {
	PWD_GEN_TYPE_NO__BASIC = 0,		// PasswordGenerator
	PWD_GEN_TYPE_NO__WCP			// WordChainPasswordGenerator
};

// Password quality and duration parameters:

#define DFLT_PWD_AGE_DAYS		30
#define MIN_PWD_AGE_DAYS		1
#define MAX_PWD_AGE_DAYS		365
#define DFLT_PWD_GEN_TYPE_NO		PWD_GEN_TYPE_NO__BASIC
#define MIN_PWD_GEN_TYPE_NO			PWD_GEN_TYPE_NO__BASIC
#define MAX_PWD_GEN_TYPE_NO			PWD_GEN_TYPE_NO__WCP

#define DFLT_PWD_COMPLEXITY		4
#define MAX_PWD_COMPLEXITY		4
#define MIN_PWD_COMPLEXITY		1
#define DFLT_PWD_LENGTH				12
#define MIN_PWD_LENGTH				8
#define MAX_PWD_LENGTH				64

#define DFLT_WCP_MIN_WORD_LIST_LENGTH	512
#define MIN_WCP_MIN_WORD_LIST_LENGTH	1
#define MAX_WCP_MIN_WORD_LIST_LENGTH	5000000
#define DFLT_WCP_DELIMITERS					_T("-.")
#define MIN_WCP_DELIMITERS_LENGTH			1
#define MAX_WCP_DELIMITERS_LENGTH			100
#define DFLT_WCP_WORD_COUNT				6
#define MIN_WCP_WORD_COUNT				2
#define MAX_WCP_WORD_COUNT				14
#define DFLT_WCP_MIN_NUM_SEQ_LENGTH			4
#define MIN_WCP_MIN_NUM_SEQ_LENGTH			1
#define MAX_WCP_MIN_NUM_SEQ_LENGTH			15
#define DFLT_WCP_MIN_LENGTH				DFLT_PWD_LENGTH
#define MIN_WCP_MIN_LENGTH				MIN_PWD_LENGTH
#define MAX_WCP_MIN_LENGTH				MAX_PWD_LENGTH


class Config
{
public:
	Config();
	~Config();


	// Properties:

	// logging level
	__declspec(property(get = GET_LogLevel)) DWORD LogLevel;
	// management enabled
	__declspec(property(get = GET_AccountManagementEnabled)) bool AccountManagementEnabled;
	// password expiration protection
	__declspec(property(get = GET_PasswordExpirationProtectionRequired)) bool PasswordExpirationProtectionRequired;
	// admin account name
	__declspec(property(get = GET_AdminAccountName)) TCHAR* AdminAccountName;
	// max password age
	__declspec(property(get = GET_PasswordAge)) DWORD PasswordAge;
	// Selected password generator type number. PWD_GEN_TYPE_NO__BASIC or PWD_GEN_TYPE_NO__WCP.
	__declspec(property(get = GET_SelectedPasswordGenerator)) DWORD SelectedPasswordGenerator;

	// Password complexity (used by basic password generators).
	__declspec(property(get = GET_PasswordComplexity)) DWORD PasswordComplexity;
	// Password length (used by basic password generators).
	__declspec(property(get = GET_PasswordLength)) DWORD PasswordLength;

	// The filepath of the word list used by word chain password generators.
	// The path may contain environment variables.
	// The value is either a nullptr or a null-terminated C-string.
	__declspec(property(get = GET_WcpWordListFileNonexpanded)) const TCHAR* WcpWordListFileNonexpanded;
	// The filepath of the word list used by word chain password generators.
	// Environment variables in the path have been expanded using PathUnExpandEnvStrings.
	// The value is either a nullptr or a null-terminated C-string.
	__declspec(property(get = GET_WcpWordListFileExpanded)) const TCHAR* WcpWordListFileExpanded;
	// The minimum number of words in the word list.
	__declspec(property(get = GET_WcpMinWordListLength)) DWORD WcpMinWordListLength;
	// The delimiter characters to be used after words in a word chain password.
	__declspec(property(get = GET_WcpDelimiters)) const TCHAR* WcpDelimiters;
	// Number of words in a word chain password.
	__declspec(property(get = GET_WcpWordCount)) DWORD WcpWordCount;
	// The minimum and default length of the decimal number sequence at the end of a word chain password.
	// In other words, the minimum and default number of decimal numbers in a word chain password.
	// The number of decimal numbers is higher than the minimum if and only if the lower limit for
	// the length of the password (WcpMinLength) is not reached by using the minimum.
	__declspec(property(get = GET_WcpMinNumSeqLength)) DWORD WcpMinNumSeqLength;
	// Minimum number of characters in a word chain password.
	__declspec(property(get = GET_WcpMinLength)) DWORD WcpMinLength;
	

	// Accessors:

	inline DWORD GET_LogLevel() const {
		return _logLevel;
	}
	inline bool GET_AccountManagementEnabled() const {
		return _AccountManagementEnabled;
	}
	inline bool GET_PasswordExpirationProtectionRequired() const {
		return _pwdExpirationProtectionRequired;
	}
	inline TCHAR* GET_AdminAccountName() const {
		return _adminName;
	}
	inline DWORD GET_PasswordAge() const {
		return _pwdAge;
	}
	inline DWORD GET_SelectedPasswordGenerator() const {
		return _pwdGenTypeNo;
	}

	inline DWORD GET_PasswordComplexity() const {
		return _pwdComplexity;
	}
	inline DWORD GET_PasswordLength() const {
		return _pwdLength;
	}

	inline const TCHAR* GET_WcpWordListFileNonexpanded() const {
		return _wcpWordListFileNonexpanded;
	}
	inline const TCHAR* GET_WcpWordListFileExpanded() const {
		return _wcpWordListFileExpanded;
	}
	inline DWORD GET_WcpMinWordListLength() const {
		return _wcpMinWordListLength;
	}
	inline const TCHAR* GET_WcpDelimiters() const {
		return _wcpNonDefaultDelimiters? _wcpNonDefaultDelimiters : wcpDefaultDelimiters;
	}
	inline DWORD GET_WcpWordCount() const {
		return _wcpWordCount;
	}
	inline DWORD GET_WcpMinNumSeqLength() const {
		return _wcpMinNumSeqLength;
	}
	inline DWORD GET_WcpMinLength() const {
		return _wcpMinLength;
	}


private:
	DWORD _logLevel;
	bool _AccountManagementEnabled;
	bool _pwdExpirationProtectionRequired;
	TCHAR* _adminName;
	DWORD _pwdAge;
	DWORD _pwdGenTypeNo;

	DWORD _pwdComplexity;
	DWORD _pwdLength;
	
	TCHAR* _wcpWordListFileNonexpanded;
	TCHAR* _wcpWordListFileExpanded;
	DWORD _wcpMinWordListLength;
	TCHAR* _wcpNonDefaultDelimiters;	// Iff this is null, WcpDelimiters is wcpDefaultDelimiters.
	DWORD _wcpWordCount;
	DWORD _wcpMinNumSeqLength;
	DWORD _wcpMinLength;

	
	// Methods:

	HRESULT GetRegistryDWORD(HKEY hReg, LPCTSTR regValueName, DWORD *retVal);
	HRESULT GetRegistryString(HKEY hReg, LPCTSTR regValueName, TCHAR **retVal, DWORD *dwStringCapacity);

	// Static:

	// Sets param to dfltVal if param is not in the range [minVal, maxVal].
	static inline void CheckParam(DWORD &param, DWORD dfltVal, DWORD minVal, DWORD maxVal)
	{
		if (param < minVal || param > maxVal)  param = dfltVal;
	}

	static const TCHAR * const wcpDefaultDelimiters;		// Value is DFLT_WCP_DELIMITERS.
};

#endif // !ADMPWD_CONFIG
