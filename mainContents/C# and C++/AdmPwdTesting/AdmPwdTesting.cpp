
//
// Copyright (C) 2016 IT Services of the University of Turku
//

#define _CRTDBG_MAP_ALLOC

#include "AdmPwd\stdafx.h"
#include <cstdlib>
#include <crtdbg.h>
#include <iostream>
#include "AdmPwd\Config.h"
#include "AdmPwd\PasswordGenerator.h"
#include "AdmPwd\WordChainPasswordGenerator.h"


namespace AdmPwdTestingMain
{
	const size_t inputBufferCapacity = 250;		// in TCHARs
	TCHAR inputBuffer[inputBufferCapacity] = {};

	// If true, configAndPwdGenComboTest() will be run. Otherwise the separate tests configTest() and pwdGenTest() will be run.
	const bool runComboTest = true;

	// The chosen password generator.
	const DWORD pwdGenTypeNo =
		//PWD_GEN_TYPE_NO__BASIC;
		PWD_GEN_TYPE_NO__WCP;

	// PasswordGenerator parameters
	struct BasicGenParams
	{
		DWORD passwordComplexity		= 4;
		DWORD passwordLength			= 13;

		void setWithConfig(const Config *cfg)
		{
			this->passwordComplexity = cfg->PasswordComplexity;
			this->passwordLength = cfg->PasswordLength;
		}
	};

	// WordChainPasswordGenerator parameters
	struct WcpGenParams
	{
		DWORD wcpMinLength				= 41;
		DWORD wcpWordCount				= 5;
		DWORD wcpMinNumSeqLength		= 4;
		DWORD wcpMinWordListLength		= 3;
		const TCHAR *wcpDelimiters		= _T("-. ");
		const TCHAR *wcpWordListFileNonexpanded =
			_T("%USERPROFILE%\\Documents\\AdmPwd\\TestFiles\\WcpWords.txt");
			//nullptr;

		void setWithConfig(const Config *cfg)
		{
			this->wcpMinLength = cfg->WcpMinLength;
			this->wcpWordCount = cfg->WcpWordCount;
			this->wcpMinNumSeqLength = cfg->WcpMinNumSeqLength;
			this->wcpMinWordListLength = cfg->WcpMinWordListLength;
			this->wcpDelimiters = cfg->WcpDelimiters;
			this->wcpWordListFileNonexpanded = cfg->WcpWordListFileNonexpanded;
		}
	};



	void printConfig(const Config& config)
	{
#define TEMP_PRINT(expr, format, typeCast) \
_tprintf_s(  _T(#expr) _T(": ") _T(format) _T("\n"),  typeCast expr  )

		TEMP_PRINT(config.LogLevel, "%d", (int));
		TEMP_PRINT(config.AccountManagementEnabled, "%d", (int));
		TEMP_PRINT(config.PasswordExpirationProtectionRequired, "%d", (int));
		TEMP_PRINT(config.AdminAccountName, "\"%s\"", );
		TEMP_PRINT(config.PasswordAge, "%d", (int));
		TEMP_PRINT(config.SelectedPasswordGenerator, "%d", (int));

		TEMP_PRINT(config.PasswordComplexity, "%d", (int));
		TEMP_PRINT(config.PasswordLength, "%d", (int));

		TEMP_PRINT(config.WcpWordListFileNonexpanded, "\"%s\"", );
		TEMP_PRINT(config.WcpWordListFileExpanded, "\"%s\"", );
		TEMP_PRINT(config.WcpMinWordListLength, "%d", (int));
		TEMP_PRINT(config.WcpDelimiters, "\"%s\"", );
		TEMP_PRINT(config.WcpWordCount, "%d", (int));
		TEMP_PRINT(config.WcpMinNumSeqLength, "%d", (int));
		TEMP_PRINT(config.WcpMinLength, "%d", (int));

#undef TEMP_PRINT
	}


	// Tests Config.
	int configTest()
	{
		_tprintf_s( _T("---- configTest() ----\n\n") );
		Config config;
		printConfig(config);
		_tprintf_s( _T("\n\n") );
		return 0;
	}



	inline void createPwdGen(std::unique_ptr<PasswordGenerator>& upGen, const Config *cfg = nullptr)
	{
		BasicGenParams params;
		if (cfg)  params.setWithConfig(cfg);

		upGen.reset( new PasswordGenerator(params.passwordComplexity, params.passwordLength) );
	}

	inline void createPwdGen(std::unique_ptr<WordChainPasswordGenerator>& upGen, const Config *cfg = nullptr)
	{
		WcpGenParams params;
		if (cfg)  params.setWithConfig(cfg);

		TCHAR *wcpWordListFileExpanded = nullptr;
		TCHAR wcpWordListFileExpandedBuffer[MAX_PATH];

		if (params.wcpWordListFileNonexpanded)
		{
			wcpWordListFileExpanded = wcpWordListFileExpandedBuffer;
			BOOL success = ExpandEnvironmentStrings(params.wcpWordListFileNonexpanded, wcpWordListFileExpanded, MAX_PATH);
			if (!success)  throw std::runtime_error("Could not expand wcpWordListFileNonexpanded.");
		}
		
		upGen.reset( new WordChainPasswordGenerator(params.wcpMinLength, params.wcpWordCount, params.wcpMinNumSeqLength,
			wcpWordListFileExpanded, params.wcpDelimiters, params.wcpMinWordListLength) );
	}

	
	inline void printPwdGenProperties(const PasswordGenerator& gen)
	{
		_tprintf_s( _T("Password complexity: %d\n"), (int)gen.PasswordComplexity );
	}

	inline void printPwdGenProperties(const WordChainPasswordGenerator& gen)
	{
		_tprintf_s( _T("Number of words in the word list: %d\n"), (int)gen.WordListLen );
	}


	inline void createPwdGenAndPrintItsProperties(std::unique_ptr<IPasswordGenerator>& upGen,
		DWORD pwdGenTypeNo = PWD_GEN_TYPE_NO__BASIC, const Config *cfg = nullptr)
	{
		if (pwdGenTypeNo == PWD_GEN_TYPE_NO__WCP)
		{
			std::unique_ptr<WordChainPasswordGenerator> tempUpGen(nullptr);
			createPwdGen(tempUpGen, cfg);
			printPwdGenProperties( *tempUpGen );
			upGen.reset( tempUpGen.release() );
		}
		else
		{
			std::unique_ptr<PasswordGenerator> tempUpGen(nullptr);
			createPwdGen(tempUpGen, cfg);
			printPwdGenProperties( *tempUpGen );
			upGen.reset( tempUpGen.release() );
		}
	}


	void pwdGenTestCore(const Config *cfg = nullptr)
	{
		std::unique_ptr<IPasswordGenerator> upGen(nullptr);

		DWORD finalPwdGenTypeNo = (cfg)? cfg->SelectedPasswordGenerator : pwdGenTypeNo;

		do {
		outerLoopBegin:
			createPwdGenAndPrintItsProperties(upGen, finalPwdGenTypeNo, cfg);

			do {
			innerLoopBegin:
				TCHAR* result = upGen->Generate();

				_tprintf_s( _T("Generated password:\n") );
				_tprintf_s( _T("%s\n"), result );
				_tprintf_s( _T("\nGenerate another password?\n") );
				_tprintf_s( _T("0: no\n1: yes, with the same generator\n2: yes, with a new generator\n> ") );
				_fgetts(inputBuffer, inputBufferCapacity, stdin);
				_tprintf_s( _T("\n") );

				switch (inputBuffer[0]) {
				case _T('1'):
					goto innerLoopBegin;
				case _T('2'):
					goto outerLoopBegin;
				}
			} while (false);
		} while (false);
	}


	//
	// Tests the password generator class corresponding to pwdGenTypeNo.
	// The password generators will be constructed using the customizable default parameter values specified
	// in the structs inside this namespace.
	//
	int pwdGenTest()
	{
		_tprintf_s( _T("---- pwdGenTest() ----\n\n") );
		pwdGenTestCore();
		_tprintf_s( _T("\n\n") );
		return 0;
	}


	//
	// Tests Config and then the password generator class chosen according to an instance of Config.
	// The password generators will be constructed using the parameters available in the instance of Config.
	//
	int configAndPwdGenComboTest()
	{
		_tprintf_s( _T("---- configAndPwdGenComboTest() ----\n\n") );
		_tprintf_s( _T("--- Config ---\n\n") );
		Config config;
		printConfig(config);
		_tprintf_s( _T("\n\n--- PwdGen ---\n\n") );
		pwdGenTestCore( &config );
		_tprintf_s( _T("\n\n") );
		return 0;
	}
	
} // namespace AdmPwdTestingMain



int main()
{
	using namespace AdmPwdTestingMain;
	int returnVal = 0;
	
	try
	{
		if (!runComboTest)
		{
			if (!returnVal)  returnVal = configTest();
			if (!returnVal)  returnVal = pwdGenTest();
		}
		else  returnVal = configAndPwdGenComboTest();

		int memLeaksWereFound = _CrtDumpMemoryLeaks();
		if (memLeaksWereFound) {
			_tprintf_s( _T("Memory leaks found!\n\n") );
		}
		_tprintf_s( _T("Press Enter/Return to close the test program.\n> ") );
		_fgetts(inputBuffer, inputBufferCapacity, stdin);
	}
	catch (const std::exception &e)
	{
		_tprintf_s( _T("An exception occured. Message:\n%S"), e.what() );
		throw;
	}
	catch (const HRESULT hr)
	{
		_tprintf_s( _T("A HRESULT was thrown. Hex: 0x%lX.\n"), (ULONG)hr );
		throw;
	}

	return returnVal;
}
