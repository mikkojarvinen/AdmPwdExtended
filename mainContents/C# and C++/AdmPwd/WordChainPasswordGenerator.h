
#pragma once

//
// Copyright (C) 2016 IT Services of the University of Turku
// 
// This file is based on a version of the file "PasswordGenerator.h" that
// was created by Jiri Formacek and published under Apache license version 2.0.
//

#include "stdafx.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <codecvt>
#include "IPasswordGenerator.h"

//
// Password generator class for generating passwords following the pattern
// <word in uppercase><delimiter>(<word><delimiter>){wordCount-1}[0-9]{numSeqLen}.
//
// Details:
// - Each delimiter is chosen by random from a group of delimiters given as a parameter to the constructor.
// - Each word is chosen by random from a word list so that the same word can appear multiple times in the password.
// - The word list is loaded from the file given as a parameter to the constructor.
// - A valid word may contain only the lower-case letters a-z, and its length must be from 1 to maxValidWordLen, inclusive.
// - The word list contains from 1 up to and including maxWordListLen valid words.
// - wordCount is given as a parameter to the constructor.
// - numSeqLen is max( minNumSeqLen, minPwdLen - (length of password without number sequence) ),
// where minNumSeqLen and minPwdLen are given as parameters to the constructor.
//
class WordChainPasswordGenerator : public IPasswordGenerator
{
private:

	// Length of BOM in TCHARs.
	static const size_t bomTcsLen = (_UNICODE)? 1 : 3;

	//
	// Removes BOM (Byte Order Mark) from the beginning of the string, if present.
	// Returns true iff BOM was found and removed.
	//
	static inline bool RemoveBom(tstring &str)
	{
#ifdef _UNICODE
		const std::wstring bomTcs( L"\uFEFF" );
#else
		const std::string bomTcs( "\xEF\xBB\xBF" );
#endif
		_ASSERT( bomTcsLen == bomTcs.length() );
		
		const bool hasBom = str.compare(0, bomTcsLen, bomTcs) == 0;
		if (hasBom)
		{
			const TCHAR * const origTcsBomlessBegin = str.c_str() + bomTcsLen;
			const size_t newTcsCapacity = str.length() - bomTcsLen + 1;
			std::unique_ptr<TCHAR[]> newTcs( new TCHAR[newTcsCapacity] );

			_tcscpy_s( newTcs.get(), newTcsCapacity, origTcsBomlessBegin );
			str = newTcs.get();
		}
		return hasBom;
	}

public:

	//
	// The maximum valid length of a word in a word list.
	// In characters, excluding the ending null character.
	//
	static const UINT maxValidWordLen = 7;

	//
	// The maximum word list length (the number of words in the list).
	// If the word list file contains more valid words, only the
	// maxValidWordLen first words will be included into the word list.
	//
	static const size_t maxWordListLen = 5000000;

	// The maximum length of the parameter delims given to the constructor, in characters.
	static const size_t maxDelims = 100;

	// The smallest allowed value for the constructor parameter wordCount.
	static const UINT minWordCount = 2;

	// The greatest allowed value for the constructor parameter wordCount.
	static const UINT maxWordCount = 14;

	// The smallest allowed value for the constructor parameter minNumSeqLen.
	static const UINT min_minNumSeqLen = 1;

	// The greatest allowed value for the constructor parameter minNumSeqLen.
	static const UINT max_minNumSeqLen = 15;


	static_assert(maxWordCount * (maxValidWordLen+1) + max_minNumSeqLen <= 127, "_maxPwdLen could be > 127.");
	// Max length for a password that can always be typed in Windows is 127. Max length in AD is 128.


private:

	// The number of words (randomly chosen from the word list) in a password.
	const UINT _wordCount;

	// The minimum number of decimal numbers ('0'..'9') at the end of a password.
	const UINT _minNumSeqLen;
	
	// The minimum length of a password. In characters, excluding the ending null character.
	const UINT _minPwdLen;

	// The maximum length of a password. In characters, excluding the ending null character.
	// The capacity of _pNewPwd is _maxPwdLen + 1.
	const UINT _maxPwdLen;
	
	//
	// List of valid words loaded from a word list file.
	//
	// May contain duplicate words.
	// Each word consists of lower-case ASCII letters (a-z) and has its _tcslen between 1 and maxValidWordLen.
	//
	// When a word is chosen from this list into a password, the word and any pointers or indexes related to the
	// word should be only stored in memory areas that will be securely wiped with the macro SecureZeroMemory.
	// This requirement/aim might not be met in optimized builds as the compiler has the freedom to create
	// additional (temporary) copies. Please note that the word list itself is not considered secret.
	//
	std::vector<TCHAR *> _wordList;

	// The minimum number of words in the word list.
	const UINT _minWordListLen;

	// The length of the array _delimArray.
	UINT _delimArrayLen;

	// An array (NOT a C-string) containing the delimiters to use in a password. May contain duplicates.
	TCHAR *_delimArray;

	// Handle to a key container within a cryptocraphic service provider. Used for generating pseudo random numbers.
	HCRYPTPROV _hProv;

	// The current generated password. Use SecureZeroMemory before deleting.
	TCHAR *_pNewPwd;




	// Is the word valid for being in the word list?
	inline bool IsValidWord(const tstring &word)
	{
		const size_t len = word.length();
		if ( len <= 0  ||  len > maxValidWordLen )  return false;

		for (size_t i = 0;  i < len;  ++i) {
			const TCHAR &currChar = word[i];
			if ( currChar < _T('a')  ||  currChar > _T('z') )  return false;
		}
		return true;
	}


	// Load the word list.
	void LoadWordList(const TCHAR *filename)
	{
		if (!filename)  throw HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS);

		try {
			// Read the file assuming UTF-8 encoding (only ASCII-characters will be accepted in the words).
			// Process lines (word candidates) using default encoding (uses TCHAR).
			// We will not use std::ifstream::imbue(), because we want to have full control over supported line
			// terminators and handling of errors related to invalid UTF-8 (treating invalid UTF-8 as EOF is not ok).

			static_assert( std::is_same<TCHAR, wchar_t>::value, "char as TCHAR currently not supported." );
			typedef std::codecvt_utf8_utf16<TCHAR> facet_t;			// UTF-8 -> UTF-16
			const facet_t facet(1);									// 1 to disable auto-delete
			std::mbstate_t facetState = std::mbstate_t();
			const char *facetSrcNext;
			TCHAR *facetDstNext;

#ifndef _DEBUG
			const size_t firstBuffSize = 128;
#else
			const size_t firstBuffSize = 31;		// More efficient debugging but likely slower performance.
#endif
			// All the data from the file will go through this buffer used for parsing the data into lines.
			char firstBuff[firstBuffSize];

			const size_t tcsBuffSize = maxValidWordLen + 1 + bomTcsLen;  // Reserve space for null character and BOM.
			TCHAR tcsBuff[tcsBuffSize];		// Target buffer for translations with the facet.

			typedef std::ifstream ifs_t;
			ifs_t ifs(filename, std::ios::in | std::ios::binary);
			if ( ifs.fail() )  throw HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

			// The buffer after firstBuff. Contains the currently read part of the current line, excluding line termination.
			std::string line;

			bool isFirstLine = true;
			UINT lineState = 0;		// 0: completed;  1: mid-line;  2: terminator started ('\r' encountered)
			ptrdiff_t firstBuffCopyBeginInd = firstBuffSize;
			ptrdiff_t firstBuffCopyEndInd;
			ptrdiff_t firstBuffNextCopyBeginInd;
			ptrdiff_t firstBuffDataEndInd = 0;
			do
			{
				const bool copyFromFirstBuff = (lineState != 2);

				// If firstBuff is empty, read more data from the file to the buffer.
				if (firstBuffCopyBeginInd >= firstBuffDataEndInd)
				{
					firstBuffCopyBeginInd = 0;
					if ( ifs.eof() )
					{
						if (lineState == 0)		// The file ended with '\n'. The last non-empty line
							break;				// has been processed, we may stop now.
						else
						{	// Terminate the current line and process it. '\r' might already have been read.
							firstBuff[0] = '\n';
							firstBuffDataEndInd = 1;
						}
					}
					else
					{
						ifs.read(firstBuff, firstBuffSize);
						if ( ifs.bad() || (ifs.fail() && !ifs.eof()) )
							throw HRESULT_FROM_WIN32(ERROR_UNIDENTIFIED_ERROR);		// Error while reading file.

						firstBuffDataEndInd = (ptrdiff_t)ifs.gcount();
					}
				}

				if (lineState == 0)  lineState = 1;					// Start reading a new line.
				// For when firstBuff ends before the current line (including terminator):
				firstBuffCopyEndInd = firstBuffDataEndInd;
				firstBuffNextCopyBeginInd = firstBuffDataEndInd;

				for (	ptrdiff_t currFirstBuffInd = firstBuffCopyBeginInd;
						currFirstBuffInd < firstBuffDataEndInd && lineState != 0;
						++currFirstBuffInd   )
				{
					const char &currChar = firstBuff[currFirstBuffInd];

					if (lineState == 2)
					{
						firstBuffNextCopyBeginInd = currFirstBuffInd + (ptrdiff_t)(currChar == '\n');  // "\r" or "\r\n"
						lineState = 0;
					}
					else if (currChar == '\n')
					{
						firstBuffCopyEndInd = currFirstBuffInd;
						firstBuffNextCopyBeginInd = currFirstBuffInd + 1;
						lineState = 0;
					}
					else if (currChar == '\r')		// "\r" or "\r\n"
					{
						firstBuffCopyEndInd = currFirstBuffInd;
						lineState = 2;
					}
				} // for

				if (copyFromFirstBuff)
				{
					const char * const firstBuffCopyBegin = firstBuff + firstBuffCopyBeginInd;
					const char * const firstBuffCopyEnd = firstBuff + firstBuffCopyEndInd;
					line.append(firstBuffCopyBegin, firstBuffCopyEnd);
				}

				firstBuffCopyBeginInd = firstBuffNextCopyBeginInd;

				if (lineState == 0)		// Line read completely. Accept or reject it as a word.
				{
					{
						const size_t lineLen = line.length();
						if (lineLen >= tcsBuffSize)  goto clearLine;  // Skip invalid words (tcsBuffSize > maxValidWordLen + 1).

						const char * const lineCStr = line.c_str();
						// Copy line with UTF-8 -> UTF-16 translation to tcsBuff with terminating null character:
						facet_t::result facetResult = facet.in(facetState,
							lineCStr, lineCStr + lineLen + 1, facetSrcNext,
							tcsBuff, tcsBuff + lineLen + 1, facetDstNext);

						if ( facetResult != facet_t::ok)
						{	// Treat the line as an invalid word to skip. Reset the facet state.
							std::memset (&facetState, 0, sizeof(facetState));
							goto clearLine;
						}

						tstring tstringLine(tcsBuff);

						if (isFirstLine)
						{
							RemoveBom(tstringLine);
							isFirstLine = false;
						}

						if ( !IsValidWord(tstringLine) )  goto clearLine;  // Skip invalid words.

						size_t wordLen = line.length();
						_wordList.reserve( _wordList.size() + 1 );  // Ensure push_back will never throw bad_alloc.
						TCHAR *tcWord = new TCHAR[wordLen + 1];
						_wordList.push_back(tcWord);
						_tcscpy_s( tcWord, wordLen + 1, tstringLine.c_str() );
					}

				clearLine:
					line.clear();
				} // if (lineState == 0)

			}
			while (_wordList.size() < maxWordListLen);

			if (_wordList.size() < _minWordListLen)  throw HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS);

			ifs.close();
		}
		catch (std::bad_alloc&) {
			throw HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		}
		catch (std::exception&) {
			throw HRESULT_FROM_WIN32(ERROR_UNIDENTIFIED_ERROR);
		}
	} // LoadWordList()




public:

	//
	// Initializes a new instance of WordChainPasswordGenerator.
	// 
	// minPwdLen: The minimum length of a password.
	// wordCount: The number of words (randomly chosen from the word list) in a password.
	//		Must be >= minWordCount and <= maxWordCount.
	// minNumSeqLen: The minimum and default number of decimal numbers ('0'..'9') at the end of a password.
	//		Must be >= min_minNumSeqLen and <= max_minNumSeqLen.
	// wordListFilename: The file from which the word list will be read.
	//		- The file must be in UTF-8 format (with or without BOM).
	//		- Each line in the file is interpreted as a single word. Both Windows-style (CR+LF) and Unix-style (LF)
	//		line terminators are supported. Other line terminators in the Unicode standard (VT, FF, CR, NEL, LS and PS)
	//		might or might not be considered as line terminators.
	//		- A valid word may contain only the lower-case letters a-z, and its length must be >= 1 and <= maxValidWordLen.
	//		- Invalid words in the word list file will be skipped; they will not be included into the word list.
	//		- The word list file must contain at least minWordListLen valid words.
	//		- The word list cannot contain more than maxWordListLen words. After this many valid words has been read from
	//		the file, the rest of the file will be ignored.
	//		- The word list may contain duplicate words.
	//		- The constructed object will not be dependent on the memory contents pointed to by this parameter.
	// delims: The set of delimiters to be used after words.
	//		A null-terminated C-string consisting of ASCII characters from the interval [TEXT(' '), TEXT('~')]
	//		(i.e. [TEXT('\u0020'), TEXT('\u007E')]). If the parameter is nullptr, the string is empty or longer than
	//		maxDelims, or the string contains invalid characters, HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS) is thrown.
	//		It is recommended that each character in the string occurs in it only once. The probability of a certain
	//		delimiter character getting chosen from the string is (approximately) proportional to the number of occurences
	//		in the string.
	//		The constructed object will not be dependent on the memory contents pointed to by this parameter.
	// minWordListLen: The minimum number of words in the word list.
	//		Note that this does not inevitably limit the number of unique words in the word list.
	//		Must be positive.
	//
	WordChainPasswordGenerator(UINT minPwdLen, UINT wordCount, UINT minNumSeqLen, const TCHAR *wordListFilename,
		const TCHAR *delims, UINT minWordListLen) :
		_wordCount(wordCount), _minNumSeqLen(minNumSeqLen), _minPwdLen(minPwdLen),
		_maxPwdLen(   max(  minPwdLen,
			wordCount * (maxValidWordLen+1) + minNumSeqLen  )   ),
		_wordList(), _minWordListLen(minWordListLen), _delimArrayLen(0), _delimArray(nullptr), _hProv(0), _pNewPwd(nullptr)
	{
		_ASSERT(minWordCount <= wordCount && wordCount <= maxWordCount);
		_ASSERT(min_minNumSeqLen <= minNumSeqLen && minNumSeqLen <= max_minNumSeqLen);
		_ASSERT(minWordListLen > 0);

		LoadWordList(wordListFilename);

		// Init _delimArrayLen and _delimArray:
		if (delims == nullptr)
			throw HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS);
		_delimArrayLen = (UINT)_tcslen(delims);
		if (_delimArrayLen == 0)
			throw HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS);
		_delimArray = new(std::nothrow) TCHAR[_delimArrayLen];
		if (_delimArray == nullptr)
			throw HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);

		for (size_t i = 0; i < _delimArrayLen; ++i) {
			const TCHAR &currChar = delims[i];
			if (currChar < _T(' ') || currChar > _T('~'))
				throw HRESULT_FROM_WIN32(ERROR_BAD_ARGUMENTS);
			_delimArray[i] = currChar;
		}

		// Init _hProv:
		if (!CryptAcquireContext(&_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			throw HRESULT_FROM_WIN32(GetLastError());

		_pNewPwd = new(std::nothrow) TCHAR[_maxPwdLen + 1]();	// Init with null characters
		if (_pNewPwd == nullptr)
			throw HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
	}


	~WordChainPasswordGenerator()
	{
		if (_pNewPwd != nullptr) {
			SecureZeroMemory( _pNewPwd,  (_maxPwdLen + 1) * sizeof(TCHAR) );
			delete[] _pNewPwd;
		}
		if (_hProv != 0)
			CryptReleaseContext(_hProv, 0);

		delete[] _delimArray;

		size_t wordListSize = _wordList.size();
		for (size_t i = 0; i < wordListSize; ++i) {
			delete[] _wordList[i];
		}
	}


	// See IPasswordGenerator::Generate().
	TCHAR* Generate()
	{
		// The difference of an ASCII lowercase letter and its uppercase counterpart.
		const INT lcMinusUc = (INT)(_T('a')) - (INT)(_T('A'));
		const UINT wordListSize = (UINT)_wordList.size();
		UINT nRandom;						// Wipe with SecureZeroMemory.
		TCHAR currChar;						// Wipe with SecureZeroMemory.
		TCHAR *wordIter;					// Wipe with SecureZeroMemory (only the pointer itself).
		TCHAR *pNewPwdIter = _pNewPwd;		// Wipe with SecureZeroMemory (only the pointer itself).
		TCHAR *pNewPwdEnd;					// Wipe with SecureZeroMemory (only the pointer itself).
		// The end of a minimum length password (the cell with the terminating null character).
		TCHAR * const pNewPwdMinEnd = _pNewPwd + _minPwdLen;


		// Write _wordCount random words (each followed by one delimiter character) into the password.
		for (size_t w = 0; w < _wordCount; ++w)
		{
			nRandom = 0;
			CryptGenRandom(_hProv, sizeof(nRandom), (LPBYTE)&nRandom);
			nRandom %= wordListSize;
			wordIter = _wordList[nRandom];

			// Write the word.
			while ( (currChar = *wordIter++) != _T('\0') )
			{
				if (w == 0)		// First word; write in uppercase.
				{	
					currChar -= lcMinusUc;		// Convert lowercase ASCII letter into uppercase.
				}
				*pNewPwdIter++ = currChar;
			}

			// Write a random delimiter character.
			nRandom = 0;
			CryptGenRandom(_hProv, sizeof(nRandom), (LPBYTE)&nRandom);
			nRandom %= _delimArrayLen;
			*pNewPwdIter++ = _delimArray[nRandom];
		}

		// Write at least _minNumSeqLen decimal numbers to the end of the password.
		pNewPwdEnd = pNewPwdIter + _minNumSeqLen;
		if (pNewPwdEnd < pNewPwdMinEnd)  pNewPwdEnd = pNewPwdMinEnd;

		do
		{
			nRandom = 0;
			CryptGenRandom(_hProv, sizeof(nRandom), (LPBYTE)&nRandom);
			nRandom %= 10;
			currChar = (TCHAR)((UINT)(_T('0')) + nRandom);	// _T('0') .. _T('9')
			*pNewPwdIter++ = currChar;
		}
		while (pNewPwdIter < pNewPwdEnd);

		*pNewPwdIter = _T('\0');	// End with a null character.


		SecureZeroMemory(&pNewPwdEnd, sizeof(pNewPwdEnd));
		SecureZeroMemory(&pNewPwdIter, sizeof(pNewPwdIter));
		SecureZeroMemory(&wordIter, sizeof(wordIter));
		SecureZeroMemory(&currChar, sizeof(currChar));
		SecureZeroMemory(&nRandom, sizeof(nRandom));
		
		return _pNewPwd;
	} // Generate()


	// The number of words in the word list. The number includes duplicate words.
	__declspec(property(get = GET_WordListLen)) size_t WordListLen;
	// Get the number of words in the word list. The number includes duplicate words.
	inline size_t GET_WordListLen() const {
		return _wordList.size();
	}

};
