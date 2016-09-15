
#pragma once

//
// Copyright (C) 2016 IT Services of the University of Turku
//
// This file is based on a version of the file "stdafx.h" that
// was created by Jiri Formacek and published under Apache license version 2.0.
//

//
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#include "targetver.h"

#include <sal.h>
#include <windows.h>
#include <objbase.h>
#include <tchar.h>

#include <userenv.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <winerror.h>
#include <sddl.h>

#include <Wincrypt.h>
#include <new.h>

#include <lm.h>
#include <Winldap.h>
#include <WinBer.h>
#include <security.h>


#include <memory>		// for smart pointers
#include <string>

typedef std::basic_string<TCHAR> tstring;
