
#pragma once

//
// Copyright (C) 2016 IT Services of the University of Turku
//

#include "stdafx.h"

// An interface for password generators.
class IPasswordGenerator
{
public:
	//
	// Generates a new password and returns a pointer to the new password stored inside the object.
	//
	// The password will get wiped from the memory when the destructor of this object is run.
	// If a password has already been generated, the old password will be replaced with the new one,
	// and the use of any remaining pointers to the stored password should be ended.
	//
	virtual TCHAR* Generate() = 0;

	virtual ~IPasswordGenerator() {}
protected:
	inline IPasswordGenerator() {}
private:
	inline IPasswordGenerator(const IPasswordGenerator&) {}  // deleted
	inline IPasswordGenerator& operator= (const IPasswordGenerator&) {}  // deleted

};

