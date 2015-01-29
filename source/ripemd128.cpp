//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.5.0.0.1
//
// Copyright 2009-2011 DiceLock Security, LLC. All rights reserved.
//
//                               DISCLAIMER
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// DICELOCK IS A REGISTERED TRADEMARK OR TRADEMARK OF THE OWNERS.
// 

#include <memory.h>
#include "ripemd128.h"
#include <stdio.h>

namespace DiceLockSecurity {
	
  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Ripemd128::hashName = RIPEMD_128;
	
	// Number of hash bits
	const unsigned short int Ripemd128::hashBits = 128;
	// Number of hash unsigned chars
	const unsigned short int Ripemd128::hashUCs = 16;
	// Number of hash unsigned short ints
	const unsigned short int Ripemd128::hashUSs = 8;
	// Number of hash unsigned long ints
	const unsigned short int Ripemd128::hashULs = 4;

	// Constructor
	Ripemd128::Ripemd128() {
	}

	// Destructor
	Ripemd128::~Ripemd128() {

		this->remainingBytesLength = 0;
		this->messageByteLengthHigh = 0;
		this->messageByteLengthLow = 0;
	}

	// Computes the 64 byte chunk of stream information 
	void Ripemd128::Compress(unsigned long int* stream) {
		unsigned long int a1 = this->messageDigest->GetULPosition(0), a2 = this->messageDigest->GetULPosition(0);
		unsigned long int b1 = this->messageDigest->GetULPosition(1), b2 = this->messageDigest->GetULPosition(1);
		unsigned long int c1 = this->messageDigest->GetULPosition(2), c2 = this->messageDigest->GetULPosition(2);
		unsigned long int d1 = this->messageDigest->GetULPosition(3), d2 = this->messageDigest->GetULPosition(3);

		Transform_F0(&a1, &b1, &c1, &d1, stream);
		Transform_G1(&a1, &b1, &c1, &d1, stream);
		Transform_H2(&a1, &b1, &c1, &d1, stream);
		Transform_I3(&a1, &b1, &c1, &d1, stream);
		Transform_I5(&a2, &b2, &c2, &d2, stream);
		Transform_H6(&a2, &b2, &c2, &d2, stream);
		Transform_G7(&a2, &b2, &c2, &d2, stream);
		Transform_F9(&a2, &b2, &c2, &d2, stream);
		d2 += c1 + this->messageDigest->GetULPosition(1);
		this->messageDigest->SetULPosition(1, this->messageDigest->GetULPosition(2) + d1 + a2);
		this->messageDigest->SetULPosition(2, this->messageDigest->GetULPosition(3) + a1 + b2);
		this->messageDigest->SetULPosition(3, this->messageDigest->GetULPosition(0) + b1 + c2);
		this->messageDigest->SetULPosition(0, d2);
	}

	// Gets hash length in bits
	unsigned short int Ripemd128::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Ripemd128::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Ripemd128::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Ripemd128::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets the type of the object
	Hashes Ripemd128::GetType(void) {

		return this->hashName;
	}
  }
}
