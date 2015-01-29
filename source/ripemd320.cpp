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
#include "ripemd320.h"


namespace DiceLockSecurity {
	
  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Ripemd320::hashName = RIPEMD_320;
	
	// Number of hash bits
	const unsigned short int Ripemd320::hashBits = 320;
	// Number of hash unsigned chars
	const unsigned short int Ripemd320::hashUCs = 40;
	// Number of hash unsigned short ints
	const unsigned short int Ripemd320::hashUSs = 20;
	// Number of hash unsigned long ints
	const unsigned short int Ripemd320::hashULs = 10;

	// Additional initial states of Ripemd 320 algorithm
	const unsigned long int Ripemd320::inistate5 = 0x76543210;
	const unsigned long int Ripemd320::inistate6 = 0xFEDCBA98;
	const unsigned long int Ripemd320::inistate7 = 0x89ABCDEF;
	const unsigned long int Ripemd320::inistate8 = 0x01234567;
	const unsigned long int Ripemd320::inistate9 = 0x3C2D1E0F;

	// Constructor
	Ripemd320::Ripemd320() {
	}

	// Destructor
	Ripemd320::~Ripemd320() {
	}

	// Initializes state of Ripmed 256 algorithm
	void Ripemd320::Initialize() {

		this->BaseRipemd160X::Initialize();
		this->messageDigest->SetULPosition(5, inistate5);
		this->messageDigest->SetULPosition(6, inistate6);
		this->messageDigest->SetULPosition(7, inistate7);
		this->messageDigest->SetULPosition(8, inistate8);
		this->messageDigest->SetULPosition(9, inistate9);
	}

	// Computes the 64 byte chunk of stream information 
	void Ripemd320::Compress(unsigned long int* stream) {
		unsigned long int a1 = this->messageDigest->GetULPosition(0);
		unsigned long int b1 = this->messageDigest->GetULPosition(1); 
		unsigned long int c1 = this->messageDigest->GetULPosition(2); 
		unsigned long int d1 = this->messageDigest->GetULPosition(3); 
		unsigned long int e1 = this->messageDigest->GetULPosition(4); 
		unsigned long int a2 = this->messageDigest->GetULPosition(5);
		unsigned long int b2 = this->messageDigest->GetULPosition(6);
		unsigned long int c2 = this->messageDigest->GetULPosition(7);
		unsigned long int d2 = this->messageDigest->GetULPosition(8);
		unsigned long int e2 = this->messageDigest->GetULPosition(9); 
		unsigned long int temp;
		Transform_F0(&a1, &b1, &c1, &d1, &e1, stream);
		Transform_J5(&a2, &b2, &c2, &d2, &e2, stream);
		temp = a1;
		a1 = a2;
		a2 = temp;
		Transform_G1(&a1, &b1, &c1, &d1, &e1, stream);
		Transform_I6(&a2, &b2, &c2, &d2, &e2, stream);
		temp = b1;
		b1 = b2;
		b2 = temp;
		Transform_H2(&a1, &b1, &c1, &d1, &e1, stream);
		Transform_H7(&a2, &b2, &c2, &d2, &e2, stream);
		temp = c1;
		c1 = c2;
		c2 = temp;
		Transform_I3(&a1, &b1, &c1, &d1, &e1, stream);
		Transform_G8(&a2, &b2, &c2, &d2, &e2, stream);
		temp = d1;
		d1 = d2;
		d2 = temp;
		Transform_J4(&a1, &b1, &c1, &d1, &e1, stream);
		Transform_F9(&a2, &b2, &c2, &d2, &e2, stream);
		temp = e1;
		e1 = e2;
		e2 = temp;
		this->messageDigest->SetULPosition(0, this->messageDigest->GetULPosition(0) + a1);
		this->messageDigest->SetULPosition(1, this->messageDigest->GetULPosition(1) + b1);
		this->messageDigest->SetULPosition(2, this->messageDigest->GetULPosition(2) + c1);
		this->messageDigest->SetULPosition(3, this->messageDigest->GetULPosition(3) + d1);
		this->messageDigest->SetULPosition(4, this->messageDigest->GetULPosition(4) + e1);
		this->messageDigest->SetULPosition(5, this->messageDigest->GetULPosition(5) + a2);
		this->messageDigest->SetULPosition(6, this->messageDigest->GetULPosition(6) + b2);
		this->messageDigest->SetULPosition(7, this->messageDigest->GetULPosition(7) + c2);
		this->messageDigest->SetULPosition(8, this->messageDigest->GetULPosition(8) + d2);
		this->messageDigest->SetULPosition(9, this->messageDigest->GetULPosition(9) + e2);
	}

	// Gets hash length in bits
	unsigned short int Ripemd320::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Ripemd320::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Ripemd320::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Ripemd320::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets the type of the object
	Hashes Ripemd320::GetType(void) {

		return this->hashName;
	}
  }
}
