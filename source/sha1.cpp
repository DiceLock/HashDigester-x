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
#include "sha1.h"


#define SHA1_Operation_Ini(f, a, b, c, d, e, temp, j, K)\
	(*temp) = SHA1_RotateLeft((*a), 5) + f((*b), (*c), (*d)) + (*e) + (K) + (messageSchedule[j]);\
	(*e) = (*d);\
	(*d) = (*c);\
	(*c) = SHA1_RotateLeft((*b), 30) ;\
	(*b) = (*a);\
	(*a) = (*temp);

#define SHA1_Operation_Tail(f, a, b, c, d, e, temp, j, K)\
	messageSchedule[j] = (SHA1_RotateLeft(messageSchedule[j-3] ^ messageSchedule[j-8] ^ messageSchedule[j-14] ^ messageSchedule[j-16], 1));\
	(*temp) = SHA1_RotateLeft((*a), 5) + f((*b), (*c), (*d)) + (*e) + (K) + (messageSchedule[j]);\
	(*e) = (*d);\
	(*d) = (*c);\
	(*c) = SHA1_RotateLeft((*b), 30) ;\
	(*b) = (*a);\
	(*a) = (*temp);


namespace DiceLockSecurity {
	
  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Sha1::hashName = SHA_1;

	// Number of hash bits
	const unsigned short int Sha1::hashBits = SHA1_DIGESTBITS;
	// Number of hash unsigned chars
	const unsigned short int Sha1::hashUCs = SHA1_DIGESTUCHARS;
	// Number of hash unsigned short ints
	const unsigned short int Sha1::hashUSs = SHA1_DIGESTUSHORTS;
	// Number of hash unsigned long ints
	const unsigned short int Sha1::hashULs = SHA1_DIGESTULONGS;

	// Number of schedule words
	const unsigned short int Sha1::scheduleNumber = SHA1_MESSAGESCHEDULE;

	// Initial hash values of SHA1 
	const unsigned long int Sha1::initials[SHA1_DIGESTULONGS] = {0x67452301UL, 
																0xefcdab89UL, 
																0x98badcfeUL, 
																0x10325476UL, 
																0xc3d2e1f0UL};

	// Computational constant values of SHA1 
	const unsigned long int Sha1::constants[SHA1_COMPUTECONSTANTS] = {0x5a827999UL, 
																	0x6ed9eba1UL, 
																	0x8f1bbcdcUL, 
																	0xca62c1d6UL};

	// Computes the chunk block of information  
	void Sha1::Compress(BaseCryptoRandomStream* digest, unsigned char* stream) {
		unsigned long int a, b, c, d, e, temp;
		unsigned short int i;

		// Initilizing working variables
		a = digest->GetULPosition(0);
		b = digest->GetULPosition(1);
		c = digest->GetULPosition(2);
		d = digest->GetULPosition(3);
		e = digest->GetULPosition(4);

		for (i = 0; i < this->hashBlockULs; i++) {
			messageSchedule[i] = (stream[i*4] << 24) | (stream[i*4+1] << 16) | (stream[i*4+2] << 8) | (stream[i*4+3]);
		}

		//  0 <= t <= 19
		for (i = 0; i < 16; i++) {
			SHA1_Operation_Ini(BASESHA_32_Ch, &a, &b, &c, &d, &e, &temp, i, this->constants[0]);
		}
		for (i = 16; i < 20; i++) {
			SHA1_Operation_Tail(BASESHA_32_Ch, &a, &b, &c, &d, &e, &temp, i, this->constants[0]);
		}
		// 20 <= t <= 39
		for (i = 20; i < 40; i++) {
			SHA1_Operation_Tail(SHA1_Parity, &a, &b, &c, &d, &e, &temp, i, this->constants[1]);
		}
		// 40 <= t <= 59
		for (i = 40; i < 60; i++) {
			SHA1_Operation_Tail(BASESHA_32_Maj, &a, &b, &c, &d, &e, &temp, i, this->constants[2]);
		}
		// 60 <= t <= 79
		for (i = 60; i < SHA1_OPERATIONS; i++) {
			SHA1_Operation_Tail(SHA1_Parity, &a, &b, &c, &d, &e, &temp, i, this->constants[3]);
		}

		// Upgrading hash values
		digest->SetULPosition(0, digest->GetULPosition(0) + a);
		digest->SetULPosition(1, digest->GetULPosition(1) + b);
		digest->SetULPosition(2, digest->GetULPosition(2) + c);
		digest->SetULPosition(3, digest->GetULPosition(3) + d);
		digest->SetULPosition(4, digest->GetULPosition(4) + e);
	}

	// Constructor, default 
	Sha1::Sha1() {
	}

	// Destructor
	Sha1::~Sha1() {
	}

	// Initializes common states of Sha1 algorithm
	void Sha1::Initialize(void) {

		this->messageDigest->SetULPosition(0, this->initials[0]);
		this->messageDigest->SetULPosition(1, this->initials[1]);
		this->messageDigest->SetULPosition(2, this->initials[2]);
		this->messageDigest->SetULPosition(3, this->initials[3]);
		this->messageDigest->SetULPosition(4, this->initials[4]);
		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Finalizes hash and performs little endian transformation
	void Sha1::Finalize(void) {

		this->BaseSha32::Finalize();
		this->SwapLittleEndian();
	}

	// Gets hash length in bits
	unsigned short int Sha1::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Sha1::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Sha1::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Sha1::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets the type of the object
	Hashes Sha1::GetType(void) {

		return this->hashName;
	}
  }
}