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
#include "sha256.h"
#include <stdio.h>

#define SHA256_Operation_Ini(a, b, c, d, e, f, g, h, temp1, temp2, j)\
	(*temp1) = (*h) + SHA256_SUM_1((*e)) + BASESHA_32_Ch((*e), (*f), (*g)) + (this->constants[j]) + (messageSchedule[j]);\
	(*temp2) = SHA256_SUM_0((*a)) + BASESHA_32_Maj((*a), (*b), (*c));\
	(*h) = (*g);\
	(*g) = (*f);\
	(*f) = (*e);\
	(*e) = (*d) + (*temp1);\
	(*d) = (*c);\
	(*c) = (*b);\
	(*b) = (*a);\
	(*a) = ((*temp1) + (*temp2));

#define SHA256_Operation_Tail(a, b, c, d, e, f, g, h, temp1, temp2, j)\
	messageSchedule[j] = (SHA256_SIG_1(messageSchedule[j-2]) + messageSchedule[j-7] + SHA256_SIG_0(messageSchedule[j-15]) + messageSchedule[j-16]);\
	(*temp1) = (*h) + SHA256_SUM_1((*e)) + BASESHA_32_Ch((*e), (*f), (*g)) + (this->constants[j]) + (messageSchedule[j]);\
	(*temp2) = SHA256_SUM_0((*a)) + BASESHA_32_Maj((*a), (*b), (*c));\
	(*h) = (*g);\
	(*g) = (*f);\
	(*f) = (*e);\
	(*e) = (*d) + (*temp1);\
	(*d) = (*c);\
	(*c) = (*b);\
	(*b) = (*a);\
	(*a) = ((*temp1) + (*temp2));


namespace DiceLockSecurity {
	
  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Sha256::hashName = SHA_256;

	// Number of hash bits
	const unsigned short int Sha256::hashBits = SHA256_DIGESTBITS;
	// Number of hash unsigned chars
	const unsigned short int Sha256::hashUCs = SHA256_DIGESTUCHARS;
	// Number of hash unsigned short ints
	const unsigned short int Sha256::hashUSs = SHA256_DIGESTUSHORTS;
	// Number of hash unsigned long ints
	const unsigned short int Sha256::hashULs = SHA256_DIGESTULONGS;

	// Number of schedule words
	const unsigned short int Sha256::scheduleNumber = SHA256_MESSAGESCHEDULE;

	// Initial hash values of SHA1 
	const unsigned long int Sha256::initials[SHA256_DIGESTULONGS] = {0x6a09e667UL, 
																	 0xbb67ae85UL, 
																	 0x3c6ef372UL, 
																	 0xa54ff53aUL, 
																	 0x510e527fUL, 
																	 0x9b05688cUL, 
																	 0x1f83d9abUL, 
																	 0x5be0cd19UL};

	// Computational constant values of SHA1 
	const unsigned long int Sha256::constants[SHA256_COMPUTECONSTANTS] = 
		{0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
		 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 
		 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 
		 0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL, 
		 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 
		 0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 
		 0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL, 
		 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

	// Computes the chunk block of information  
	void Sha256::Compress(BaseCryptoRandomStream* digest, unsigned char* stream) {
		unsigned long int a, b, c, d, e, f, g, h, temp1, temp2;
		unsigned short int i;

		// Initilizing working variables
		a = digest->GetULPosition(0);
		b = digest->GetULPosition(1);
		c = digest->GetULPosition(2);
		d = digest->GetULPosition(3);
		e = digest->GetULPosition(4);
		f = digest->GetULPosition(5);
		g = digest->GetULPosition(6);
		h = digest->GetULPosition(7);

		for (i = 0; i < this->hashBlockULs; i++) {
			messageSchedule[i] = (stream[i*4] << 24) | (stream[i*4+1] << 16) | (stream[i*4+2] << 8) | (stream[i*4+3]);
		}

		//  0 <= t <= 19
		for (i = 0; i < 16; i++) {
			SHA256_Operation_Ini(&a, &b, &c, &d, &e, &f, &g, &h, &temp1, &temp2, i);
		}
		// 16 <= t <= 63
		for (i = 16; i < SHA256_OPERATIONS; i++) {
			SHA256_Operation_Tail(&a, &b, &c, &d, &e, &f, &g, &h, &temp1, &temp2, i);
		}

		// Upgrading hash values
		digest->SetULPosition(0, digest->GetULPosition(0) + a);
		digest->SetULPosition(1, digest->GetULPosition(1) + b);
		digest->SetULPosition(2, digest->GetULPosition(2) + c);
		digest->SetULPosition(3, digest->GetULPosition(3) + d);
		digest->SetULPosition(4, digest->GetULPosition(4) + e);
		digest->SetULPosition(5, digest->GetULPosition(5) + f);
		digest->SetULPosition(6, digest->GetULPosition(6) + g);
		digest->SetULPosition(7, digest->GetULPosition(7) + h);
	}

	// Constructor, default 
	Sha256::Sha256() {
	}

	// Destructor
	Sha256::~Sha256() {
	}

	// Initializes common states of Sha256 algorithm
	void Sha256::Initialize(void) {

		this->messageDigest->SetULPosition(0, this->initials[0]);
		this->messageDigest->SetULPosition(1, this->initials[1]);
		this->messageDigest->SetULPosition(2, this->initials[2]);
		this->messageDigest->SetULPosition(3, this->initials[3]);
		this->messageDigest->SetULPosition(4, this->initials[4]);
		this->messageDigest->SetULPosition(5, this->initials[5]);
		this->messageDigest->SetULPosition(6, this->initials[6]);
		this->messageDigest->SetULPosition(7, this->initials[7]);
		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Finalizes hash and performs little endian transformation
	void Sha256::Finalize(void) {

		this->BaseSha32::Finalize();
		this->SwapLittleEndian();
	}

	// Gets hash length in bits
	unsigned short int Sha256::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Sha256::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Sha256::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Sha256::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets the type of the object
	Hashes Sha256::GetType(void) {

		return this->hashName;
	}
  }
}
