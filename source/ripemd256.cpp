//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.4.0.0.1
//
// Copyright � 2009-2010 DiceLock Security, LLC. All rigths reserved.
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

#include "ripemd256.h"


namespace DiceLockSecurity {

  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Ripemd256::hashName = RIPEMD_256;

	// Number of hash bits
	const unsigned short int Ripemd256::hashBits = 256;
	// Number of hash unsigned chars
	const unsigned short int Ripemd256::hashUCs = 32;
	// Number of hash unsigned short ints
	const unsigned short int Ripemd256::hashUSs = 16;
	// Number of hash unsigned long ints
	const unsigned short int Ripemd256::hashULs = 8;

	// Additional initial states of Ripemd 256 algorithm
	const unsigned long int Ripemd256::inistate4 = 0x76543210;
	const unsigned long int Ripemd256::inistate5 = 0xFEDCBA98;
	const unsigned long int Ripemd256::inistate6 = 0x89ABCDEF;
	const unsigned long int Ripemd256::inistate7 = 0x01234567;

	// Constructor
	Ripemd256::Ripemd256() {
	}

	// Destructor
	Ripemd256::~Ripemd256() {
	}

	// Initializes state of Ripmed 256 algorithm
	void Ripemd256::Initialize() {

		this->BaseRipemd::Initialize();
		this->messageDigest->SetULPosition(4, inistate4);
		this->messageDigest->SetULPosition(5, inistate5);
		this->messageDigest->SetULPosition(6, inistate6);
		this->messageDigest->SetULPosition(7, inistate7);
	}

	// Computes the 64 byte chunk of stream information
	void Ripemd256::Compress(unsigned long int* stream) {
		unsigned long int a1 = this->messageDigest->GetULPosition(0);
		unsigned long int b1 = this->messageDigest->GetULPosition(1);
		unsigned long int c1 = this->messageDigest->GetULPosition(2);
		unsigned long int d1 = this->messageDigest->GetULPosition(3);
		unsigned long int a2 = this->messageDigest->GetULPosition(4);
		unsigned long int b2 = this->messageDigest->GetULPosition(5);
		unsigned long int c2 = this->messageDigest->GetULPosition(6);
		unsigned long int d2 = this->messageDigest->GetULPosition(7);
		unsigned long int temp;
		Transform_F0(&a1, &b1, &c1, &d1, stream);
		Transform_I5(&a2, &b2, &c2, &d2, stream);
		temp = a1;
		a1 = a2;
		a2 = temp;
		Transform_G1(&a1, &b1, &c1, &d1, stream);
		Transform_H6(&a2, &b2, &c2, &d2, stream);
		temp = b1;
		b1 = b2;
		b2 = temp;
		Transform_H2(&a1, &b1, &c1, &d1, stream);
		Transform_G7(&a2, &b2, &c2, &d2, stream);
		temp = c1;
		c1 = c2;
		c2 = temp;
		Transform_I3(&a1, &b1, &c1, &d1, stream);
		Transform_F9(&a2, &b2, &c2, &d2, stream);
		temp = d1;
		d1 = d2;
		d2 = temp;
		this->messageDigest->SetULPosition(0, this->messageDigest->GetULPosition(0) + a1);
		this->messageDigest->SetULPosition(1, this->messageDigest->GetULPosition(1) + b1);
		this->messageDigest->SetULPosition(2, this->messageDigest->GetULPosition(2) + c1);
		this->messageDigest->SetULPosition(3, this->messageDigest->GetULPosition(3) + d1);
		this->messageDigest->SetULPosition(4, this->messageDigest->GetULPosition(4) + a2);
		this->messageDigest->SetULPosition(5, this->messageDigest->GetULPosition(5) + b2);
		this->messageDigest->SetULPosition(6, this->messageDigest->GetULPosition(6) + c2);
		this->messageDigest->SetULPosition(7, this->messageDigest->GetULPosition(7) + d2);
	}

	// Gets hash length in bits
	unsigned short int Ripemd256::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Ripemd256::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Ripemd256::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Ripemd256::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets the type of the object
	Hashes Ripemd256::GetType(void) {

		return this->hashName;
	}
  }
}
