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

#include <stdlib.h>
#include "sha512.h"


#define SHA512_Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define SHA512_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA512_Operation_Ini(a, b, c, d, e, f, g, h, temp1, temp2, j)\
	(*temp1) = (*h) + SHA512_SUM_1((*e)) + SHA512_Ch((*e), (*f), (*g)) + (this->constants[j]) + (messageSchedule[j]);\
	(*temp2) = SHA512_SUM_0((*a)) + SHA512_Maj((*a), (*b), (*c));\
	(*h) = (*g);\
	(*g) = (*f);\
	(*f) = (*e);\
	(*e) = (*d) + (*temp1);\
	(*d) = (*c);\
	(*c) = (*b);\
	(*b) = (*a);\
	(*a) = ((*temp1) + (*temp2));

#define SHA512_Operation_Tail(a, b, c, d, e, f, g, h, temp1, temp2, j)\
	messageSchedule[j] = (SHA512_SIG_1(messageSchedule[j-2]) + messageSchedule[j-7] + SHA512_SIG_0(messageSchedule[j-15]) + messageSchedule[j-16]);\
	(*temp1) = (*h) + SHA512_SUM_1((*e)) + SHA512_Ch((*e), (*f), (*g)) + (this->constants[j]) + (messageSchedule[j]);\
	(*temp2) = SHA512_SUM_0((*a)) + SHA512_Maj((*a), (*b), (*c));\
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
	const Hashes Sha512::hashName = SHA_512;

	// Number of hash bits
	const unsigned short int Sha512::hashBits = SHA512_DIGESTBITS;
	// Number of hash unsigned chars
	const unsigned short int Sha512::hashUCs = SHA512_DIGESTUCHARS;
	// Number of hash unsigned short ints
	const unsigned short int Sha512::hashUSs = SHA512_DIGESTUSHORTS;
	// Number of hash unsigned long ints
	const unsigned short int Sha512::hashULs = SHA512_DIGESTULONGS;
	// Number of hash unsigned 64 bits
	const unsigned short int Sha512::hash64s = SHA512_DIGESTULG64S;

		// Number of data bits to compute hash
	const unsigned short int Sha512::dataHashBits = SHA512_DATABITS;
	// Number of data unsigned chars to compute hash
	const unsigned short int Sha512::dataHashUCs = SHA512_DATAUCHARS;
	// Number of data unsigned long integers to compute hash
	const unsigned short int Sha512::dataHashULs = SHA512_DATAULONGS;
	// Number of data unsigned long integers to compute hash
	const unsigned short int Sha512::dataHash64s = SHA512_DATAULG64S;

	// Equation modulo constant value
	const unsigned short int Sha512::equationModulo = SHA512_EQUATIONMODULO;

	// Number of schedule words
	const unsigned short int Sha512::scheduleNumber = SHA512_MESSAGESCHEDULE;

	// Initial hash values of SHA1
	const unsigned long long int Sha512::initials[SHA512_DIGESTULONGS] =
			{0x6a09e667f3bcc908,
             0xbb67ae8584caa73b,
             0x3c6ef372fe94f82b,
             0xa54ff53a5f1d36f1,
             0x510e527fade682d1,
             0x9b05688c2b3e6c1f,
             0x1f83d9abfb41bd6b,
			 0x5be0cd19137e2179};

	// Computational constant values of SHA1
	const unsigned long long int Sha512::constants[SHA512_COMPUTECONSTANTS] =
			 {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
              0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
              0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
              0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
              0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
              0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
              0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
              0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
              0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
              0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
              0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
              0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
              0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
              0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
              0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
              0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

	// Gets the number of unsigned chars in the hash block to be hashed
	unsigned short int Sha512::GetDataHashUCs(void) {

		return this->dataHashUCs;
	}

	// Adds messaage length processed, if it is greater than unsigned long makes use
	// of another usigned long to store overflow
	void Sha512::AddMessageLength(unsigned long int byteLength) {

		if ((this->messageBitLengthLow + (byteLength * BYTEBITS)) < this->messageBitLengthLow)
			// add overflow of unsigned long
			this->messageBitLengthHigh++;
		this->messageBitLengthLow += (byteLength  * BYTEBITS);
	}

	// Computes the chunk block of information
	void Sha512::Compress(BaseCryptoRandomStream* digest, unsigned char* stream) {
		unsigned long long int a, b, c, d, e, f, g, h, temp1, temp2;
		unsigned short int i;

		// Initilizing working variables
		a = digest->Get64Position(0);
		b = digest->Get64Position(1);
		c = digest->Get64Position(2);
		d = digest->Get64Position(3);
		e = digest->Get64Position(4);
		f = digest->Get64Position(5);
		g = digest->Get64Position(6);
		h = digest->Get64Position(7);

		for (i = 0; i < this->dataHash64s; i++) {
			messageSchedule[i] = (((unsigned long long int )stream[i*8]) << 56) | (((unsigned long long int )stream[i*8+1]) << 48)
							   | (((unsigned long long int )stream[i*8+2]) << 40) | (((unsigned long long int )stream[i*8+3]) << 32)
							   | (((unsigned long long int )stream[i*8+4]) << 24) | (((unsigned long long int )stream[i*8+5]) << 16)
							   | (((unsigned long long int )stream[i*8+6]) << 8) | (((unsigned long long int )stream[i*8+7]));
		}

		//  0 <= t <= 19
		for (i = 0; i < 16; i++) {
			SHA512_Operation_Ini(&a, &b, &c, &d, &e, &f, &g, &h, &temp1, &temp2, i);
		}
		// 16 <= t <= 79
		for (i = 16; i < SHA512_OPERATIONS; i++) {
			SHA512_Operation_Tail(&a, &b, &c, &d, &e, &f, &g, &h, &temp1, &temp2, i);
		}

		// Upgrading hash values
		digest->Set64Position(0, digest->Get64Position(0) + a);
		digest->Set64Position(1, digest->Get64Position(1) + b);
		digest->Set64Position(2, digest->Get64Position(2) + c);
		digest->Set64Position(3, digest->Get64Position(3) + d);
		digest->Set64Position(4, digest->Get64Position(4) + e);
		digest->Set64Position(5, digest->Get64Position(5) + f);
		digest->Set64Position(6, digest->Get64Position(6) + g);
		digest->Set64Position(7, digest->Get64Position(7) + h);

	}

	// Constructor, default
	Sha512::Sha512() {
	}

	// Destructor
	Sha512::~Sha512() {
	}

	// Initializes common states of Sha1 algorithm
	void Sha512::Initialize(void) {

		this->messageDigest->Set64Position(0, this->initials[0]);
		this->messageDigest->Set64Position(1, this->initials[1]);
		this->messageDigest->Set64Position(2, this->initials[2]);
		this->messageDigest->Set64Position(3, this->initials[3]);
		this->messageDigest->Set64Position(4, this->initials[4]);
		this->messageDigest->Set64Position(5, this->initials[5]);
		this->messageDigest->Set64Position(6, this->initials[6]);
		this->messageDigest->Set64Position(7, this->initials[7]);
		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Adds the BaseCryptoRandomStream to the hash
	void Sha512::Add(BaseCryptoRandomStream* stream) {
		unsigned long int startStreamByte = 0, processBytes = 0;
		long int numBytes = 0;

		// If bytes left from previous added stream, then they will be processed now with added data from new stream
		if (this->remainingBytesLength) {
			if ((this->remainingBytesLength + stream->GetUCLength()) > ((unsigned long int)this->GetDataHashUCs() - 1)) {
				// Setting the point to start the current stream processed
				startStreamByte = this->GetDataHashUCs() - this->remainingBytesLength;
				processBytes = stream->GetUCLength() - (this->GetDataHashUCs() - this->remainingBytesLength);

				memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(0), this->GetDataHashUCs() - this->remainingBytesLength);
				// Process remaining bytes of previous streams adn 64 byte padding of current stream
				this->Compress(this->messageDigest, this->remainingBytes);
				// Updating message byt length processed
				this->AddMessageLength(this->GetDataHashUCs());
				// Remaining bytes of previous strema set to 0
				this->remainingBytesLength = 0;
			}
			else {
				processBytes = stream->GetUCLength();
			}
		}
		else {
			processBytes = stream->GetUCLength();
			startStreamByte = 0;
		}

		for (numBytes = 0; processBytes > ((unsigned long int)this->GetDataHashUCs() - 1); numBytes += this->GetDataHashUCs()) {
			// Process the chunk
			this->Compress(this->messageDigest, stream->GetUCAddressPosition(startStreamByte + numBytes));
			// Updating message byt length processed
			this->AddMessageLength(this->GetDataHashUCs());
			processBytes -= this->GetDataHashUCs();
		}

		// If remaining bytes left, they will be copied for the next added stream
		if (processBytes > 0) {
			memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(stream->GetUCLength() - processBytes), processBytes);
			this->remainingBytesLength += processBytes;
		}
	}

	// Finalize the hash
	void Sha512::Finalize(void) {

		this->remainingBytes[this->remainingBytesLength] = 0x80;
		if ((this->remainingBytesLength * BYTEBITS) % this->dataHashBits >= this->equationModulo) {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetDataHashUCs() - this->remainingBytesLength -1);
			this->Compress(this->messageDigest, this->remainingBytes);
			this->AddMessageLength(this->remainingBytesLength);
			int i; i=this->GetDataHashUCs();
			memset(this->remainingBytes, 0, this->GetDataHashUCs());
			this->remainingBytesLength = 0;
		}
		else {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetDataHashUCs() - this->remainingBytesLength -1);
		}
		this->AddMessageLength(this->remainingBytesLength);
		this->remainingBytes[112] = (((unsigned long long int)this->messageBitLengthHigh) >> 56) & 255;
		this->remainingBytes[113] = (((unsigned long long int)this->messageBitLengthHigh) >> 48) & 255;
		this->remainingBytes[114] = (((unsigned long long int)this->messageBitLengthHigh) >> 40) & 255;
		this->remainingBytes[115] = (((unsigned long long int)this->messageBitLengthHigh) >> 32) & 255;
		this->remainingBytes[116] = (((unsigned long long int)this->messageBitLengthHigh) >> 24) & 255;
		this->remainingBytes[117] = (((unsigned long long int)this->messageBitLengthHigh) >> 16) & 255;
		this->remainingBytes[118] = (((unsigned long long int)this->messageBitLengthHigh) >> 8) & 255;
		this->remainingBytes[119] = (((unsigned long long int)this->messageBitLengthHigh)) & 255;
		this->remainingBytes[120] = (((unsigned long long int)this->messageBitLengthLow) >> 56) & 255;
		this->remainingBytes[121] = (((unsigned long long int)this->messageBitLengthLow) >> 48) & 255;
		this->remainingBytes[122] = (((unsigned long long int)this->messageBitLengthLow) >> 40) & 255;
		this->remainingBytes[123] = (((unsigned long long int)this->messageBitLengthLow) >> 32) & 255;
		this->remainingBytes[124] = (((unsigned long long int)this->messageBitLengthLow) >> 24) & 255;
		this->remainingBytes[125] = (((unsigned long long int)this->messageBitLengthLow) >> 16) & 255;
		this->remainingBytes[126] = (((unsigned long long int)this->messageBitLengthLow) >> 8) & 255;
		this->remainingBytes[127] = (((unsigned long long int)this->messageBitLengthLow)) & 255;
		this->Compress(this->messageDigest, this->remainingBytes);
	}

	// Gets hash length in bits
	unsigned short int Sha512::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Sha512::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Sha512::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Sha512::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets hash length in unsigned 64 bits
	unsigned short int Sha512::Get64HashLength(void) {

		return this->hash64s;
	}

	// Gets the type of the object
	Hashes Sha512::GetType(void) {

		return this->hashName;
	}
  }
}

