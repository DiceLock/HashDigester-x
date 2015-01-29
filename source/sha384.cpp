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
#include <stdlib.h>
#include "sha384.h"


namespace DiceLockSecurity {
	
  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Sha384::hashName = SHA_384;

	// Number of hash bits
	const unsigned short int Sha384::hashBits = SHA384_DIGESTBITS;
	// Number of hash unsigned chars
	const unsigned short int Sha384::hashUCs = SHA384_DIGESTUCHARS;
	// Number of hash unsigned short ints
	const unsigned short int Sha384::hashUSs = SHA384_DIGESTUSHORTS;
	// Number of hash unsigned long ints
	const unsigned short int Sha384::hashULs = SHA384_DIGESTULONGS;
	// Number of hash unsigned 64 bits
	const unsigned short int Sha384::hash64s = SHA384_DIGESTULG64S;

	// Initial hash values of SHA384 
	const unsigned long long int Sha384::initials[SHA384_DIGESTULONGS] = 
			{0xcbbb9d5dc1059ed8, 
             0x629a292a367cd507, 
             0x9159015a3070dd17, 
             0x152fecd8f70e5939, 
             0x67332667ffc00b31, 
             0x8eb44a8768581511, 
             0xdb0c2e0d64f98fa7, 
			 0x47b5481dbefa4fa4};

	// Constructor, default 
	Sha384::Sha384() {

		this->workingDigest512 = NULL;
		this->autoWorkingDigest = false;
	}

	// Destructor
	Sha384::~Sha384() {

		if (autoWorkingDigest) {
			delete this->workingDigest512;
			this->workingDigest512 = NULL;
			this->autoWorkingDigest = false;
		}
	}

	// Set the Working Digest BaseCryptoRandomStream for underlaying SHA512 algorithm
	void Sha384::SetWorkingDigest(BaseCryptoRandomStream* workDigest) {

		this->workingDigest512 = workDigest;
	}

	// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in bits
	unsigned short int Sha384::GetWorkingDigestBitLength(void) {

		return this->Sha512::GetBitHashLength();
	}

	// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in unsigned chars
	unsigned short int Sha384::GetWorkingDigestUCLength(void) {

		return this->Sha512::GetUCHashLength();
	}

	// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in unsigned short ints
	unsigned short int Sha384::GetWorkingDigestUSLength(void) {

		return this->Sha512::GetUSHashLength();
	}

	// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm length in unsigned long ints
	unsigned short int Sha384::GetWorkingDigestULLength(void) {

		return this->Sha512::GetULHashLength();
	}

	// Initializes common states of Sha1 algorithm
	void Sha384::Initialize(void) {

		if (this->workingDigest512 == NULL) {
			this->workingDigest512 = new DefaultCryptoRandomStream();
			this->workingDigest512->SetCryptoRandomStreamUC(this->GetWorkingDigestUCLength());
			this->autoWorkingDigest = true;
		}
		this->workingDigest512->Set64Position(0, this->initials[0]);
		this->workingDigest512->Set64Position(1, this->initials[1]);
		this->workingDigest512->Set64Position(2, this->initials[2]);
		this->workingDigest512->Set64Position(3, this->initials[3]);
		this->workingDigest512->Set64Position(4, this->initials[4]);
		this->workingDigest512->Set64Position(5, this->initials[5]);
		this->workingDigest512->Set64Position(6, this->initials[6]);
		this->workingDigest512->Set64Position(7, this->initials[7]);
		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Adds the BaseCryptoRandomStream to the hash
	void Sha384::Add(BaseCryptoRandomStream* stream) {
		unsigned long int startStreamByte = 0, processBytes = 0;
		long int numBytes = 0;
		unsigned long int i = 0;

		// If bytes left from previous added stream, then they will be processed now with added data from new stream
		if (this->remainingBytesLength) {
			if ((this->remainingBytesLength + stream->GetUCLength()) > ((unsigned long int)this->GetUCHashBlockLength() - 1)) {
				// Setting the point to start the current stream processed
				startStreamByte = this->GetUCHashBlockLength() - this->remainingBytesLength;
				processBytes = stream->GetUCLength() - (this->GetUCHashBlockLength() - this->remainingBytesLength);

				memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(0), this->GetUCHashBlockLength() - this->remainingBytesLength);
				// Process remaining bytes of previous streams adn 64 byte padding of current stream
				this->Compress(this->workingDigest512, this->remainingBytes);
				// Updating message byt length processed
				this->AddMessageLength(this->GetUCHashBlockLength());
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

		for (numBytes = 0; processBytes > ((unsigned long int)this->GetUCHashBlockLength() - 1); numBytes += this->GetUCHashBlockLength()) {
			// Process the chunk
			this->Compress(this->workingDigest512, stream->GetUCAddressPosition(startStreamByte + numBytes));
			// Updating message byt length processed
			this->AddMessageLength(this->GetUCHashBlockLength()); 
			processBytes -= this->GetUCHashBlockLength();
		}

		// If remaining bytes left, they will be copied for the next added stream
		if (processBytes > 0) {
			memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(stream->GetUCLength() - processBytes), processBytes);
			this->remainingBytesLength += processBytes;
		}
		i = this->Get64HashLength();
		for (i = 0; i < this->Get64HashLength(); i++) {
			this->messageDigest->Set64Position(i, this->workingDigest512->Get64Position(i));
		}
	}

	// Finalize the hash
	void Sha384::Finalize(void) {
		unsigned short int i;

		this->remainingBytes[this->remainingBytesLength] = 0x80;
		if ((this->remainingBytesLength * BYTEBITS) % this->hashBlockBits >= this->equationModulo) {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetUCHashBlockLength() - this->remainingBytesLength -1);
			this->Compress(this->workingDigest512, this->remainingBytes);
			this->AddMessageLength(this->remainingBytesLength);
			memset(this->remainingBytes, 0, this->GetUCHashBlockLength());
			this->remainingBytesLength = 0;
		}
		else {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetUCHashBlockLength() - this->remainingBytesLength -1);
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
		this->Compress(this->workingDigest512, this->remainingBytes);
		for (i = 0; i < this->Get64HashLength(); i++) {
			this->messageDigest->Set64Position(i, this->workingDigest512->Get64Position(i));
		}
		this->SwapLittleEndian();
	}

	// Gets hash length in bits
	unsigned short int Sha384::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Sha384::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Sha384::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Sha384::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets hash length in unsigned 64 bits
	unsigned short int Sha384::Get64HashLength(void) {

		return this->hash64s;
	}

	// Gets the type of the object
	Hashes Sha384::GetType(void) {

		return this->hashName;
	}
  }
}
