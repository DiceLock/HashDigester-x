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

#include "sha224.h"


namespace DiceLockSecurity {

  namespace Hash {

	// Hash Algorithms Class enumerator name
	const Hashes Sha224::hashName = SHA_224;

	// Number of hash bits
	const unsigned short int Sha224::hashBits = SHA224_DIGESTBITS;
	// Number of hash unsigned chars
	const unsigned short int Sha224::hashUCs = SHA224_DIGESTUCHARS;
	// Number of hash unsigned short ints
	const unsigned short int Sha224::hashUSs = SHA224_DIGESTUSHORTS;
	// Number of hash unsigned long ints
	const unsigned short int Sha224::hashULs = SHA224_DIGESTULONGS;

	// Initial hash values of SHA224
	const unsigned long int Sha224::initials[SHA256_DIGESTULONGS] =
			{0xc1059ed8,
             0x367cd507,
             0x3070dd17,
             0xf70e5939,
             0xffc00b31,
             0x68581511,
             0x64f98fa7,
			 0xbefa4fa4};

	// Constructor, default
	Sha224::Sha224() {

		this->workingDigest256 = NULL;
		this->autoWorkingDigest = false;
	}

	// Destructor
	Sha224::~Sha224() {

		if ( autoWorkingDigest ) {
			delete this->workingDigest256;
			this->workingDigest256 = NULL;
			this->autoWorkingDigest = false;
		}
	}

	// Set the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm
	void Sha224::SetWorkingDigest(BaseCryptoRandomStream* workDigest) {

		this->workingDigest256 = (DefaultCryptoRandomStream *)workDigest;
	}

	// Set the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm
	unsigned short int Sha224::GetWorkingDigestUCLength(void) {

		return this->Sha256::GetUCHashLength();
	}

	// Initializes common states of Sha1 algorithm
	void Sha224::Initialize(void) {

		if (this->workingDigest256 == NULL) {
			this->workingDigest256 = new DefaultCryptoRandomStream();
			this->workingDigest256->SetCryptoRandomStreamUC(this->GetWorkingDigestUCLength());
			this->autoWorkingDigest = true;
		}
		this->workingDigest256->SetULPosition(0, this->initials[0]);
		this->workingDigest256->SetULPosition(1, this->initials[1]);
		this->workingDigest256->SetULPosition(2, this->initials[2]);
		this->workingDigest256->SetULPosition(3, this->initials[3]);
		this->workingDigest256->SetULPosition(4, this->initials[4]);
		this->workingDigest256->SetULPosition(5, this->initials[5]);
		this->workingDigest256->SetULPosition(6, this->initials[6]);
		this->workingDigest256->SetULPosition(7, this->initials[7]);
		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Adds the BaseCryptoRandomStream to the hash
	void Sha224::Add(BaseCryptoRandomStream* stream) {
		unsigned long int startStreamByte = 0, processBytes = 0;
		long int numBytes = 0;
		unsigned long int i = 0;

		// If bytes left from previous added stream, then they will be processed now with added data from new stream
		if (this->remainingBytesLength) {
			if ((this->remainingBytesLength + stream->GetUCLength()) > ((unsigned long int)this->GetDataHashUCs() - 1)) {
				// Setting the point to start the current stream processed
				startStreamByte = this->GetDataHashUCs() - this->remainingBytesLength;
				processBytes = stream->GetUCLength() - (this->GetDataHashUCs() - this->remainingBytesLength);

				memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(0), this->GetDataHashUCs() - this->remainingBytesLength);
				// Process remaining bytes of previous streams adn 64 byte padding of current stream
				this->Compress(this->workingDigest256, this->remainingBytes);
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
			this->Compress(this->workingDigest256, stream->GetUCAddressPosition(startStreamByte + numBytes));
			// Updating message byt length processed
			this->AddMessageLength(this->GetDataHashUCs());
			processBytes -= this->GetDataHashUCs();
		}

		// If remaining bytes left, they will be copied for the next added stream
		if (processBytes > 0) {
			memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(stream->GetUCLength() - processBytes), processBytes);
			this->remainingBytesLength += processBytes;
		}
		for (i = 0; i < this->GetULHashLength(); i++) {
			this->messageDigest->SetULPosition(i, this->workingDigest256->GetULPosition(i));
		}
	}

	// Finalize the hash
	void Sha224::Finalize(void) {
		unsigned short int i;

		this->remainingBytes[this->remainingBytesLength] = 0x80;
		if ((this->remainingBytesLength * BYTEBITS) % this->dataHashBits >= this->equationModulo) {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetDataHashUCs() - this->remainingBytesLength -1);
			this->Compress(this->workingDigest256, this->remainingBytes);
			this->AddMessageLength(this->remainingBytesLength);
			int i; i=this->GetDataHashUCs();
			memset(this->remainingBytes, 0, this->GetDataHashUCs());
			this->remainingBytesLength = 0;
		}
		else {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetDataHashUCs() - this->remainingBytesLength -1);
		}
		this->AddMessageLength(this->remainingBytesLength);
		this->remainingBytes[56] = (this->messageBitLengthHigh >> 24) & 255;
		this->remainingBytes[57] = (this->messageBitLengthHigh >> 16) & 255;
		this->remainingBytes[58] = (this->messageBitLengthHigh >> 8) & 255;
		this->remainingBytes[59] = (this->messageBitLengthHigh) & 255;
		this->remainingBytes[60] = (this->messageBitLengthLow >> 24) & 255;
		this->remainingBytes[61] = (this->messageBitLengthLow >> 16) & 255;
		this->remainingBytes[62] = (this->messageBitLengthLow >> 8) & 255;
		this->remainingBytes[63] = (this->messageBitLengthLow) & 255;
		this->Compress(this->workingDigest256, this->remainingBytes);
		for (i = 0; i < this->GetULHashLength(); i++) {
			this->messageDigest->SetULPosition(i, this->workingDigest256->GetULPosition(i));
		}
	}

	// Gets hash length in bits
	unsigned short int Sha224::GetBitHashLength(void) {

		return this->hashBits;
	}

	// Gets hash length in unsigned chars
	unsigned short int Sha224::GetUCHashLength(void) {

		return this->hashUCs;
	}

	// Gets hash length in unsigned short ints
	unsigned short int Sha224::GetUSHashLength(void) {

		return this->hashUSs;
	}

	// Gets hash length in unsigned long ints
	unsigned short int Sha224::GetULHashLength(void) {

		return this->hashULs;
	}

	// Gets the type of the object
	Hashes Sha224::GetType(void) {

		return this->hashName;
	}
  }
}
