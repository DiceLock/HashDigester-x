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
#include "baseSha32.h"


namespace DiceLockSecurity {
	
  namespace Hash {

	// Number of data bits to compute hash
	const unsigned short int BaseSha32::hashBlockBits = BASESHA_32_BLOCKBITS;
	// Number of data unsigned chars to compute hash
	const unsigned short int BaseSha32::hashBlockUCs = BASESHA_32_BLOCKUCHARS;
	// Number of data unsigned long shorts to compute hash
	const unsigned short int BaseSha32::hashBlockUSs = BASESHA_32_BLOCKUSHORTS;
	// Number of data unsigned long ints to compute hash
	const unsigned short int BaseSha32::hashBlockULs = BASESHA_32_BLOCKULONGS;

	// Equation modulo constant value
	const unsigned short int BaseSha32::equationModulo = BASESHA_32_EQUATIONMODULO;

	// Adds messaage length processed, if it is greater than unsigned long makes use
	// of another usigned long to store overflow
	void BaseSha32::AddMessageLength(unsigned long int byteLength) {

		if ((this->messageBitLengthLow + (byteLength * BYTEBITS)) < this->messageBitLengthLow) 
			// add overflow of unsigned long
			this->messageBitLengthHigh++;
		this->messageBitLengthLow += (byteLength  * BYTEBITS);
	}

	// Swap bytes for little endian
	void BaseSha32::SwapLittleEndian(void) {
		unsigned long int swap, i;

		for ( i = 0; i < this->messageDigest->GetULLength(); i++ ) {
			swap = this->messageDigest->GetULPosition(i);
			this->messageDigest->SetUCPosition( (i * 4), (unsigned char)(swap >> 24) & 0xFF);
			this->messageDigest->SetUCPosition( (i * 4) + 1, (unsigned char)(swap >> 16) & 0xFF);
			this->messageDigest->SetUCPosition( (i * 4) + 2, (unsigned char)(swap >> 8) & 0xFF);
			this->messageDigest->SetUCPosition( (i * 4) + 3, (unsigned char)(swap & 0xFF));
		}

	}

	// Constructor, default 
	BaseSha32::BaseSha32() {

		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Destructor
	BaseSha32::~BaseSha32() {

		this->remainingBytesLength = 0;
		this->messageBitLengthHigh = 0;
		this->messageBitLengthLow = 0;
	}

	// Adds the BaseCryptoRandomStream to the hash
	void BaseSha32::Add(BaseCryptoRandomStream* stream) {
		unsigned long int startStreamByte = 0, processBytes = 0;
		long int numBytes = 0;

		// If bytes left from previous added stream, then they will be processed now with added data from new stream
		if (this->remainingBytesLength) {
			if ((this->remainingBytesLength + stream->GetUCLength()) > ((unsigned long int)this->GetUCHashBlockLength() - 1)) {
				// Setting the point to start the current stream processed
				startStreamByte = this->GetUCHashBlockLength() - this->remainingBytesLength;
				processBytes = stream->GetUCLength() - (this->GetUCHashBlockLength() - this->remainingBytesLength);

				memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(0), this->GetUCHashBlockLength() - this->remainingBytesLength);
				// Process remaining bytes of previous streams adn 64 byte padding of current stream
				this->Compress(this->messageDigest, this->remainingBytes);
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
			this->Compress(this->messageDigest, stream->GetUCAddressPosition(startStreamByte + numBytes));
			// Updating message byt length processed
			this->AddMessageLength(this->GetUCHashBlockLength()); 
			processBytes -= this->GetUCHashBlockLength();
		}

		// If remaining bytes left, they will be copied for the next added stream
		if (processBytes > 0) {
			memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(stream->GetUCLength() - processBytes), processBytes);
			this->remainingBytesLength += processBytes;
		}
	}

	// Finalize the hash
	void BaseSha32::Finalize(void) {

		this->remainingBytes[this->remainingBytesLength] = 0x80;
		if ((this->remainingBytesLength * BYTEBITS) % this->hashBlockBits >= this->equationModulo) {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetUCHashBlockLength() - this->remainingBytesLength -1);
			this->Compress(this->messageDigest, this->remainingBytes);
			this->AddMessageLength(this->remainingBytesLength);
			memset(this->remainingBytes, 0, this->GetUCHashBlockLength());
			this->remainingBytesLength = 0;
		}
		else {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetUCHashBlockLength() - this->remainingBytesLength -1);
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
		this->Compress(this->messageDigest, this->remainingBytes);
	}

	// Gets the number of bits in the hash block to be hashed
	unsigned short int BaseSha32::GetBitHashBlockLength(void) {

		return this->hashBlockBits;
	}

	// Gets the number of unsigned chars in the hash block to be hashed
	unsigned short int BaseSha32::GetUCHashBlockLength(void) {

		return this->hashBlockUCs;
	}

	// Gets the number of unsigned short ints in the hash block to be hashed
	unsigned short int BaseSha32::GetUSHashBlockLength(void) {

		return this->hashBlockUSs;
	}

	// Gets the number of unsigned long ints in the hash block to be hashed
	unsigned short int BaseSha32::GetULHashBlockLength(void) {

		return this->hashBlockULs;
	}

  }
}
