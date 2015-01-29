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

#include "baseSha32.h"


namespace DiceLockSecurity {

  namespace Hash {

	// Number of data bits to compute hash
	const unsigned short int BaseSha32::dataHashBits = BASESHA_32_DATABITS;
	// Number of data unsigned chars to compute hash
	const unsigned short int BaseSha32::dataHashUCs = BASESHA_32_DATAUCHARS;
	// Number of data unsigned long integers to compute hash
	const unsigned short int BaseSha32::dataHashULs = BASESHA_32_DATAULONGS;

	// Equation modulo constant value
	const unsigned short int BaseSha32::equationModulo = BASESHA_32_EQUATIONMODULO;

	// Gets the number of unsigned chars in the hash block to be hashed
	unsigned short int BaseSha32::GetDataHashUCs(void) {

		return this->dataHashUCs;
	}

	// Adds messaage length processed, if it is greater than unsigned long makes use
	// of another usigned long to store overflow
	void BaseSha32::AddMessageLength(unsigned long int byteLength) {

		if ((this->messageBitLengthLow + (byteLength * BYTEBITS)) < this->messageBitLengthLow)
			// add overflow of unsigned long
			this->messageBitLengthHigh++;
		this->messageBitLengthLow += (byteLength  * BYTEBITS);
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
	void BaseSha32::Finalize(void) {

		this->remainingBytes[this->remainingBytesLength] = 0x80;
		if ((this->remainingBytesLength * BYTEBITS) % this->dataHashBits >= this->equationModulo) {
			memset(this->remainingBytes + this->remainingBytesLength + 1, 0, this->GetDataHashUCs() - this->remainingBytesLength -1);
			this->Compress(this->messageDigest, this->remainingBytes);
			this->AddMessageLength(this->remainingBytesLength);
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
		this->Compress(this->messageDigest, this->remainingBytes);
	}
  }
}
