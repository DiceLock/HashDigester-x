//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.6.0.0.1
//
// Copyright 2009-2012 DiceLock Security, LLC. All rights reserved.
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
#include "baseRipemd.h"


namespace DiceLockSecurity {
	
  namespace Hash {

	// Number of data bits to compute hash
	const unsigned short int BaseRipemd::hashBlockBits = RIPEMD_BLOCKBITS;
	// Number of data unsigned chars to compute hash
	const unsigned short int BaseRipemd::hashBlockUCs = RIPEMD_BLOCKUCHARS;
	// Number of data unsigned long shorts to compute hash
	const unsigned short int BaseRipemd::hashBlockUSs = RIPEMD_BLOCKUSHORTS;
	// Number of data unsigned long ints to compute hash
	const unsigned short int BaseRipemd::hashBlockULs = RIPEMD_BLOCKULONGS;

	// Constants for all RIPEMD algorithms
	const unsigned long int BaseRipemd::constant0 = 0x00000000UL;
	const unsigned long int BaseRipemd::constant1 = 0x5A827999UL;
	const unsigned long int BaseRipemd::constant2 = 0x6ED9EBA1UL;
	const unsigned long int BaseRipemd::constant3 = 0x8F1BBCDCUL;
	const unsigned long int BaseRipemd::constant5 = 0x50A28BE6UL;
	const unsigned long int BaseRipemd::constant6 = 0x5C4DD124UL;
	const unsigned long int BaseRipemd::constant7 = 0x6D703EF3UL;
	const unsigned long int BaseRipemd::constant9 = 0x00000000UL;

	// Amounts of rotate left
	const unsigned short int BaseRipemd::rl_0_15[16] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8};
	const unsigned short int BaseRipemd::rl_16_31[16] = {7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12};
	const unsigned short int BaseRipemd::rl_32_47[16] = {11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5};
	const unsigned short int BaseRipemd::rl_48_63[16] = {11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12};
	// Amounts of prime rotate left 
	const unsigned short int BaseRipemd::prime_rl_0_15[16] = {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6};
	const unsigned short int BaseRipemd::prime_rl_16_31[16] = {9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11};
	const unsigned short int BaseRipemd::prime_rl_32_47[16] = {9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5};
	const unsigned short int BaseRipemd::prime_rl_48_63[16] = {15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8};

	// Initial states of all Ripemd algorithms
	const unsigned long int BaseRipemd::inistate0 = 0x67452301;
	const unsigned long int BaseRipemd::inistate1 = 0xEFCDAB89;
	const unsigned long int BaseRipemd::inistate2 = 0x98BADCFE;
	const unsigned long int BaseRipemd::inistate3 = 0X10325476;


	// Constructor
	BaseRipemd::BaseRipemd() {

		this->remainingBytesLength = 0;
		this->messageByteLengthHigh = 0;
		this->messageByteLengthLow = 0;
	}

	// Destructor
	BaseRipemd::~BaseRipemd() {

		this->remainingBytesLength = 0;
		this->messageByteLengthHigh = 0;
		this->messageByteLengthLow = 0;
	}

	// Initializes common states of all Ripmed algorithms  
	void BaseRipemd::Initialize() {

		this->messageDigest->SetULPosition(0, inistate0);
		this->messageDigest->SetULPosition(1, inistate1);
		this->messageDigest->SetULPosition(2, inistate2);
		this->messageDigest->SetULPosition(3, inistate3);
		this->remainingBytesLength = 0;
		this->messageByteLengthHigh = 0;
		this->messageByteLengthLow = 0;
	}

	// Computes the 64 byte chunk of stream information 
	void BaseRipemd::Add(BaseCryptoRandomStream* stream) {
		unsigned long int chunk[RIPEMD_DATAULONGS];
		unsigned long int startStreamByte = 0, numBytes = 0, processBytes = 0;
		unsigned long int i = 0;
		unsigned char* pointerUC;

		// If bytes left from previous added stream, then they will be processed now with added data from new stream
		if (this->remainingBytesLength) {
			if ((this->remainingBytesLength + stream->GetUCLength()) > (RIPEMD_DATAUCHARS - 1)) {
				// Setting the point to start the current stream processed
				startStreamByte = RIPEMD_DATAUCHARS - this->remainingBytesLength;
				processBytes = stream->GetUCLength() - (RIPEMD_DATAUCHARS - this->remainingBytesLength);

				memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(0), RIPEMD_DATAUCHARS - this->remainingBytesLength);
				pointerUC = this->remainingBytes;
				for (i = 0; i < RIPEMD_DATAULONGS; i++) {
					chunk[i] = ((unsigned long int) *((pointerUC) + 3) << 24) | ((unsigned long int) *((pointerUC) + 2) << 16) | ((unsigned long int) *((pointerUC) + 1) << 8) | ((unsigned long int) *(pointerUC));
					pointerUC += RIPEMD_DATASHIFT;
				}
				// Process remaining bytes of previous streams adn 64 byte padding of current stream
				this->Compress(chunk);
				// Updating message byt length processed
				this->AddMessageLength(RIPEMD_DATAUCHARS);
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

		for (numBytes = processBytes; numBytes > (RIPEMD_DATAUCHARS - 1); numBytes -= RIPEMD_DATAUCHARS) {
			for (i = 0; i < RIPEMD_DATAULONGS; i++) {
				pointerUC = stream->GetUCAddressPosition(startStreamByte + (processBytes - numBytes) + (i<<2));
				chunk[i] = ((unsigned long int) *((pointerUC) + 3) << 24) | ((unsigned long int) *((pointerUC) + 2) << 16) | ((unsigned long int) *((pointerUC) + 1) << 8) | ((unsigned long int) *(pointerUC));
			}
			this->Compress(chunk);
			// Updating message byt length processed
			this->AddMessageLength(RIPEMD_DATAUCHARS); 
		}

		// If remaining bytes left, they will be copied for the next added stream
		if (numBytes > 0) {
			memcpy(this->remainingBytes + this->remainingBytesLength, stream->GetUCAddressPosition(stream->GetUCLength() - numBytes), numBytes);
			this->remainingBytesLength += numBytes;
		}
	}

	// Finalize the hash
	void BaseRipemd::Finalize(void) {
		unsigned long int i, length;
		unsigned long int X[RIPEMD_DATAULONGS];
		unsigned char* leftBytes;

		if (this->remainingBytesLength > 0) {
			this->AddMessageLength(this->remainingBytesLength);
			leftBytes = this->remainingBytes;

		}
		else {
			leftBytes = NULL;
		}
		length = this->messageByteLengthLow;

		memset(X, 0, RIPEMD_DATAULONGS*sizeof(unsigned long int));

		/* put bytes from strptr into X */
		for (i = 0; i < (this->messageByteLengthLow&63); i++) {
			/* byte i goes into word X[i div 4] at pos.  8*(i mod 4)  */
			X[i>>2] ^= (unsigned long int) *leftBytes++ << (8 * (i&3));
		}

		/* append the bit m_n == 1 */
		X[(this->messageByteLengthLow>>2) % RIPEMD_DATAULONGS] ^= (unsigned long int)1 << (8*(this->messageByteLengthLow&3) + 7);

		if ((this->messageByteLengthLow % RIPEMD_DATAUCHARS) > 55) {
			/* length goes to next block */
			this->Compress(X);
			memset(X, 0, RIPEMD_DATAULONGS * sizeof(unsigned long int));
		}

		/* append length in bits*/
		X[RIPEMD_DATAULONGS - 2] = this->messageByteLengthLow << 3;
		X[RIPEMD_DATAULONGS - 1] = (this->messageByteLengthLow >> 29) | (this->messageByteLengthHigh << 3);
		this->Compress(X);
	}

	// Adds messaage length in bytes processed, if it is greater than unsigned long makes use
	// of another usigned long to store overflow
	void BaseRipemd::AddMessageLength(unsigned long int byteLength) {

		if ((this->messageByteLengthLow + byteLength) < this->messageByteLengthLow) 
			// add overflow of unsigned long
			this->messageByteLengthHigh++;
		this->messageByteLengthLow += byteLength;
	}
 
	// Gets the number of bits in the hash block to be hashed
	unsigned short int BaseRipemd::GetBitHashBlockLength(void) {

		return this->hashBlockBits;
	}

	// Gets the number of unsigned chars in the hash block to be hashed
	unsigned short int BaseRipemd::GetUCHashBlockLength(void) {

		return this->hashBlockUCs;
	}

	// Gets the number of unsigned short ints in the hash block to be hashed
	unsigned short int BaseRipemd::GetUSHashBlockLength(void) {

		return this->hashBlockUSs;
	}

	// Gets the number of unsigned long ints in the hash block to be hashed
	unsigned short int BaseRipemd::GetULHashBlockLength(void) {

		return this->hashBlockULs;
	}

 }
}