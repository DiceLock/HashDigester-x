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

#ifndef BASESHA32_HPP

#define BASESHA32_HPP

#include "baseHash.h"


#define BASESHA_32_Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define BASESHA_32_Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define BASESHA_32_BLOCKBITS    512    // 512 block bits
#define BASESHA_32_BLOCKUCHARS  64     // 64  block unsigned chars
#define BASESHA_32_BLOCKUSHORTS 32     // 32  block unsigned shorts
#define BASESHA_32_BLOCKULONGS  16     // 16  block unsigned longs

#define BASESHA_32_EQUATIONMODULO  448


namespace DiceLockSecurity {

  namespace Hash {

	class BaseSha32 : public BaseHash {

		protected:

			/// Number of block bits to compute hash
			static const unsigned short int hashBlockBits;
			/// Number of block unsigned chars to compute hash
			static const unsigned short int hashBlockUCs;
			/// Number of block unsigned short ints to compute hash
			static const unsigned short int hashBlockUSs;
			/// Number of block unsigned long ints to compute hash
			static const unsigned short int hashBlockULs;

			/// Equation modulo constant value
			static const unsigned short int equationModulo;

			/// Array to store remaining bytes of intermediate hash operation
			unsigned char remainingBytes[BASESHA_32_BLOCKUCHARS];
			unsigned long int remainingBytesLength;

			/// Total processed message length in bytes
			unsigned long int messageBitLengthHigh;
			unsigned long int messageBitLengthLow;

			/// Adds messaage length processed, if it is greater than unsigned long makes use
			/// of another usigned long to store overflow
			void AddMessageLength(unsigned long int);

			/// Computes the chunk block of information  
			virtual void Compress(BaseCryptoRandomStream*, unsigned char*) {};

			/// Swap bytes for little endian
			void SwapLittleEndian(void);

		public:

			/// Constructor, default 
			BaseSha32();

			/// Destructor
			~BaseSha32();

			/// Adds the BaseCryptoRandomStream to the hash
			void Add(BaseCryptoRandomStream*);

			/// Finalize the hash
			void Finalize(void);

			/// Gets the number of bits in the hash block to be hashed
			unsigned short int GetBitHashBlockLength(void);

			/// Gets the number of unsigned chars in the hash block to be hashed
			unsigned short int GetUCHashBlockLength(void);

			/// Gets the number of unsigned short ints in the hash block to be hashed
			unsigned short int GetUSHashBlockLength(void);

			/// Gets the number of unsigned long ints in the hash block to be hashed
			unsigned short int GetULHashBlockLength(void);
	};
  }
}

#endif
