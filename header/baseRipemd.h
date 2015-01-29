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

#ifndef BASERIPEMD_HPP

#define BASERIPEMD_HPP

#include "baseHash.h"


#define RIPEMD_DATAUCHARS 64
#define RIPEMD_DATAULONGS 16
#define RIPEMD_DATASHIFT   4

#define RIPEMD_BLOCKBITS    512    // 512 block bits
#define RIPEMD_BLOCKUCHARS  64     // 64  block unsigned chars
#define RIPEMD_BLOCKUSHORTS 32     // 32  block unsigned shorts
#define RIPEMD_BLOCKULONGS  16     // 16  block unsigned longs

#define RIPEMD_F(x, y, z) (x ^ y ^ z)
#define RIPEMD_G(x, y, z) ((x & y) | ((~x) & z))
#define RIPEMD_H(x, y, z) ((x | (~y)) ^ z)
#define RIPEMD_I(x, y, z) ((x & z) | (y & (~z)))

#define RIPEMD_RotateLeft(x, n) ((x<<n) | (x>>(32-n)))


namespace DiceLockSecurity {

  namespace Hash {

	class BaseRipemd : public BaseHash  {

		protected:

			/// Number of block bits to compute hash
			static const unsigned short int hashBlockBits;
			/// Number of block unsigned chars to compute hash
			static const unsigned short int hashBlockUCs;
			/// Number of block unsigned short ints to compute hash
			static const unsigned short int hashBlockUSs;
			/// Number of block unsigned long ints to compute hash
			static const unsigned short int hashBlockULs;

			/// Array to store remaining bytes of intermediate hash operation
			unsigned char remainingBytes[RIPEMD_DATAUCHARS];
			unsigned long int remainingBytesLength;

			/// Total processed message length in bytes
			unsigned long int messageByteLengthHigh;
			unsigned long int messageByteLengthLow;

			/// Common operation values to all RIPEMD algorithms
			static const unsigned long int constant0;
			static const unsigned long int constant1;
			static const unsigned long int constant2;
			static const unsigned long int constant3;
			static const unsigned long int constant5;
			static const unsigned long int constant6;
			static const unsigned long int constant7;
			static const unsigned long int constant9;

			/// Amounts of rotate left
			static const unsigned short int rl_0_15[16];
			static const unsigned short int rl_16_31[16];
			static const unsigned short int rl_32_47[16];
			static const unsigned short int rl_48_63[16];
			/// Amounts of prime rotate left 
			static const unsigned short int prime_rl_0_15[16];
			static const unsigned short int prime_rl_16_31[16];
			static const unsigned short int prime_rl_32_47[16];
			static const unsigned short int prime_rl_48_63[16];

			/// Initial states of all Ripemd algorithms
			static const unsigned long int inistate0;
			static const unsigned long int inistate1;
			static const unsigned long int inistate2;
			static const unsigned long int inistate3;

			/// Adds messaage length processed, if it is greater than unsigned long makes use
			/// of another usigned long to store overflow
			void AddMessageLength(unsigned long int);

			/// Computes the 64 byte chunk of information  
			virtual void Compress(unsigned long int*) {};

		public:

			/// Constructor, default 
			BaseRipemd();

			/// Destructor
			~BaseRipemd();

			/// Initializes common states of all Ripmed algorithms 
			void Initialize(void);

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
