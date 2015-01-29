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

#ifndef SHA1_HPP

#define SHA1_HPP

#include "baseSha32.h"


#define SHA1_DIGESTBITS    160  // 160 hash bits
#define SHA1_DIGESTUCHARS  20   // 20  hash unsigned chars
#define SHA1_DIGESTUSHORTS 10   // 10  hash unsigned short ints
#define SHA1_DIGESTULONGS  5    // 5   hash unsigned long ints

#define SHA1_COMPUTECONSTANTS 4

#define SHA1_MESSAGESCHEDULE 80

#define SHA1_OPERATIONS 80

#define SHA1_RotateLeft(x, n) (((x)<<(n)) | ((x)>>(32-(n))))
#define SHA1_Parity(x, y, z) ((x) ^ (y) ^ (z))

namespace DiceLockSecurity {

  namespace Hash {

	class Sha1 : public BaseSha32 {

		private:

			/// Hash Algorithms Class enumerator name
			static const Hashes	hashName;

			/// Number of hash bits
			static const unsigned short int hashBits;
			/// Number of hash unsigned chars
			static const unsigned short int hashUCs;
			/// Number of hash unsigned short ints
			static const unsigned short int hashUSs;
			/// Number of hash unsigned long ints
			static const unsigned short int hashULs;

			/// Number of schedule words
			static const unsigned short int scheduleNumber;

			/// Initial hash values of SHA1 
			static const unsigned long int initials[SHA1_DIGESTULONGS];

			/// Computational constant values of SHA1 
			static const unsigned long int constants[SHA1_COMPUTECONSTANTS];

			/// Message schedule words for SHA1 
			unsigned long int messageSchedule[SHA1_MESSAGESCHEDULE];

			/// Computes the chunk block of information  
			void Compress(BaseCryptoRandomStream* digest, unsigned char*);

		public:

			/// Constructor, default 
			Sha1();

			/// Destructor
			~Sha1();

			/// Initializes common states of Sha1 algorithm
			void Initialize(void);

			/// Finalizes hash and performs little endian transformation
			void Finalize(void);

			/// Gets hash length in bits
			unsigned short int GetBitHashLength(void);

			/// Gets hash length in unsigned chars
			unsigned short int GetUCHashLength(void);

			/// Gets hash length in unsigned short ints
			unsigned short int GetUSHashLength(void);

			/// Gets hash length in unsigned long ints
			unsigned short int GetULHashLength(void);

			/// Gets the type of the object
			Hashes GetType(void);
	};
  }
}

#endif
