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

#ifndef SHA224_HPP

#define SHA224_HPP

#include <stdlib.h>
#include "sha256.h"
#include "defaultCryptoRandomStream.h"


#define SHA224_DIGESTBITS    224  // 224 hash bits
#define SHA224_DIGESTUCHARS  28   // 28  hash unsigned chars
#define SHA224_DIGESTUSHORTS 14   // 14  hash unsigned short ints
#define SHA224_DIGESTULONGS  7    // 7   hash unsigned long ints


namespace DiceLockSecurity {

  namespace Hash {

	class Sha224 : public Sha256 {

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

			/// Initial hash values of SHA256 
			static const unsigned long int initials[SHA256_DIGESTULONGS];

			/// Pointer to BaseCryptoRandomStream digest for SHA 256 hash algorithm
			BaseCryptoRandomStream* workingDigest256; 
			
			/// Boolean pointing if meesaageDigest for SHA 256 has been created automatically
			bool autoWorkingDigest;
			
		public:

			/// Constructor, default 
			Sha224();

			/// Destructor
			~Sha224();

			/// Set the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm
			void SetWorkingDigest(BaseCryptoRandomStream*);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm length in bits
			unsigned short int GetWorkingDigestBitLength(void);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm length in unsigned chars
			unsigned short int GetWorkingDigestUCLength(void);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm length in unsigned short ints
			unsigned short int GetWorkingDigestUSLength(void);

			/// Get the Working Digest  BaseCryptoRandomStream for underlaying SHA256 algorithm length in unsigned long ints
			unsigned short int GetWorkingDigestULLength(void);

			/// Initializes common states of Sha1 algorithm
			void Initialize(void);

			/// Adds the BaseCryptoRandomStream to the hash
			void Add(BaseCryptoRandomStream*);

			/// Finalize the hash
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
