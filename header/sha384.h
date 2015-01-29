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

#ifndef SHA384_HPP

#define SHA384_HPP


#include "sha512.h"
#include "defaultCryptoRandomStream.h"


#define SHA384_DIGESTBITS    384  // 384 hash bits
#define SHA384_DIGESTUCHARS  48   // 48  hash unsigned chars
#define SHA384_DIGESTUSHORTS 24   // 24  hash unsigned short ints
#define SHA384_DIGESTULONGS  12   // 12  hash unsigned long ints
#define SHA384_DIGESTULG64S  6    // 6   hash unsigned 64 bits


namespace DiceLockSecurity {

  namespace Hash {

	class Sha384 : public Sha512 {

		private:

			// Hash Algorithms Class enumerator name
			static const Hashes	hashName;

			// Number of hash bits
			static const unsigned short int hashBits;
			// Number of hash unsigned chars
			static const unsigned short int hashUCs;
			// Number of hash unsigned short ints
			static const unsigned short int hashUSs;
			// Number of hash unsigned long ints
			static const unsigned short int hashULs;
			// Number of hash unsigned 64 bits
			static const unsigned short int hash64s;

			// Initial hash values of SHA512
			static const unsigned long long int initials[SHA384_DIGESTULONGS];

			// Pointer to DefaultCryptoRandomStream digest for SHA 384 hash algorithm
			DefaultCryptoRandomStream* workingDigest512;

			// Boolean pointing if meesaageDigest for SHA 512 has been created automatically
			bool autoWorkingDigest;

		public:

			// Constructor, default
			Sha384();

			// Destructor
			~Sha384();

			// Set the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm
			void SetWorkingDigest(BaseCryptoRandomStream*);

			// Set the Working Digest  BaseCryptoRandomStream for underlaying SHA512 algorithm
			unsigned short int GetWorkingDigestUCLength(void);

			// Initializes common states of Sha1 algorithm
			void Initialize(void);

			// Adds the BaseCryptoRandomStream to the hash
			void Add(BaseCryptoRandomStream*);

			// Finalize the hash
			void Finalize(void);

			// Gets hash length in bits
			unsigned short int GetBitHashLength(void);

			// Gets hash length in unsigned chars
			unsigned short int GetUCHashLength(void);

			// Gets hash length in unsigned short ints
			unsigned short int GetUSHashLength(void);

			// Gets hash length in unsigned long ints
			unsigned short int GetULHashLength(void);

			// Gets hash length in unsigned 64 bits
			unsigned short int Get64HashLength(void);

			// Gets the type of the object
			Hashes GetType(void);
	};
  }
}

#endif
