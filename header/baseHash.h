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

#ifndef BASEHASH_HPP

#define BASEHASH_HPP


#include "baseCryptoRandomStream.h"

using namespace DiceLockSecurity;
using namespace DiceLockSecurity::CryptoRandomStream;


namespace DiceLockSecurity {

  namespace Hash {

	enum Hashes {
		SHA_1,
		SHA_224,
		SHA_256,
		SHA_384,
		SHA_512,
		RIPEMD_128,
		RIPEMD_160,
		RIPEMD_256,
		RIPEMD_320,
		NumberOfHashes,		// Indication of the number of hash alforithms, any added hash algorithm must be inserted before
		NotDefined,
	};

	class BaseHash {

		protected:

			// Pointer to BaseCryptoRandomStream digest
			BaseCryptoRandomStream* messageDigest;

		public:

			// Constructor, default
			BaseHash();

			// Constructor assigning diggest BaseCryptoRandomStream
			BaseHash(BaseCryptoRandomStream*);

			// Destructor
			virtual ~BaseHash();

			// Set the Message Digest BaseCryptoRandomStream
			void SetMessageDigest(BaseCryptoRandomStream*);

			// Initialize BaseHash
			virtual void Initialize() {};

			// Adds the BaseCryptoRandomStream
			virtual void Add(BaseCryptoRandomStream*) {};

			// Finalize the hash
			virtual void Finalize(void) {};

			// Gets the hash
			BaseCryptoRandomStream* GetMessageDigest(void);

			// Gets hash length in bits
			virtual unsigned short int GetBitHashLength(void) {return 0;};

			// Gets hash length in unsigned chars
			virtual unsigned short int GetUCHashLength(void) {return 0;};

			// Gets hash length in unsigned short ints
			virtual unsigned short int GetUSHashLength(void) {return 0;};

			// Gets hash length in unsigned long ints
			virtual unsigned short int GetULHashLength(void) {return 0;};

			// Gets the type of the object
			virtual Hashes GetType(void) {return NotDefined;};
	};
  }
}

#endif
