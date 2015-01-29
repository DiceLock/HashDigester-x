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

#ifndef HASHSUITE_HPP

#define HASHSUITE_HPP


#include "hashDigester.h"


namespace DiceLockSecurity {

  namespace Hash {

	  class HashSuite {

		protected:

			// Points the first hash algorithm in the suite
			static const	Hashes firstHash;

			BaseHash*				suite[NumberOfHashes];
			bool					selfCreatedHash[NumberOfHashes];
			int						instantiatedHashes;

		public:

			// Constructor, default, initializes suite
			HashSuite();

			// Destructor
			~HashSuite();

			// ADDING HASHES

			// Adds a hash to the suite
			void Add(BaseHash*);

			// Creates and adds a hash to the suite based in the enumerated hash list
			void Add(Hashes);

			// Creates and adds all hash algorithms to the suite
			void AddAll(void);

			// Creates and adds the defined hash to the suite
			void AddSha1(void);

			// Creates and adds the defined hash to the suite
			void AddSha224(void);

			// Creates and adds the defined hash to the suite
			void AddSha256(void);

			// Creates and adds the defined hash to the suite
			void AddSha384(void);

			// Creates and adds the defined hash to the suite
			void AddSha512(void);

			// Creates and adds the defined hash to the suite
			void AddRipemd128(void);

			// Creates and adds the defined hash to the suite
			void AddRipemd160(void);

			// Creates and adds the defined hash to the suite
			void AddRipemd256(void);

			// Creates and adds the defined hash to the suite
			void AddRipemd320(void);

			// GETTING HASH OBJECT

			// Gets a hash algorithm from the suite based in the enumerated hash
			BaseHash* GetMessageDigest(Hashes);

			// Gets the defined hash from the suite
			Sha1* GetSha1(void);

			// Gets the defined hash from the suite
			Sha224* GetSha224(void);

			// Gets the defined hash from the suite
			Sha256* GetSha256(void);

			// Gets the defined hash from the suite
			Sha384* GetSha384(void);

			// Gets the defined hash from the suite
			Sha512* GetSha512(void);

			// Gets the defined hash from the suite
			Ripemd128* GetRipemd128(void);

			// Gets the defined hash from the suite
			Ripemd160* GetRipemd160(void);

			// Gets the defined hash from the suite
			Ripemd256* GetRipemd256(void);

			// Gets the defined hash from the suite
			Ripemd320* GetRipemd320(void);

			// REMOVING HASH ALGORITHMS

			// Removes the pointed hash from the suite
			void Remove(BaseHash*);

			// Removes a hash from the suite based in the enumerated hash algorithms
			void Remove(Hashes);

			// Removes all hash algorithms from the suite
			void RemoveAll(void);

			// Removes the defined hash from the suite
			void RemoveSha1(void);

			// Removes the defined hash from the suite
			void RemoveSha224(void);

			// Removes the defined hash from the suite
			void RemoveSha256(void);

			// Removes the defined hash from the suite
			void RemoveSha384(void);

			// Removes the defined hash from the suite
			void RemoveSha512(void);

			// Removes the defined hash from the suite
			void RemoveRipemd128(void);

			// Removes the defined hash from the suite
			void RemoveRipemd160(void);

			// Removes the defined hash from the suite
			void RemoveRipemd256(void);

			// Removes the defined hash from the suite
			void RemoveRipemd320(void);

			// PERFORMING HASH

			// Performs the hash algorithms of BaseCryptoRandomStream with all instantiated hash
			void Hash(BaseCryptoRandomStream*);

			// INITIALIZE SUITE

			// Initializes all hash algorithms in the suite
			void Initialize(void);

			// ADDS STREAM TO THE SUITE

			// Adds BaseCryptoRandomStream stream to hash algorithms in the suite
			void Add(BaseCryptoRandomStream*);

			// FINALIZE THE SUITE

			// Finalize hash algorithms in the suite
			void Finalize(void);

			// GETTING SUITE INFORMATION

			// Gets the number of hash algorithms that contains the suite
			unsigned long int GetInstantiatedHashes(void);

			// Indicates if a hash algorithm exists in the suite
			bool Exist(Hashes);

			// Gets the first hash algorithm in the HashSuite
			Hashes GetFirstHash(void);

			// Gets the number of hash algorithms that can be used in the HahsSuite
			Hashes GetMaximumNumberOfHashes(void);
	};
  }
}

#endif
