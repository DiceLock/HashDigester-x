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

#include <stdlib.h>
#include "hashSuite.h"


namespace DiceLockSecurity {
	
  namespace Hash {

		// Points the first hash in the suite
		const Hashes HashSuite::firstHash = SHA_1;

		// Constructor, default, initializes suite 
		HashSuite::HashSuite() {
			unsigned short int i;

			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				this->suite[i] = NULL;
				this->selfCreatedHash[i] = false;
			}
			this->instantiatedHashes = 0;
		}

		// Destructor
		HashSuite::~HashSuite() {
			unsigned short int i;

			for (i = this->GetFirstHash(); i < this->GetMaximumNumberOfHashes(); i++) {
				if ((this->selfCreatedHash[i]) && (this->suite[i] != NULL)) {
					delete this->suite[i];
					this->suite[i] = NULL;
				    this->selfCreatedHash[i] = false;
				}
			}
			this->instantiatedHashes = 0;
		}

		// ADDING HASHES
			
		// Adds a random test to the suite
		void HashSuite::Add(BaseHash* hash) {

			if (hash != NULL) {
				this->suite[hash->GetType()] = hash;
				this->selfCreatedHash[hash->GetType()] = false;
				this->instantiatedHashes++;
			}
		}

		// Creates and adds a random test to the suite based in the enumerated random tests
		void HashSuite::Add(Hashes hash) {

			switch (hash) {
				case SHA_1: 
					if (this->suite[SHA_1] == NULL) {
						this->suite[SHA_1] = new Sha1();
						this->instantiatedHashes++;
					}
					break;
				case SHA_224: 
					if (this->suite[SHA_224] == NULL) {
						this->suite[SHA_224] = new Sha224();
						this->instantiatedHashes++;
					}
					break;
				case SHA_256: 
					if (this->suite[SHA_256] == NULL) {
						this->suite[SHA_256] = new Sha256();
						this->instantiatedHashes++;
					}
					break;
				case SHA_384: 
					if (this->suite[SHA_384] == NULL) {
						this->suite[SHA_384] = new Sha384();
						this->instantiatedHashes++;
					}
					break;
				case SHA_512: 
					if (this->suite[SHA_512] == NULL) {
						this->suite[SHA_512] = new Sha512();
						this->instantiatedHashes++;
					}
					break;
				case RIPEMD_128: 
					if (this->suite[RIPEMD_128] == NULL) {
						this->suite[RIPEMD_128] = new Ripemd128();
						this->instantiatedHashes++;
					}
					break;
				case RIPEMD_160: 
					if (this->suite[RIPEMD_160] == NULL) {
						this->suite[RIPEMD_160] = new Ripemd160();
						this->instantiatedHashes++;
					}
					break;
				case RIPEMD_256: 
					if (this->suite[RIPEMD_256] == NULL) {
						this->suite[RIPEMD_256] = new Ripemd256();
						this->instantiatedHashes++;
					}
					break;
				case RIPEMD_320: 
					if (this->suite[RIPEMD_320] == NULL) {
						this->suite[RIPEMD_320] = new Ripemd320();
						this->instantiatedHashes++;
					}
					break;
				default:
					break;
			}
			this->selfCreatedHash[hash] = true;
		}

		// Creates and adds all hash algorithms to the suite 
		void HashSuite::AddAll(void) {
			unsigned short int i;

			this->suite[SHA_1] = new Sha1();
			this->suite[SHA_224] = new Sha224();
			this->suite[SHA_256] = new Sha256();
			this->suite[SHA_384] = new Sha384();
			this->suite[SHA_512] = new Sha512();
			this->suite[RIPEMD_128] = new Ripemd128();
			this->suite[RIPEMD_160] = new Ripemd160();
			this->suite[RIPEMD_256] = new Ripemd256();
			this->suite[RIPEMD_320] = new Ripemd320();
			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				this->selfCreatedHash[i] = true;
			}
			this->instantiatedHashes = NumberOfHashes;

		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddSha1(void) {

			this->suite[SHA_1] = new Sha1();
			this->selfCreatedHash[SHA_1] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddSha224(void) {

			this->suite[SHA_224] = new Sha224();
			this->selfCreatedHash[SHA_224] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddSha256(void) {

			this->suite[SHA_256] = new Sha256();
			this->selfCreatedHash[SHA_256] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddSha384(void) {

			this->suite[SHA_384] = new Sha384();
			this->selfCreatedHash[SHA_384] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddSha512(void) {

			this->suite[SHA_512] = new Sha512();
			this->selfCreatedHash[SHA_512] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddRipemd128(void) {

			this->suite[RIPEMD_128] = new Ripemd128();
			this->selfCreatedHash[RIPEMD_128] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddRipemd160(void) {

			this->suite[RIPEMD_160] = new Ripemd160();
			this->selfCreatedHash[RIPEMD_160] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddRipemd256(void) {

			this->suite[RIPEMD_256] = new Ripemd256();
			this->selfCreatedHash[RIPEMD_256] = true;
			this->instantiatedHashes++;
		}

		// Creates and adds the defined hash to the suite
		void HashSuite::AddRipemd320(void) {

			this->suite[RIPEMD_320] = new Ripemd320();
			this->selfCreatedHash[RIPEMD_320] = true;
			this->instantiatedHashes++;
		}

		// GETTING HASH OBJECT
			
		// Gets a hash algorithm from the suite based in the enumerated hash
		BaseHash* HashSuite::GetMessageDigest(Hashes hash) {

			return this->suite[hash];
		}

		// Gets the defined hash from the suite
		Sha1* HashSuite::GetSha1(void) {

			return (Sha1 *)this->suite[SHA_1];
		}

		// Gets the defined hash from the suite
		Sha224* HashSuite::GetSha224(void) {

			return (Sha224 *)this->suite[SHA_224];
		}

		// Gets the defined hash from the suite
		Sha256* HashSuite::GetSha256(void) {

			return (Sha256 *)this->suite[SHA_256];
		}

		// Gets the defined hash from the suite
		Sha384* HashSuite::GetSha384(void) {

			return (Sha384 *)this->suite[SHA_384];
		}

		// Gets the defined hash from the suite
		Sha512* HashSuite::GetSha512(void) {

			return (Sha512 *)this->suite[SHA_512];
		}

		// Gets the defined hash from the suite
		Ripemd128* HashSuite::GetRipemd128(void) {

			return (Ripemd128 *)this->suite[RIPEMD_128];
		}

		// Gets the defined hash from the suite
		Ripemd160* HashSuite::GetRipemd160(void) {

			return (Ripemd160 *)this->suite[RIPEMD_160];
		}

		// Gets the defined hash from the suite
		Ripemd256* HashSuite::GetRipemd256(void) {

			return (Ripemd256 *)this->suite[RIPEMD_256];
		}

		// Gets the defined hash from the suite
		Ripemd320* HashSuite::GetRipemd320(void) {

			return (Ripemd320 *)this->suite[RIPEMD_320];
		}

		// REMOVING HASH ALGORITHMS

		// Removes a pointed hash algorithm from the suite
		void HashSuite::Remove(BaseHash* hashObject) {
			Hashes hash;

			hash = hashObject->GetType();
			if ((this->suite[hash] != NULL) && (this->suite[hash] == hashObject)) {
				if (this->selfCreatedHash[hash]) {
					delete this->suite[hash];
				}
				this->suite[hash] = NULL;
				this->selfCreatedHash[hash] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes a hash algorithm from the suite based in the enumerated hash algorithm
		void HashSuite::Remove(Hashes hash) {

			if (this->suite[hash] != NULL) {
				if (this->selfCreatedHash[hash]) {
					delete this->suite[hash];
				}
				this->suite[hash] = NULL;
				this->selfCreatedHash[hash] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes all hash algorithms from the suite
		void HashSuite::RemoveAll(void) {
			unsigned short int i;

			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				if (this->suite[i] != NULL) {
					if (this->selfCreatedHash[i]) {
						delete this->suite[i];
					}
					this->suite[i] = NULL;
				    this->selfCreatedHash[i] = false;
				}
			}
			this->instantiatedHashes = 0;
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveSha1(void) {

			if (this->suite[SHA_1] != NULL) {
				if (this->selfCreatedHash[SHA_1]) {
					delete this->suite[SHA_1];
				}
				this->suite[SHA_1] = NULL;
			    this->selfCreatedHash[SHA_1] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveSha224(void) {

			if (this->suite[SHA_224] != NULL) {
				if (this->selfCreatedHash[SHA_224]) {
					delete this->suite[SHA_224];
				}
				this->suite[SHA_224] = NULL;
			    this->selfCreatedHash[SHA_224] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveSha256(void) {

			if (this->suite[SHA_256] != NULL) {
				if (this->selfCreatedHash[SHA_256]) {
					delete this->suite[SHA_256];
				}
				this->suite[SHA_256] = NULL;
			    this->selfCreatedHash[SHA_256] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveSha384(void) {

			if (this->suite[SHA_384] != NULL) {
				if (this->selfCreatedHash[SHA_384]) {
					delete this->suite[SHA_384];
				}
				this->suite[SHA_384] = NULL;
			    this->selfCreatedHash[SHA_384] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveSha512(void) {

			if (this->suite[SHA_512] != NULL) {
				if (this->selfCreatedHash[SHA_512]) {
					delete this->suite[SHA_512];
				}
				this->suite[SHA_512] = NULL;
			    this->selfCreatedHash[SHA_512] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveRipemd128(void) {

			if (this->suite[RIPEMD_128] != NULL) {
				if (this->selfCreatedHash[RIPEMD_128]) {
					delete this->suite[RIPEMD_128];
				}
				this->suite[RIPEMD_128] = NULL;
			    this->selfCreatedHash[RIPEMD_128] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveRipemd160(void) {

			if (this->suite[RIPEMD_160] != NULL) {
				if (this->selfCreatedHash[RIPEMD_160]) {
					delete this->suite[RIPEMD_160];
				}
				this->suite[RIPEMD_160] = NULL;
			    this->selfCreatedHash[RIPEMD_160] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveRipemd256(void) {

			if (this->suite[RIPEMD_256] != NULL) {
				if (this->selfCreatedHash[RIPEMD_256]) {
					delete this->suite[RIPEMD_256];
				}
				this->suite[RIPEMD_256] = NULL;
			    this->selfCreatedHash[RIPEMD_256] = false;
				this->instantiatedHashes--;
			}
		}

		// Removes the defined hash from the suite
		void HashSuite::RemoveRipemd320(void) {

			if (this->suite[RIPEMD_320] != NULL) {
				if (this->selfCreatedHash[RIPEMD_320]) {
					delete this->suite[RIPEMD_320];
				}
				this->suite[RIPEMD_320] = NULL;
			    this->selfCreatedHash[RIPEMD_320] = false;
				this->instantiatedHashes--;
			}
		}

		// PERFORMING HASH

		// Performs the hash algorithms of BaseCryptoRandomStream with all instantiated hash 
		void HashSuite::Hash(BaseCryptoRandomStream* stream) {
			unsigned short int i;
			
			this->Initialize();
			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				if (this->suite[i] != NULL) {
					this->suite[i]->Add(stream); 
					this->suite[i]->Finalize(); 
				}
			}
		}

		// INITIALIZE SUITE
			
		// Initializes all hash algorithms in the suite
		void HashSuite::Initialize(void) {
			unsigned short int i;
			
			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				if (this->suite[i] != NULL) {
					this->suite[i]->Initialize();
				}
			}
		}

		// ADDS STREAM TO THE SUITE
			
		// Adds BaseCryptoRandomStream stream to hash algorithms in the suite
		void HashSuite::Add(BaseCryptoRandomStream* stream) {
			int i;
			
			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				if (this->suite[i] != NULL) {
					this->suite[i]->Add(stream);
				}
			}
		}

		// FINALIZE THE SUITE
			
		// Finalize hash algorithms in the suite
		void HashSuite::Finalize(void) {
			unsigned short int i;
			
			for (i=this->GetFirstHash(); i<this->GetMaximumNumberOfHashes(); i++) {
				if (this->suite[i] != NULL) {
					this->suite[i]->Finalize();
				}
			}
		}

		// GETTING SUITE INFORMATION

		// Gets the number of hash algorithms that contains the suite
		unsigned long int HashSuite::GetInstantiatedHashes(void) {

			return this->instantiatedHashes;
		}

		// Indicates if a hash algorithm object exists in the suite
		bool HashSuite::Exist(Hashes hash) {

			return (this->suite[hash] != NULL);
		}

		// Gets the first hash algorithm in the HashSuite
		Hashes HashSuite::GetFirstHash(void) {

			return this->firstHash;
		}

		// Gets the number of hash algorithms that can be used in the HahsSuite
		Hashes HashSuite::GetMaximumNumberOfHashes(void) {

			return NumberOfHashes;
		}
	}
}
