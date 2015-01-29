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

#ifndef RIPEMD256_HPP

#define RIPEMD256_HPP


#include "baseRipemd128X.h"


namespace DiceLockSecurity {

  namespace Hash {

	  class Ripemd256 : public BaseRipemd128X {

		private:

			// Initial states of Ripemd 256 algorithm
			static const unsigned long int inistate4;
			static const unsigned long int inistate5;
			static const unsigned long int inistate6;
			static const unsigned long int inistate7;

			// Computes the 64 byte chunk of information
			void Compress(unsigned long int*);

	  protected:

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


		public:

			// Constructor, default
			Ripemd256();

			// Destructor
			~Ripemd256();

			// Initializes state of Ripmed 256 algorithm
			void Initialize(void);

			// Gets hash length in bits
			unsigned short int GetBitHashLength(void);

			// Gets hash length in unsigned chars
			unsigned short int GetUCHashLength(void);

			// Gets hash length in unsigned short ints
			unsigned short int GetUSHashLength(void);

			// Gets hash length in unsigned long ints
			unsigned short int GetULHashLength(void);

			// Gets the type of the object
			Hashes GetType(void);
	};
  }
}

#endif
