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

#ifndef SHA256_HPP

#define SHA256_HPP


#include "baseSha32.h"


#define SHA256_DIGESTBITS    256  // 256 hash bits
#define SHA256_DIGESTUCHARS  32   // 32  hash unsigned chars
#define SHA256_DIGESTUSHORTS 16   // 16  hash unsigned short ints
#define SHA256_DIGESTULONGS  8    // 8   hash unsigned long ints

#define SHA256_COMPUTECONSTANTS 64

#define SHA256_MESSAGESCHEDULE 64

#define SHA256_OPERATIONS 64

#define SHA256_RotateRight(x, n) (((x)>>(n)) | ((x)<<(32-(n))))
#define SHA256_ShiftRight(x, n) ((x)>>(n))

#define SHA256_SUM_0(x) (SHA256_RotateRight(x, 2) ^ SHA256_RotateRight(x, 13) ^ SHA256_RotateRight(x, 22))
#define SHA256_SUM_1(x) (SHA256_RotateRight(x, 6) ^ SHA256_RotateRight(x, 11) ^ SHA256_RotateRight(x, 25))
#define SHA256_SIG_0(x) (SHA256_RotateRight(x, 7) ^ SHA256_RotateRight(x, 18) ^ SHA256_ShiftRight(x, 3))
#define SHA256_SIG_1(x) (SHA256_RotateRight(x, 17) ^ SHA256_RotateRight(x, 19) ^ SHA256_ShiftRight(x, 10))


namespace DiceLockSecurity {

  namespace Hash {

	class Sha256 : public BaseSha32 {

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

			// Number of schedule words
			static const unsigned short int scheduleNumber;

			// Initial hash values of SHA256
			static const unsigned long int initials[SHA256_DIGESTULONGS];

			// Computational constant values of SHA256
			static const unsigned long int constants[SHA256_COMPUTECONSTANTS];

			// Message schedule words for SHA256
			unsigned long int messageSchedule[SHA256_MESSAGESCHEDULE];

		protected:

			// Computes the chunk block of information
			void Compress(BaseCryptoRandomStream*, unsigned char*);

		public:

			// Constructor, default
			Sha256();

			// Destructor
			~Sha256();

			// Initializes common states of Sha1 algorithm
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
