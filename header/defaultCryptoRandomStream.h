//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.4.0.0.1
//
// Copyright � 2008-2010 DiceLock Security, LLC. All rigths reserved.
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

#ifndef DEFAULTCRYPTORANDOMSTREAM_HPP

#define DEFAULTCRYPTORANDOMSTREAM_HPP


#include "baseCryptoRandomStream.h"


namespace DiceLockSecurity {

  namespace CryptoRandomStream {

	class DefaultCryptoRandomStream : public BaseCryptoRandomStream  {

	private:

			// CryptoRandomStream type enumerator name
			static const CryptoRandomStreams	cryptoRandomStreamType;

			bool	autoMemory;

		public:

			// Constructor, default
			DefaultCryptoRandomStream(void);

			// Constructor, creates an empty stream with the indicated length
			DefaultCryptoRandomStream(unsigned long int);

			// Constructor, sets the pointed stream of the indicated length
			DefaultCryptoRandomStream(void *, unsigned long int);

			// Destructor
			~DefaultCryptoRandomStream();

			// Sets an empty stream with the indicated length in bits
			void SetCryptoRandomStreamBit(unsigned long int);

			// Sets the pointed stream of indicated length in bits
			void SetCryptoRandomStreamBit(void *, unsigned long int);

			// Sets an empty stream with the indicated length in unsigned chars
			void SetCryptoRandomStreamUC(unsigned long int);

			// Sets the pointed stream of indicated length in unsigned chars
			void SetCryptoRandomStreamUC(void *, unsigned long int);

			// Sets an empty stream with the indicated length in unsigned shorts
			void SetCryptoRandomStreamUS(unsigned long int);

			// Sets the pointed stream of indicated length in unsigned shorts
			void SetCryptoRandomStreamUS(void *, unsigned long int);

			// Sets an empty stream with the indicated length in unsigned longs
			void SetCryptoRandomStreamUL(unsigned long int);

			// Sets the pointed stream of indicated length in unsigned longs
			void SetCryptoRandomStreamUL(void *, unsigned long int);

			// Set the pointed stream as hexadecimal string
			void SetCryptoRandomStreamHexString(const char*);

			// Gets the CryptoRandomStream type of the object
			CryptoRandomStreams GetCryptoRandomStreamType(void);

	};
  }
}

#endif
