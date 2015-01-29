//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.4.0.0.1
//
// Copyright  2009-2010 DiceLock Security, LLC. All rigths reserved.
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
#include "baseHash.h"


namespace DiceLockSecurity {

  namespace Hash {

	// Constructor
	BaseHash::BaseHash() {
	}

	// Constructor assigning digest BaseCryptoRandomStream
	BaseHash::BaseHash(BaseCryptoRandomStream* digest) {

		this->messageDigest = digest;
	}

	// Destructor
	BaseHash::~BaseHash() {

		if (this->messageDigest != NULL) {
			this->messageDigest = NULL;
		}
	}

	// Set the Digest Message BaseCryptoRandomStream
	void BaseHash::SetMessageDigest(BaseCryptoRandomStream* digest) {

		this->messageDigest = digest;
	}

	// Gets the hash
	BaseCryptoRandomStream* BaseHash::GetMessageDigest(void) {

		return this->messageDigest;
	}
  }
}
