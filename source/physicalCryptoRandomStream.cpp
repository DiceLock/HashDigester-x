//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.6.0.0.1
//
// Copyright  2008-2012 DiceLock Security, LLC. All rights reserved.
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
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "physicalCryptoRandomStream.h"


namespace DiceLockSecurity {

  namespace CryptoRandomStream {

	// Symmetric cipher type enumerator name
	const CryptoRandomStreams	PhysicalCryptoRandomStream::cryptoRandomStreamType = PhysicalStream;

	// Constructor, default
	PhysicalCryptoRandomStream::PhysicalCryptoRandomStream(void) {

		this->cryptoStream = NULL;
		this->autoMemory = false;
		this->bitLength = 0;
		this->position = 0;
	}

	// Constructor, creates an empty stream with the indicated bit length
	PhysicalCryptoRandomStream::PhysicalCryptoRandomStream(unsigned long int streamLength) {
		unsigned long int streamLengthBytes;

		try {
			if (streamLength % BYTEBITS) {
				streamLengthBytes = (streamLength / BYTEBITS) + 1;
			}
			else {
				streamLengthBytes = streamLength / BYTEBITS;
			}
			this->AllocPhysical(streamLengthBytes);
			this->bitLength = streamLength;
			this->position = 0;
		}
		catch (char* str) {
			throw str;
		}
	}

	// Constructor, sets the pointed stream of the indicated length in bits
	PhysicalCryptoRandomStream::PhysicalCryptoRandomStream(void* stream, unsigned long int streamLength) {
		unsigned long int streamLengthBytes;
		int error_return;


		if ( stream != NULL ) {
			if (streamLength % BYTEBITS) {
				streamLengthBytes = (streamLength / BYTEBITS) + 1;
			}
			else {
				streamLengthBytes = streamLength / BYTEBITS;
			}
			this->cryptoStream = (unsigned char *)stream;
			if ( (error_return = mlock(this->cryptoStream, streamLengthBytes)) ) {
				throw "Error locking RAM memory";
			}
			this->bitLength = streamLength;
			this->autoMemory = false;
		}
	}

	// Destructor
	PhysicalCryptoRandomStream::~PhysicalCryptoRandomStream() {

		this->FreePhysical();
		this->cryptoStream = NULL;
		this->bitLength = 0;
		this->position = 0;
		this->autoMemory = false;
	}

	/// Allocates and locks pages in RAM memory, streamLengthBytes in bytes
	void PhysicalCryptoRandomStream::AllocPhysical(unsigned long int streamLengthBytes) {
		size_t page_size;
		size_t i;
		int error_return;

		this->cryptoStream = (unsigned char *)malloc(streamLengthBytes);
		if ( (error_return = mlock(this->cryptoStream, streamLengthBytes)) ) {
			throw "Error allocating RAM memory";
		}
		page_size = getpagesize();
		for (i = 0; i < streamLengthBytes; i += page_size) {
			this->cryptoStream[i] = 0;
		}
		this->autoMemory = true;
	}

	/// Frees locked pages in RAM memory
	void PhysicalCryptoRandomStream::FreePhysical() {
		unsigned long int streamLengthBytes;

		if (this->bitLength % BYTEBITS) {
			streamLengthBytes = (this->bitLength / BYTEBITS) + 1;
		}
		else {
			streamLengthBytes = this->bitLength / BYTEBITS;
		}
		munlock(this->cryptoStream, streamLengthBytes);
		if ( this->autoMemory ) {
			free(this->cryptoStream);
		}
		this->autoMemory = false;
	}

	// Sets an empty stream with the indicated length in bits
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamBit(unsigned long int streamLength) {
		unsigned long int streamLengthBytes;

		if (this->cryptoStream == NULL) {
			try {
				if (streamLength % BYTEBITS) {
					streamLengthBytes = (streamLength / BYTEBITS) + 1;
				}
				else {
					streamLengthBytes = streamLength / BYTEBITS;
				}
				this->AllocPhysical(streamLengthBytes);
				this->bitLength = streamLength;
				this->position = 0;
			}
			catch (char* str) {
				throw str;
			}
		}
	}

	// Sets the pointed stream of indicated length in bits
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamBit(void* stream, unsigned long int streamLength) {
		unsigned long int streamLengthBytes;
		int error_return;


		if ( stream != NULL ) {
			if (streamLength % BYTEBITS) {
				streamLengthBytes = (streamLength / BYTEBITS) + 1;
			}
			else {
				streamLengthBytes = streamLength / BYTEBITS;
			}
			this->cryptoStream = (unsigned char *)stream;
			if ( (error_return = mlock(this->cryptoStream, streamLengthBytes)) ) {
				throw "Error locking RAM memory";
			}
			this->bitLength = streamLength;
			this->position = 0;
			this->autoMemory = false;
		}
	}

	// Sets an empty stream with the indicated length in unsigned chars
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamUC(unsigned long int streamLength) {

		if (this->cryptoStream == NULL) {
			try {
				this->AllocPhysical(streamLength);
				this->bitLength = streamLength * BYTEBITS * sizeof(unsigned char);
				this->position = 0;
			}
			catch (char* str) {
				throw str;
			}
		}
	}

	// Sets the pointed stream of indicated length in unsigned chars
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamUC(void* stream, unsigned long int streamLength) {
		int error_return;

		if (stream != NULL) {
			this->cryptoStream = (unsigned char *)stream;
			if ( (error_return = mlock(this->cryptoStream, streamLength)) ) {
				throw "Error locking RAM memory";
			}
			this->bitLength = streamLength * BYTEBITS * sizeof(unsigned char);
			this->position = 0;
			this->autoMemory = false;
		}
	}

	// Sets an empty stream with the indicated length in unsigned shorts
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamUS(unsigned long int streamLength) {

		if (this->cryptoStream == NULL) {
			try {
				this->AllocPhysical(streamLength * sizeof(unsigned short int));
				this->bitLength = streamLength * BYTEBITS * sizeof(unsigned short int);
				this->position = 0;
			}
			catch (char* str) {
				throw str;
			}
		}
	}

	// Sets the pointed stream of indicated length in unsigned shorts
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamUS(void* stream, unsigned long int streamLength) {
		int error_return;

		if (stream != NULL) {
			this->cryptoStream = (unsigned char *)stream;
			if ( (error_return = mlock(this->cryptoStream, streamLength * sizeof(unsigned short int))) ) {
				throw "Error locking RAM memory";
			}
			this->bitLength = streamLength * BYTEBITS * sizeof(unsigned short int);
			this->position = 0;
			this->autoMemory = false;
		}
	}

	// Sets an empty stream with the indicated length in unsigned longs
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamUL(unsigned long int streamLength) {

		if (this->cryptoStream == NULL) {
			try {
				this->AllocPhysical(streamLength * sizeof(unsigned long int));
				this->bitLength = streamLength * BYTEBITS * sizeof(unsigned long int);
				this->position = 0;
			}
			catch (char* str) {
				throw str;
			}
		}
	}

	// Sets the pointed stream of indicated length in unsigned longs
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamUL(void* stream, unsigned long int streamLength) {
		int error_return;

		if (stream != NULL) {
			this->cryptoStream = (unsigned char *)stream;
			if ( (error_return = mlock(this->cryptoStream, streamLength * sizeof(unsigned long int))) ) {
				throw "Error locking RAM memory";
			}
			this->bitLength = streamLength * BYTEBITS * sizeof(unsigned long int);
			this->position = 0;
			this->autoMemory = false;
		}
	}

	// Set the pointed stream as hexadecimal string
	void PhysicalCryptoRandomStream::SetCryptoRandomStreamHexString(const char* hexStream) {
	unsigned long int lengthUC, i, streamLength;
	unsigned char byte;

		try {
			streamLength = strlen(hexStream);
			if ( streamLength % 2 ) {
				throw "Erroneous hexadecimal string!";
			}
			else {
				lengthUC = streamLength / 2;
				this->AllocPhysical(lengthUC);
				if (this->cryptoStream == NULL )
					throw "Memory allocation failure!";
				else {
					this->autoMemory = true;
					this->bitLength = lengthUC * BYTEBITS * sizeof(unsigned char);
					this->position = 0;
					for ( i = 0; i < lengthUC; i++ ) {
						byte = 0;
						switch ( hexStream[ 2 * i ] ) {
							case '0' : byte = 0x00; break;
							case '1' : byte = 0x10; break;
							case '2' : byte = 0x20; break;
							case '3' : byte = 0x30; break;
							case '4' : byte = 0x40; break;
							case '5' : byte = 0x50; break;
							case '6' : byte = 0x60; break;
							case '7' : byte = 0x70; break;
							case '8' : byte = 0x80; break;
							case '9' : byte = 0x90; break;
							case 'A' :
							case 'a' : byte = 0xa0; break;
							case 'B' :
							case 'b' : byte = 0xb0; break;
							case 'C' :
							case 'c' : byte = 0xc0; break;
							case 'D' :
							case 'd' : byte = 0xd0; break;
							case 'E' :
							case 'e' : byte = 0xe0; break;
							case 'F' :
							case 'f' : byte = 0xf0; break;
							default :
								throw "Erroneous hexadecimal string!";
								break;
						}
						switch ( hexStream[ (2 * i) + 1 ] ) {
							case '0' : byte = byte | 0x00; break;
							case '1' : byte = byte | 0x01; break;
							case '2' : byte = byte | 0x02; break;
							case '3' : byte = byte | 0x03; break;
							case '4' : byte = byte | 0x04; break;
							case '5' : byte = byte | 0x05; break;
							case '6' : byte = byte | 0x06; break;
							case '7' : byte = byte | 0x07; break;
							case '8' : byte = byte | 0x08; break;
							case '9' : byte = byte | 0x09; break;
							case 'A' :
							case 'a' : byte = byte | 0x0a; break;
							case 'B' :
							case 'b' : byte = byte | 0x0b; break;
							case 'C' :
							case 'c' : byte = byte | 0x0c; break;
							case 'D' :
							case 'd' : byte = byte | 0x0d; break;
							case 'E' :
							case 'e' : byte = byte | 0x0e; break;
							case 'F' :
							case 'f' : byte = byte | 0x0f; break;
							default :
								throw "Erroneous hexadecimal string!";
								break;
						}
						this->SetUCPosition(i, byte);
					}
				}
			}
		}
		catch (char* str) {
			throw str;
		}
	}

	// Gets the CryptoRandomStream type of the object
	CryptoRandomStreams PhysicalCryptoRandomStream::GetCryptoRandomStreamType(void) {

		return this->cryptoRandomStreamType;
	}
  }
}
