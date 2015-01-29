//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.5.0.0.1
//
// Copyright 2009-2011 DiceLock Security, LLC. All rights reserved.
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

#include "baseRipemd128X.h"
#include <stdio.h>


namespace DiceLockSecurity {
	
  namespace Hash {

	// Constructor
	BaseRipemd128X::BaseRipemd128X() {
	}

	// Destructor
	BaseRipemd128X::~BaseRipemd128X() {
	}

	// First transform set
	void BaseRipemd128X::Transform_F0(unsigned long int* a1, unsigned long int* b1, unsigned long int* c1, unsigned long int* d1, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_F, a1, b1, c1, d1, X[ 0], this->rl_0_15[ 0], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, d1, a1, b1, c1, X[ 1], this->rl_0_15[ 1], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, c1, d1, a1, b1, X[ 2], this->rl_0_15[ 2], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, b1, c1, d1, a1, X[ 3], this->rl_0_15[ 3], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, a1, b1, c1, d1, X[ 4], this->rl_0_15[ 4], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, d1, a1, b1, c1, X[ 5], this->rl_0_15[ 5], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, c1, d1, a1, b1, X[ 6], this->rl_0_15[ 6], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, b1, c1, d1, a1, X[ 7], this->rl_0_15[ 7], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, a1, b1, c1, d1, X[ 8], this->rl_0_15[ 8], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, d1, a1, b1, c1, X[ 9], this->rl_0_15[ 9], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, c1, d1, a1, b1, X[10], this->rl_0_15[10], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, b1, c1, d1, a1, X[11], this->rl_0_15[11], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, a1, b1, c1, d1, X[12], this->rl_0_15[12], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, d1, a1, b1, c1, X[13], this->rl_0_15[13], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, c1, d1, a1, b1, X[14], this->rl_0_15[14], this->constant0);
		RIPEMD_Transform128X(RIPEMD_F, b1, c1, d1, a1, X[15], this->rl_0_15[15], this->constant0);
	}

	// Second transform set
	void BaseRipemd128X::Transform_G1(unsigned long int* a1, unsigned long int* b1, unsigned long int* c1, unsigned long int* d1, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_G, a1, b1, c1, d1, X[ 7], this->rl_16_31[ 0], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, d1, a1, b1, c1, X[ 4], this->rl_16_31[ 1], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, c1, d1, a1, b1, X[13], this->rl_16_31[ 2], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, b1, c1, d1, a1, X[ 1], this->rl_16_31[ 3], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, a1, b1, c1, d1, X[10], this->rl_16_31[ 4], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, d1, a1, b1, c1, X[ 6], this->rl_16_31[ 5], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, c1, d1, a1, b1, X[15], this->rl_16_31[ 6], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, b1, c1, d1, a1, X[ 3], this->rl_16_31[ 7], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, a1, b1, c1, d1, X[12], this->rl_16_31[ 8], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, d1, a1, b1, c1, X[ 0], this->rl_16_31[ 9], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, c1, d1, a1, b1, X[ 9], this->rl_16_31[10], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, b1, c1, d1, a1, X[ 5], this->rl_16_31[11], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, a1, b1, c1, d1, X[ 2], this->rl_16_31[12], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, d1, a1, b1, c1, X[14], this->rl_16_31[13], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, c1, d1, a1, b1, X[11], this->rl_16_31[14], this->constant1);
		RIPEMD_Transform128X(RIPEMD_G, b1, c1, d1, a1, X[ 8], this->rl_16_31[15], this->constant1);
	}

	// Third transform set
	void BaseRipemd128X::Transform_H2(unsigned long int* a1, unsigned long int* b1, unsigned long int* c1, unsigned long int* d1, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_H, a1, b1, c1, d1, X[ 3], this->rl_32_47[ 0], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, d1, a1, b1, c1, X[10], this->rl_32_47[ 1], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, c1, d1, a1, b1, X[14], this->rl_32_47[ 2], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, b1, c1, d1, a1, X[ 4], this->rl_32_47[ 3], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, a1, b1, c1, d1, X[ 9], this->rl_32_47[ 4], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, d1, a1, b1, c1, X[15], this->rl_32_47[ 5], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, c1, d1, a1, b1, X[ 8], this->rl_32_47[ 6], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, b1, c1, d1, a1, X[ 1], this->rl_32_47[ 7], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, a1, b1, c1, d1, X[ 2], this->rl_32_47[ 8], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, d1, a1, b1, c1, X[ 7], this->rl_32_47[ 9], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, c1, d1, a1, b1, X[ 0], this->rl_32_47[10], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, b1, c1, d1, a1, X[ 6], this->rl_32_47[11], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, a1, b1, c1, d1, X[13], this->rl_32_47[12], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, d1, a1, b1, c1, X[11], this->rl_32_47[13], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, c1, d1, a1, b1, X[ 5], this->rl_32_47[14], this->constant2);
		RIPEMD_Transform128X(RIPEMD_H, b1, c1, d1, a1, X[12], this->rl_32_47[15], this->constant2);
	}

	// Fourth transform set
	void BaseRipemd128X::Transform_I3(unsigned long int* a1, unsigned long int* b1, unsigned long int* c1, unsigned long int* d1, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_I, a1, b1, c1, d1, X[ 1], this->rl_48_63[ 0], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, d1, a1, b1, c1, X[ 9], this->rl_48_63[ 1], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, c1, d1, a1, b1, X[11], this->rl_48_63[ 2], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, b1, c1, d1, a1, X[10], this->rl_48_63[ 3], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, a1, b1, c1, d1, X[ 0], this->rl_48_63[ 4], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, d1, a1, b1, c1, X[ 8], this->rl_48_63[ 5], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, c1, d1, a1, b1, X[12], this->rl_48_63[ 6], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, b1, c1, d1, a1, X[ 4], this->rl_48_63[ 7], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, a1, b1, c1, d1, X[13], this->rl_48_63[ 8], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, d1, a1, b1, c1, X[ 3], this->rl_48_63[ 9], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, c1, d1, a1, b1, X[ 7], this->rl_48_63[10], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, b1, c1, d1, a1, X[15], this->rl_48_63[11], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, a1, b1, c1, d1, X[14], this->rl_48_63[12], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, d1, a1, b1, c1, X[ 5], this->rl_48_63[13], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, c1, d1, a1, b1, X[ 6], this->rl_48_63[14], this->constant3);
		RIPEMD_Transform128X(RIPEMD_I, b1, c1, d1, a1, X[ 2], this->rl_48_63[15], this->constant3);
	}

	// Fifth transform set
	void BaseRipemd128X::Transform_I5(unsigned long int* a2, unsigned long int* b2, unsigned long int* c2, unsigned long int* d2, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_I, a2, b2, c2, d2, X[ 5], this->prime_rl_0_15[ 0], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, d2, a2, b2, c2, X[14], this->prime_rl_0_15[ 1], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, c2, d2, a2, b2, X[ 7], this->prime_rl_0_15[ 2], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, b2, c2, d2, a2, X[ 0], this->prime_rl_0_15[ 3], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, a2, b2, c2, d2, X[ 9], this->prime_rl_0_15[ 4], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, d2, a2, b2, c2, X[ 2], this->prime_rl_0_15[ 5], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, c2, d2, a2, b2, X[11], this->prime_rl_0_15[ 6], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, b2, c2, d2, a2, X[ 4], this->prime_rl_0_15[ 7], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, a2, b2, c2, d2, X[13], this->prime_rl_0_15[ 8], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, d2, a2, b2, c2, X[ 6], this->prime_rl_0_15[ 9], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, c2, d2, a2, b2, X[15], this->prime_rl_0_15[10], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, b2, c2, d2, a2, X[ 8], this->prime_rl_0_15[11], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, a2, b2, c2, d2, X[ 1], this->prime_rl_0_15[12], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, d2, a2, b2, c2, X[10], this->prime_rl_0_15[13], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, c2, d2, a2, b2, X[ 3], this->prime_rl_0_15[14], this->constant5);
		RIPEMD_Transform128X(RIPEMD_I, b2, c2, d2, a2, X[12], this->prime_rl_0_15[15], this->constant5);
	}

	// Sixth transform set
	void BaseRipemd128X::Transform_H6(unsigned long int* a2, unsigned long int* b2, unsigned long int* c2, unsigned long int* d2, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_H, a2, b2, c2, d2, X[ 6], this->prime_rl_16_31[ 0], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, d2, a2, b2, c2, X[11], this->prime_rl_16_31[ 1], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, c2, d2, a2, b2, X[ 3], this->prime_rl_16_31[ 2], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, b2, c2, d2, a2, X[ 7], this->prime_rl_16_31[ 3], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, a2, b2, c2, d2, X[ 0], this->prime_rl_16_31[ 4], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, d2, a2, b2, c2, X[13], this->prime_rl_16_31[ 5], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, c2, d2, a2, b2, X[ 5], this->prime_rl_16_31[ 6], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, b2, c2, d2, a2, X[10], this->prime_rl_16_31[ 7], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, a2, b2, c2, d2, X[14], this->prime_rl_16_31[ 8], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, d2, a2, b2, c2, X[15], this->prime_rl_16_31[ 9], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, c2, d2, a2, b2, X[ 8], this->prime_rl_16_31[10], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, b2, c2, d2, a2, X[12], this->prime_rl_16_31[11], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, a2, b2, c2, d2, X[ 4], this->prime_rl_16_31[12], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, d2, a2, b2, c2, X[ 9], this->prime_rl_16_31[13], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, c2, d2, a2, b2, X[ 1], this->prime_rl_16_31[14], this->constant6);
		RIPEMD_Transform128X(RIPEMD_H, b2, c2, d2, a2, X[ 2], this->prime_rl_16_31[15], this->constant6);
	}

	// Seventh transform set
	void BaseRipemd128X::Transform_G7(unsigned long int* a2, unsigned long int* b2, unsigned long int* c2, unsigned long int* d2, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_G, a2, b2, c2, d2, X[15], this->prime_rl_32_47[ 0], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, d2, a2, b2, c2, X[ 5], this->prime_rl_32_47[ 1], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, c2, d2, a2, b2, X[ 1], this->prime_rl_32_47[ 2], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, b2, c2, d2, a2, X[ 3], this->prime_rl_32_47[ 3], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, a2, b2, c2, d2, X[ 7], this->prime_rl_32_47[ 4], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, d2, a2, b2, c2, X[14], this->prime_rl_32_47[ 5], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, c2, d2, a2, b2, X[ 6], this->prime_rl_32_47[ 6], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, b2, c2, d2, a2, X[ 9], this->prime_rl_32_47[ 7], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, a2, b2, c2, d2, X[11], this->prime_rl_32_47[ 8], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, d2, a2, b2, c2, X[ 8], this->prime_rl_32_47[ 9], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, c2, d2, a2, b2, X[12], this->prime_rl_32_47[10], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, b2, c2, d2, a2, X[ 2], this->prime_rl_32_47[11], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, a2, b2, c2, d2, X[10], this->prime_rl_32_47[12], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, d2, a2, b2, c2, X[ 0], this->prime_rl_32_47[13], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, c2, d2, a2, b2, X[ 4], this->prime_rl_32_47[14], this->constant7);
		RIPEMD_Transform128X(RIPEMD_G, b2, c2, d2, a2, X[13], this->prime_rl_32_47[15], this->constant7);
	}

	// Eighth transform set
	void BaseRipemd128X::Transform_F9(unsigned long int* a2, unsigned long int* b2, unsigned long int* c2, unsigned long int* d2, unsigned long int* X) {

		RIPEMD_Transform128X(RIPEMD_F, a2, b2, c2, d2, X[ 8], this->prime_rl_48_63[ 0], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, d2, a2, b2, c2, X[ 6], this->prime_rl_48_63[ 1], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, c2, d2, a2, b2, X[ 4], this->prime_rl_48_63[ 2], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, b2, c2, d2, a2, X[ 1], this->prime_rl_48_63[ 3], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, a2, b2, c2, d2, X[ 3], this->prime_rl_48_63[ 4], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, d2, a2, b2, c2, X[11], this->prime_rl_48_63[ 5], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, c2, d2, a2, b2, X[15], this->prime_rl_48_63[ 6], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, b2, c2, d2, a2, X[ 0], this->prime_rl_48_63[ 7], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, a2, b2, c2, d2, X[ 5], this->prime_rl_48_63[ 8], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, d2, a2, b2, c2, X[12], this->prime_rl_48_63[ 9], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, c2, d2, a2, b2, X[ 2], this->prime_rl_48_63[10], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, b2, c2, d2, a2, X[13], this->prime_rl_48_63[11], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, a2, b2, c2, d2, X[ 9], this->prime_rl_48_63[12], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, d2, a2, b2, c2, X[ 7], this->prime_rl_48_63[13], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, c2, d2, a2, b2, X[10], this->prime_rl_48_63[14], this->constant9);
		RIPEMD_Transform128X(RIPEMD_F, b2, c2, d2, a2, X[14], this->prime_rl_48_63[15], this->constant9);
	}
  }
}
