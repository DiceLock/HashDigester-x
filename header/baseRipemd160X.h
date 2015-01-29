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

#ifndef BASERIPEMD_160X_HPP

#define BASERIPEMD_160X_HPP

#include "baseRipemd.h"


#define RIPEMD_J(x, y, z) ((x) ^ ((y) | ~(z)))

#define RIPEMD_Transform160X(f, a, b, c, d, e, x, s, k)\
	(*a) += f((*b), (*c), (*d)) + x + k;\
	(*a) = RIPEMD_RotateLeft((*a), s) + (*e);\
	(*c) = RIPEMD_RotateLeft((*c), 10);


namespace DiceLockSecurity {

  namespace Hash {

	  class BaseRipemd160X : public BaseRipemd  {

		protected:

			/// Constants for 160 and 320 RIPEMD algorithms
			static const unsigned long int constant4;
			static const unsigned long int constant8;

			/// Amounts of rotate left
			static const unsigned short int rl_64_79[16];
			/// Amounts of prime rotate left 
			static const unsigned short int prime_rl_64_79[16];

			/// Initial states of Ripemd 160 and 320 algorithms
			static const unsigned long int inistate4;

			/// First transform set
			void Transform_F0(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Second transform set
			void Transform_G1(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Third transform set
			void Transform_H2(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Fourth transform set
			void Transform_I3(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Fifth transform set
			void Transform_J4(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Sixth transform set
			void Transform_J5(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Seventh transform set
			void Transform_I6(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Eighth transform set
			void Transform_H7(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Ninth transform set
			void Transform_G8(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

			/// Tenth transform set
			void Transform_F9(unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*, unsigned long int*);

		public:

			/// Constructor, default 
			BaseRipemd160X();

			/// Destructor
			~BaseRipemd160X();

			/// Initializes state of Ripmed 160 and 320 algorithms
			void Initialize(void);
	  };
  }
}

#endif
