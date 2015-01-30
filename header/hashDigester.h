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

/*! \mainpage HashDigester-x 6.0.0.1 Documentation
 *
 * \section intro_sec HashDigester-x implements Hash algorithms, hash digest geneartors, for Linux operating systems
 *
 *     HashDigester-x implements the following hash algorithms
 *
 *     - Secure Hash Algorithm 1, Sha 1
 *
 *     - Secure Hash Algorithm 224, Sha 224
 *
 *     - Secure Hash Algorithm 256, Sha 256
 *
 *     - Secure Hash Algorithm 384, Sha 384
 *
 *     - Secure Hash Algorithm 512, Sha 512
 *
 *     - Ripemd 128
 *
 *     - Ripemd 160
 *
 *     - Ripemd 256
 *
 *     - Ripemd 320
 *
 */

#ifndef HASHDIGESTER_HPP

#define HASHDIGESTER_HPP

#include "baseCryptoRandomStream.h"
#include "defaultCryptoRandomStream.h"
#include "physicalCryptoRandomStream.h"
#include "ripemd128.h"
#include "ripemd160.h"
#include "ripemd256.h"
#include "ripemd320.h"
#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "hashSuite.h"

#endif
