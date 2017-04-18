/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include "rte_atomic.h"
#include "tsx.h"
int max_retries = 3;

static void
run_cpuid (uint32_t eax, uint32_t ecx, uint32_t *abcd)
{
  uint32_t ebx = 0, edx = 0;

#if defined(__i386__) && defined (__PIC__)
  /* in case of PIC under 32-bit EBX cannot be clobbered */
__asm__ ("movl %%ebx, %%edi \n\t cpuid \n\t xchgl %%ebx, %%edi":"=D" (ebx),
#else
__asm__ ("cpuid":"+b" (ebx),
#endif
		 "+a" (eax), "+c" (ecx), "=d" (edx));
  abcd[0] = eax;
  abcd[1] = ebx;
  abcd[2] = ecx;
  abcd[3] = edx;
}

static int
check_xcr0_ymm (void)
{
uint32_t xcr0;
__asm__ ("xgetbv" : "=a" (xcr0) : "c" (0) : "%edx");
return ((xcr0 & 6) == 6);/* checking if xmm and ymm state are enabled in XCR0 */
}

static int
check_4th_gen_intel_core_features (void)
{
  uint32_t abcd[4];
  uint32_t fma_movbe_osxsave_mask = ((1 << 12) | (1 << 22) | (1 << 27));
  uint32_t avx2_bmi12_mask = (1 << 5) | (1 << 3) | (1 << 8);

  /* CPUID.(EAX=01H, ECX=0H):ECX.FMA[bit 12]==1   &&
     CPUID.(EAX=01H, ECX=0H):ECX.MOVBE[bit 22]==1 &&
     CPUID.(EAX=01H, ECX=0H):ECX.OSXSAVE[bit 27]==1 */
  run_cpuid (1, 0, abcd);
  if ((abcd[2] & fma_movbe_osxsave_mask) != fma_movbe_osxsave_mask) {
		printf ("Failing in if cond-1\n");
		return 0;
  }
  if (!check_xcr0_ymm ()) {
		printf ("Failing in if cond-2\n");
		return 0;
  }

  /*  CPUID.(EAX=07H, ECX=0H):EBX.AVX2[bit 5]==1  &&
     CPUID.(EAX=07H, ECX=0H):EBX.BMI1[bit 3]==1  &&
     CPUID.(EAX=07H, ECX=0H):EBX.BMI2[bit 8]==1  */
  run_cpuid (7, 0, abcd);
  if ((abcd[1] & avx2_bmi12_mask) != avx2_bmi12_mask) {
      printf ("Failing in if cond-3\n");
      return 0;
    }
  /* CPUID.(EAX=80000001H):ECX.LZCNT[bit 5]==1 */
  run_cpuid (0x80000001, 0, abcd);
  if ((abcd[2] & (1 << 5)) == 0) {
      printf ("Failing in if cond-4\n");
      return 0;
    }
  /* CPUID.(EAX=07H, ECX=0H).EBX.RTM[bit 11]==1 */
  run_cpuid (7, 0, abcd);
  if ((abcd[1] & (1 << 11)) == 0) {
      printf ("Failing in if cond-5\n");
      return 0;
    }
  /* CPUID.(EAX=07H, ECX=0H).EBX.HLE[bit 4]==1 */
  run_cpuid (7, 0, abcd);
  if ((abcd[1] & (1 << 4)) == 0) {
      printf ("Failing in if cond-6\n");
      return 0;
    }
  return 1;
}

int
can_use_intel_core_4th_gen_features (void)
{
  static int the_4th_gen_features_available = -1;
  /* test is performed once */
  if (the_4th_gen_features_available < 0)
    the_4th_gen_features_available = check_4th_gen_intel_core_features ();
  return the_4th_gen_features_available;
}

void
rtm_init (void)
{
  naborted = (rte_atomic64_t) RTE_ATOMIC64_INIT (0);

  //RTE_ATOMIC64_INIT(naborted);
} int

rtm_lock (void)
{
  int nretries = 0;
  while (1) {
      ++nretries;
      unsigned int status = _xbegin ();
      if (status == _XBEGIN_STARTED) {
		if (!is_hle_locked ())
			return 1;		// successfully started transaction
		// started transaction but someone executes the transaction section
		// non-speculatively (acquired the fall-back lock)
		_xabort (0xff);	// abort with code 0xff
	}
      // abort handler
      rte_atomic64_inc (&naborted);	// do abort statistics
      printf
	("DEBUG: Transaction aborted: %d time(s) with the status: %u\n",
	 nretries, status);
      // handle _xabort(0xff) from above
      if ((status & _XABORT_EXPLICIT)
		&& _XABORT_CODE (status) == 0xff && !(status & _XABORT_NESTED)) {
		while (is_hle_locked ())
			_mm_pause ();	// wait until lock is free
	}
      else if (!(status & _XABORT_RETRY))
	break;			// take the fall-back lock if the retry abort flag is not set
      if (nretries >= max_retries)
	break;			// too many retries, take the fall-back lock
    }
  hle_lock ();
  return 1;
}

int
rtm_unlock (void)
{
  if (is_hle_locked ())
    hle_release ();

  else
    _xend ();
  return 1;
}

int
is_rtm_locked (void)
{
  return ((int) _xtest ());
}
