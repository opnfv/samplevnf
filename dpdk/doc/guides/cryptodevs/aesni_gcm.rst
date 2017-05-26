..  BSD LICENSE
    Copyright(c) 2016 Intel Corporation. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.
    * Neither the name of Intel Corporation nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AES-NI GCM Crypto Poll Mode Driver
==================================


The AES-NI GCM PMD (**librte_pmd_aesni_gcm**) provides poll mode crypto driver
support for utilizing Intel multi buffer library (see AES-NI Multi-buffer PMD documentation
to learn more about it, including installation).

The AES-NI GCM PMD has current only been tested on Fedora 21 64-bit with gcc.

Features
--------

AESNI GCM PMD has support for:

Cipher algorithms:

* RTE_CRYPTO_CIPHER_AES_GCM

Authentication algorithms:

* RTE_CRYPTO_AUTH_AES_GCM

Initialization
--------------

In order to enable this virtual crypto PMD, user must:

* Export the environmental variable AESNI_MULTI_BUFFER_LIB_PATH with the path where
  the library was extracted.

* Build the multi buffer library (go to Installation section in AES-NI MB PMD documentation).

* Set CONFIG_RTE_LIBRTE_PMD_AESNI_GCM=y in config/common_base.

To use the PMD in an application, user must:

* Call rte_eal_vdev_init("cryptodev_aesni_gcm_pmd") within the application.

* Use --vdev="cryptodev_aesni_gcm_pmd" in the EAL options, which will call rte_eal_vdev_init() internally.

The following parameters (all optional) can be provided in the previous two calls:

* socket_id: Specify the socket where the memory for the device is going to be allocated
  (by default, socket_id will be the socket where the core that is creating the PMD is running on).

* max_nb_queue_pairs: Specify the maximum number of queue pairs in the device (8 by default).

* max_nb_sessions: Specify the maximum number of sessions that can be created (2048 by default).

Example:

.. code-block:: console

    ./l2fwd-crypto -c 40 -n 4 --vdev="cryptodev_aesni_gcm_pmd,socket_id=1,max_nb_sessions=128"

Limitations
-----------

* Chained mbufs are not supported.
* Hash only is not supported.
* Cipher only is not supported.
* Only in-place is currently supported (destination address is the same as source address).
* Only supports session-oriented API implementation (session-less APIs are not supported).
*  Not performance tuned.
