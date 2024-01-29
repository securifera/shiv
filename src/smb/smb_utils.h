/**
  BSD 3-Clause License

  Copyright (c) 2019, Securifera, Inc. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
	list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
	this list of conditions and the following disclaimer in the documentation
	and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
	contributors may be used to endorse or promote products derived from
	this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include <stdint.h>
#include "smb.h"

BOOL pad_to_64bit(struct pdu_buffer_array* v);

BOOL buf_get_uint8(struct pdu_buffer* pdu_array, int offset, uint8_t* value);
BOOL buf_get_uint16(struct pdu_buffer* pdu_array, int offset, uint16_t* value);
BOOL buf_get_uint32(struct pdu_buffer* pdu_array, int offset, uint32_t* value);
BOOL buf_get_uint64(struct pdu_buffer* pdu_array, int offset, uint64_t* value);

BOOL buf_set_uint8(struct pdu_buffer* pdu_array, int offset, uint8_t value);
BOOL buf_set_uint16(struct pdu_buffer* pdu_array, int offset, uint16_t value);
BOOL buf_set_uint32(struct pdu_buffer* pdu_array, int offset, uint32_t value);
BOOL buf_set_uint64(struct pdu_buffer* pdu_array, int offset, uint64_t value);