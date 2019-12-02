/** @file
  function definitions for internal to application functions.

  Copyright (c) 2019, Gavin Xue. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef _ISH_SLOT_H_
#define _ISH_SLOT_H_

#include <PiDxe.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/ShellLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#define ISH_GUID \
  { \
    0x8b31a9f9, 0x208f, 0x4b26, { 0x93, 0xd9, 0x31, 0xaa, 0x76, 0xa6, 0x8d, 0x86 } \
  }

//
// Image Slot Header (ISH) for boot slot
//
#define ISH_VAR_NAME               L"IshVar"

typedef struct {
  UINT32       SlotA_Priority;
  UINT32       SlotA_UpdateRetries;
  UINT32       SlotA_GlitchRetries;
  UINT32       SlotB_Priority;
  UINT32       SlotB_UpdateRetries;
  UINT32       SlotB_GlitchRetries;
} ISH_INFO;

#endif
