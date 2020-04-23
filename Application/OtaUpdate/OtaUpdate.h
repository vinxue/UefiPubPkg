/** @file
  function definitions for internal to application functions.

  Copyright (c) 2020, Gavin Xue. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef _OTA_UPDATE_H_
#define _OTA_UPDATE_H_

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

#define OTA_CAPSULE_GUID \
  { \
    0x38605b43, 0xcc36, 0x4a28, { 0x86, 0x29, 0x2f, 0x6d, 0x37, 0xfd, 0x4f, 0xcc } \
  }

#pragma pack (1)
//
// OTA for BIOS Capsule update
//
typedef struct {
  UINT8        UpdateFlag;  // 0: No update required; 1: update required
  UINT8        UpdateSlot;  // 0: Slot A; 1: Slot B
} OTA_CAPSULE_UPDATE;

#pragma pack ()

//
// Variable Name for OTA BIOS Update
//
#define OTA_CAPSULE_VAR_NAME          L"OtaCapsuleVar"

#endif
