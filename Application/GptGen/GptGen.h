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

#ifndef _GPT_GEN_H_
#define _GPT_GEN_H_

#include <PiDxe.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/ShellLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/RngLib.h>
#include <IndustryStandard/Mbr.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>

#define GPT_BIN_MAGIC       0x6A8B0DA1

#define GPT_REVISION        0x00010000
#define GPT_ENTRIES         128
#define GPT_ENTRY_SIZE      128
#define GPT_DISK_ALIGNMENT  SIZE_1MB

typedef struct {
  UINT32      Magic;
  UINT32      StartLba;
  UINT32      NPart;
} GPT_BIN_HEADER;

typedef struct {
  UINT32      Length;
  CHAR16      Label[36];
  EFI_GUID    Type;
  EFI_GUID    Uuid;
} GPT_BIN_PART;

#define ALIGN_DOWN(x, y) ((y) * ((x) / (y)))

typedef struct {
  EFI_DEVICE_PATH_PROTOCOL  *ParentDevicePath;
  EFI_BLOCK_IO_PROTOCOL     *BlockIo;
  EFI_DISK_IO_PROTOCOL      *DiskIo;
} PARTITON_DATA;

#endif
