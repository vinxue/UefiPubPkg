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

#ifndef _UEFI_AVB_H_
#define _UEFI_AVB_H_

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
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DiskIo.h>
// #include "efilib.h"

#define uefi_call_wrapper(func, va_num, ...) func(__VA_ARGS__)

// extern EFI_SYSTEM_TABLE         *ST;
#define ST                      gST
// extern EFI_BOOT_SERVICES        *BS;
#define BS                      gBS
// extern EFI_RUNTIME_SERVICES     *RT;
#define RT                      gRT

#endif
