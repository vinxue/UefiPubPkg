/** @file
  A UEFI tool for OTA BIOS Capsule trigger.

  Copyright (c) 2020, Gavin Xue. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "OtaUpdate.h"

VOID
EFIAPI
ShowHelpInfo (
  VOID
  )
{
  Print (L"Help info:\n");
  Print (L"  OtaUpdate.efi [UpdateSlot]\n");
  Print (L"  OtaUpdate.efi 0 - Update Slot A\n");
  Print (L"  OtaUpdate.efi 1 - Update Slot B\n\n");
}

/**
  UEFI application entry point which has an interface similar to a
  standard C main function.

  The ShellCEntryLib library instance wrappers the actual UEFI application
  entry point and calls this ShellAppMain function.

  @param[in]  Argc  The number of parameters.
  @param[in]  Argv  The array of pointers to parameters.

  @retval  0               The application exited normally.
  @retval  Other           An error occurred.

**/
INTN
EFIAPI
ShellAppMain (
  IN UINTN                     Argc,
  IN CHAR16                    **Argv
  )
{
  EFI_STATUS          Status;
  OTA_CAPSULE_UPDATE  OtaCapsuleUpdate;
  UINTN               VarSize;
  EFI_GUID            OtaCapsuleGuid = OTA_CAPSULE_GUID;

  if (Argc != 2) {
    ShowHelpInfo ();
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&OtaCapsuleUpdate, sizeof (OTA_CAPSULE_UPDATE));

  OtaCapsuleUpdate.UpdateFlag = 1;
  OtaCapsuleUpdate.UpdateSlot = (UINT8) StrHexToUintn (Argv[1]);

  if (OtaCapsuleUpdate.UpdateSlot > 1) {
    Print (L"Invalid Update Slot Number.\n");
    return EFI_INVALID_PARAMETER;
  }

  VarSize = sizeof (OTA_CAPSULE_UPDATE);
  Status = gRT->SetVariable (
                  OTA_CAPSULE_VAR_NAME,
                  &OtaCapsuleGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  sizeof (OTA_CAPSULE_UPDATE),
                  (VOID *) &OtaCapsuleUpdate
                  );
  if (EFI_ERROR (Status)) {
    Print (L"Trigger OTA Capsule Update Failed: %r\n", Status);
  } else {
    Print (L"Trigger OTA Capsule Update Passed: %r\n", Status);
  }

  //
  // Reset system
  //
  Print (L"Restting system in 1 seconds ...\n");
  gBS->Stall (1 * 1000 * 1000);
  gRT->ResetSystem (EfiResetWarm, EFI_SUCCESS, 0, NULL);

  return 0;
}
