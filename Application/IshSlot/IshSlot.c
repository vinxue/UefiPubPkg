/** @file
  A UEFI tool for ISH Slot setting.

  Copyright (c) 2019, Gavin Xue. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "IshSlot.h"


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
  ISH_INFO            IshInfo;
  UINTN               VarSize;
  EFI_GUID            IshGuid = ISH_GUID;

  if ((!StrCmp (Argv[1], L"r")) || (!StrCmp (Argv[1], L"R"))) {
    VarSize = sizeof (ISH_INFO);
    Status = gRT->GetVariable (
                    ISH_VAR_NAME,
                    &IshGuid,
                    NULL,
                    &VarSize,
                    (VOID *) &IshInfo
                    );
    if (EFI_ERROR (Status)) {
      Print (L"Read ISH variable failed: %r\n", Status);
      return Status;
    }

    Print (L"IshInfo.SlotA_Priority:      0x%x\n", IshInfo.SlotA_Priority);
    Print (L"IshInfo.SlotA_UpdateRetries: 0x%x\n", IshInfo.SlotA_UpdateRetries);
    Print (L"IshInfo.SlotA_GlitchRetries: 0x%x\n", IshInfo.SlotA_GlitchRetries);
    Print (L"IshInfo.SlotB_Priority:      0x%x\n", IshInfo.SlotB_Priority);
    Print (L"IshInfo.SlotB_UpdateRetries: 0x%x\n", IshInfo.SlotB_UpdateRetries);
    Print (L"IshInfo.SlotB_GlitchRetries: 0x%x\n", IshInfo.SlotB_GlitchRetries);

    return Status;
  }

  if ((!StrCmp (Argv[1], L"w")) || (!StrCmp (Argv[1], L"W"))) {

    ZeroMem (&IshInfo, sizeof (ISH_INFO));

    IshInfo.SlotA_Priority          = (UINT32) StrHexToUintn (Argv[2]);
    IshInfo.SlotA_UpdateRetries     = (UINT32) StrHexToUintn (Argv[3]);
    IshInfo.SlotA_GlitchRetries     = 0xFF;
    IshInfo.SlotB_Priority          = (UINT32) StrHexToUintn (Argv[4]);
    IshInfo.SlotB_UpdateRetries     = (UINT32) StrHexToUintn (Argv[5]);
    IshInfo.SlotB_GlitchRetries     = 0xFF;

    VarSize = sizeof (ISH_INFO);
    Status = gRT->SetVariable (
                    ISH_VAR_NAME,
                    &IshGuid,
                    EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                    sizeof (ISH_INFO),
                    (VOID *) &IshInfo
                    );
    if (EFI_ERROR (Status)) {
      Print (L"Write ISH variable faile: %r\n", Status);
    }

    Print (L"Write ISH variable passed: %r\n", Status);

    return Status;
  }

  return 0;
}
