/** @file
  A UEFI tool for dumpping DebugToMemory log.

  Copyright (c) 2019, Gavin Xue. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "DumpLog.h"

#define DEBUG_TO_MEMORY_SIG     SIGNATURE_32 ('D','P','R','M')
#define LOG_FILE                L"DumpLog.log"

typedef struct {
  UINT32    Signature;
  UINT32    Index;
  UINT8     Reserved[8];
} DEBUG_TO_MEMORY_HEADER;

EFI_STATUS
EFIAPI
SaveFileToDisk (
  IN  CHAR16              *FileName,
  IN  UINTN               BufferSize,
  IN  VOID                *Buffer
  )
{
  EFI_STATUS           Status;
  SHELL_FILE_HANDLE    FileHandle;

  if (!EFI_ERROR (ShellFileExists (FileName))) {
    ShellDeleteFileByName (FileName);
  }

  Status = ShellOpenFileByName (FileName, &FileHandle, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
  if (EFI_ERROR (Status)) {
    Print (L"Open file failed: %r\n", Status);
    return Status;
  }

  Status = ShellWriteFile (FileHandle, &BufferSize, Buffer);
  if (EFI_ERROR (Status)) {
    Print (L"Write file failed: %r\n", Status);
    ShellCloseFile (&FileHandle);
    return Status;
  }

  ShellCloseFile (&FileHandle);

  return EFI_SUCCESS;
}

VOID
EFIAPI
ShowHelpInfo (
  VOID
  )
{
  Print (L"Help info:\n");
  Print (L"  DumpLog.efi BaseAddress\n\n");
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
  EFI_STATUS                    Status;
  DEBUG_TO_MEMORY_HEADER        *Header;
  UINTN                         BaseAddress;

  if (Argc != 2) {
    ShowHelpInfo ();
    return EFI_INVALID_PARAMETER;
  }

  BaseAddress = StrHexToUintn (Argv[1]);

  Header = (DEBUG_TO_MEMORY_HEADER *) BaseAddress;

  if (Header->Signature != DEBUG_TO_MEMORY_SIG) {
    Print (L"Don't find correct signature.\n");
    return EFI_UNSUPPORTED;
  }

  Status = SaveFileToDisk (LOG_FILE, Header->Index, (UINT8 *) Header + sizeof (DEBUG_TO_MEMORY_HEADER));
  if (EFI_ERROR (Status)) {
    Print (L"Save log failed.\n");
    return Status;
  }

  Print (L"Save log %s Passed.\n", LOG_FILE);

  return 0;
}
