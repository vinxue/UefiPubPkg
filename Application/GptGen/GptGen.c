/** @file
  A simple UEFI tool for GPT table generation.

  Copyright (c) 2019, Gavin Xue. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "GptGen.h"

STATIC CONST CHAR8 Hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

EFI_DEVICE_PATH_PROTOCOL      *mDiskDevicePath;
PARTITON_DATA                 *mPartData;

EFI_PARTITION_TABLE_HEADER    mPartHeader;
EFI_PARTITION_ENTRY           mPartitionEntries[GPT_ENTRIES];

BOOLEAN                       mGptGen = FALSE;
BOOLEAN                       mGptFlash = FALSE;

VOID
EFIAPI
DumpHex (
  IN UINTN        Indent,
  IN UINTN        Offset,
  IN UINTN        DataSize,
  IN VOID         *UserData
  )
{
  UINT8 *Data;

  CHAR8 Val[50];

  CHAR8 Str[20];

  UINT8 TempByte;
  UINTN Size;
  UINTN Index;

  Data = UserData;
  while (DataSize != 0) {
    Size = 16;
    if (Size > DataSize) {
      Size = DataSize;
    }

    for (Index = 0; Index < Size; Index += 1) {
      TempByte            = Data[Index];
      Val[Index * 3 + 0]  = Hex[TempByte >> 4];
      Val[Index * 3 + 1]  = Hex[TempByte & 0xF];
      Val[Index * 3 + 2]  = (CHAR8) ((Index == 7) ? '-' : ' ');
      Str[Index]          = (CHAR8) ((TempByte < ' ' || TempByte > '~') ? '.' : TempByte);
    }

    Val[Index * 3]  = 0;
    Str[Index]      = 0;
    Print(L"%*a%08X: %-48a *%a*\r\n", Indent, "", Offset, Val, Str);

    Data += Size;
    Offset += Size;
    DataSize -= Size;
  }
}

EFI_STATUS
EFIAPI
ReadFileFromDisk (
  IN  CHAR16               *FileName,
  OUT  UINTN               *BufferSize,
  OUT  VOID                **Buffer
  )
{
  EFI_STATUS           Status;
  SHELL_FILE_HANDLE    FileHandle;
  UINTN                FileSize;
  VOID                 *FileBuffer;

  Status = ShellOpenFileByName (FileName, &FileHandle, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR (Status)) {
    Print (L"Open file failed: %r\n", Status);
    return Status;
  }

  Status = ShellGetFileSize (FileHandle, &FileSize);
  if (EFI_ERROR (Status)) {
    Print (L"Failed to read file size, Status: %r\n", Status);
    if (FileHandle != NULL) {
      ShellCloseFile (&FileHandle);
    }
    return Status;
  }

  FileBuffer = AllocateZeroPool (FileSize);
  if (FileBuffer == NULL) {
    Print (L"Allocate resouce failed\n");
    if (FileHandle != NULL) {
      ShellCloseFile (&FileHandle);
    }
    return EFI_OUT_OF_RESOURCES;
  }

  Status = ShellReadFile (FileHandle, &FileSize, FileBuffer);
  if (EFI_ERROR (Status)) {
    Print (L"Failed to read file, Status: %r\n", Status);
    if (FileHandle != NULL) {
      ShellCloseFile (&FileHandle);
    }
    if (Buffer != NULL) {
      FreePool (Buffer);
    }
    return Status;
  }

  ShellCloseFile (&FileHandle);

  *BufferSize = FileSize;
  *Buffer     = FileBuffer;

  return EFI_SUCCESS;
}

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

BOOLEAN
EFIAPI
IsUsbDevice (
  IN EFI_DEVICE_PATH_PROTOCOL   *DevicePath
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *TempDevicePath;
  BOOLEAN                   Match;

  if (DevicePath == NULL) {
    return FALSE;
  }

  Match = FALSE;

  //
  // Search for USB device path node.
  //
  TempDevicePath = DevicePath;
  while (!IsDevicePathEnd (TempDevicePath)) {
    if ((DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) &&
        ((DevicePathSubType (TempDevicePath) == MSG_USB_DP))) {
      Match = TRUE;
    }
    TempDevicePath = NextDevicePathNode (TempDevicePath);
  }

  return Match;
}

EFI_STATUS
EFIAPI
InitDevicePath (
  VOID
  )
{
  EFI_STATUS                Status;
  UINT8                     Index;
  UINTN                     HandleCount;
  EFI_HANDLE                *HandleBuffer;
  EFI_BLOCK_IO_PROTOCOL     *BlockIo;
  EFI_DISK_IO_PROTOCOL      *DiskIo;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  //
  // Locate all the BlockIo protocol
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlockIo
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiDiskIoProtocolGuid,
                    (VOID **) &DiskIo
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if ((BlockIo->Media->LogicalPartition) || (BlockIo->Media->RemovableMedia)) {
      continue;
    }

    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiDevicePathProtocolGuid,
                    (VOID **) &DevicePath
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    if (IsUsbDevice (DevicePath)) {
      continue;
    }

    break;
  }

  if (Index >= HandleCount) {
    Print (L"Failed to find boot device.\n");
    return EFI_DEVICE_ERROR;
  }

  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
    HandleBuffer = NULL;
  }

  mDiskDevicePath = DuplicateDevicePath (DevicePath);

  mPartData->BlockIo          = BlockIo;
  mPartData->DiskIo           = DiskIo;
  mPartData->ParentDevicePath = mDiskDevicePath;

  return EFI_SUCCESS;
}

VOID
EFIAPI
GptNew (
  IN PARTITON_DATA               *PartData,
  IN EFI_PARTITION_TABLE_HEADER  *PartHdr,
  IN UINT32                      StartLba
  )
{
  UINT32       GptSize;
  BOOLEAN      IsRandom;
  UINT64       TempRand[2];
  UINT32       BlockSize;
  EFI_LBA      LastBlock;

  IsRandom  = FALSE;
  BlockSize = PartData->BlockIo->Media->BlockSize;
  LastBlock = PartData->BlockIo->Media->LastBlock;

  ZeroMem (PartHdr, sizeof (EFI_PARTITION_TABLE_HEADER));
  PartHdr->Header.Signature = EFI_PTAB_HEADER_ID;

  PartHdr->Header.Revision = GPT_REVISION;
  PartHdr->Header.HeaderSize = sizeof (EFI_PARTITION_TABLE_HEADER);

  PartHdr->NumberOfPartitionEntries = GPT_ENTRIES;
  PartHdr->SizeOfPartitionEntry     = GPT_ENTRY_SIZE;
  GptSize = 1 + (PartHdr->NumberOfPartitionEntries * PartHdr->SizeOfPartitionEntry / BlockSize);
  //
  // If StartLba is forced, use it, otherwise start at GptSize + 1
  //
  if (StartLba > 2 + GptSize) {
    PartHdr->FirstUsableLBA = StartLba;
  } else {
    PartHdr->FirstUsableLBA = GptSize + 1;
  }

  PartHdr->LastUsableLBA = LastBlock - GptSize;
  DEBUG ((DEBUG_INFO, "FirstUsableLBA: 0x%x, LastUsableLBA: 0x%x\n", PartHdr->FirstUsableLBA, PartHdr->LastUsableLBA));

  IsRandom = GetRandomNumber128 (TempRand);
  if (IsRandom) {
    DEBUG ((DEBUG_INFO, "IsRandom: %d, TempRand[0]: %lx, TempRand[1]: %lx\n", IsRandom, TempRand[0], TempRand[1]));
    PartHdr->DiskGUID.Data1 = (UINT32) TempRand[0];
    PartHdr->DiskGUID.Data2 = (UINT16) RShiftU64 (TempRand[0], 32);
    PartHdr->DiskGUID.Data3 = (((UINT16) RShiftU64 (TempRand[0], 48)) & 0x0FFF) | 0x4000;  // version 4 : random generation
    CopyMem (PartHdr->DiskGUID.Data4, &TempRand[1], sizeof (UINT64));
    PartHdr->DiskGUID.Data4[0] = (PartHdr->DiskGUID.Data4[0] & 0x3F) | 0x80;  // Reversion 0b10
  }
}

EFI_STATUS
EFIAPI
GptCheckPartitionList (
  IN PARTITON_DATA      *PartData,
  IN GPT_BIN_PART       *Gbp,
  IN UINT32             PartCount
  )
{
  UINTN         Index;
  UINT64        TotalSize;
  UINT64        DiskSize;
  INTN          PartIndex;
  UINT32        BlockSize;
  EFI_LBA       LastBlock;
  UINT32        GptSize;
  EFI_LBA       AlignFirstLBA;
  EFI_LBA       AlignLastLBA;

  TotalSize = 0;
  PartIndex  = -1;

  for (Index = 0; Index < PartCount; Index++) {
    if ((Gbp[Index].Length == 0)) {
      DEBUG ((DEBUG_ERROR, "Incorrect lenght for partition %d\n", Index));
      return EFI_INVALID_PARAMETER;
    }

    if (Gbp[Index].Length == 0xFFFFFFFF) {
      if (PartIndex >= 0) {
        DEBUG ((DEBUG_ERROR, "More than 1 partition has -1 length %d\n", Index));
        return EFI_INVALID_PARAMETER;
      }
      PartIndex = Index;
      continue;
    }
    TotalSize += Gbp[Index].Length;
  }

  BlockSize = PartData->BlockIo->Media->BlockSize;
  LastBlock = PartData->BlockIo->Media->LastBlock;

  GptSize = 1 + (mPartHeader.NumberOfPartitionEntries * mPartHeader.SizeOfPartitionEntry / BlockSize);
  AlignFirstLBA = GPT_DISK_ALIGNMENT / BlockSize;
  AlignLastLBA  = ALIGN_DOWN (LastBlock - (GptSize), (GPT_DISK_ALIGNMENT / BlockSize)) - 1;

  DiskSize = ((AlignLastLBA + 1 - AlignFirstLBA) * BlockSize) / SIZE_1MB;

  if (TotalSize > DiskSize) {
    DEBUG ((DEBUG_ERROR, "partitions are bigger than the disk, partitions %ld MB disk %ld MB", TotalSize, DiskSize));
    return EFI_INVALID_PARAMETER;
  }

  Gbp[PartIndex].Length = (UINT32) (DiskSize - TotalSize);

  return EFI_SUCCESS;
}

VOID
EFIAPI
GptFillEntries (
  IN PARTITON_DATA       *PartData,
  IN UINT32               PartCount,
  IN GPT_BIN_PART         *Gbp,
  IN EFI_PARTITION_ENTRY  *PartEntries
  )
{
  UINT64             StartLba;
  UINTN              Index;
  UINT32             BlockSize;

  BlockSize = PartData->BlockIo->Media->BlockSize;
  //
  // Align on MB boundaries
  //
  StartLba = GPT_DISK_ALIGNMENT / BlockSize;

  for (Index = 0; Index < PartCount; Index++) {
    CopyMem (&PartEntries[Index].PartitionName, &Gbp[Index].Label, sizeof (PartEntries[Index].PartitionName));
    CopyMem (&PartEntries[Index].PartitionTypeGUID, &Gbp[Index].Type, sizeof (EFI_GUID));
    CopyMem (&PartEntries[Index].UniquePartitionGUID, &Gbp[Index].Uuid, sizeof (EFI_GUID));
    PartEntries[Index].StartingLBA = StartLba;
    PartEntries[Index].EndingLBA = StartLba - 1 + Gbp[Index].Length * (GPT_DISK_ALIGNMENT / BlockSize);
    StartLba = PartEntries[Index].EndingLBA + 1;
    DEBUG ((
      DEBUG_INFO,
      "Partition %s, Start 0x%x, End 0x%x\n",
      PartEntries[Index].PartitionName,
      PartEntries[Index].StartingLBA,
      PartEntries[Index].EndingLBA
      ));
  }
}

EFI_STATUS
EFIAPI
SetGptHdrCrc (
  IN EFI_PARTITION_TABLE_HEADER   *GptHdr
  )
{
  EFI_STATUS         Status;
  UINT32             Crc32;

  GptHdr->Header.CRC32 = 0;

  Status = gBS->CalculateCrc32 (GptHdr, sizeof (EFI_PARTITION_TABLE_HEADER), &Crc32);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  GptHdr->Header.CRC32 = Crc32;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
WriteGptTableToDisk (
  IN PARTITON_DATA               *PartData,
  IN EFI_PARTITION_TABLE_HEADER  *GptHdr
  )
{
  EFI_STATUS        Status;
  UINT64            HdrOffset;
  UINT64            EntriesOffset;
  UINT64            EntriesSize;
  UINT32            BlockSize;
  VOID              *Buffer;

  BlockSize = PartData->BlockIo->Media->BlockSize;

  EntriesSize   = GptHdr->NumberOfPartitionEntries * GptHdr->SizeOfPartitionEntry;
  HdrOffset     = GptHdr->MyLBA * BlockSize;
  EntriesOffset = GptHdr->PartitionEntryLBA * BlockSize;

  Buffer = AllocateZeroPool (BlockSize);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (Buffer, GptHdr, sizeof (EFI_PARTITION_TABLE_HEADER));

  Status = PartData->DiskIo->WriteDisk (
             PartData->DiskIo,
             PartData->BlockIo->Media->MediaId,
             HdrOffset,
             BlockSize,
             Buffer
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Write GPT header failed\n"));
    FreePool (Buffer);
    return Status;
  }

  FreePool (Buffer);

  Status = PartData->DiskIo->WriteDisk (
             PartData->DiskIo,
             PartData->BlockIo->Media->MediaId,
             EntriesOffset,
             EntriesSize,
             mPartitionEntries
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Write GPT entries failed\n"));
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
WriteProtectiveMbr (
  IN PARTITON_DATA      *PartData
  )
{
  EFI_STATUS                  Status;
  MASTER_BOOT_RECORD          *ProtectiveMbr;
  UINT32                      SizeInLBA;
  UINT32                      BlockSize;
  EFI_LBA                     LastBlock;

  BlockSize = PartData->BlockIo->Media->BlockSize;
  LastBlock = PartData->BlockIo->Media->LastBlock;

  ProtectiveMbr = AllocateZeroPool (BlockSize);
  if (ProtectiveMbr == NULL) {
    return EFI_NOT_FOUND;
  }

  ProtectiveMbr->Partition[0].StartSector    = 2;
  ProtectiveMbr->Partition[0].OSIndicator    = PMBR_GPT_PARTITION;
  ProtectiveMbr->Partition[0].EndHead        = 0xFF;
  ProtectiveMbr->Partition[0].EndSector      = 0xFF;
  ProtectiveMbr->Partition[0].EndTrack       = 0xFF;
  ProtectiveMbr->Partition[0].StartingLBA[0] = 1;
  SizeInLBA = (UINT32) MIN (LastBlock, 0xFFFFFFFF);
  CopyMem (ProtectiveMbr->Partition[0].SizeInLBA, &SizeInLBA, sizeof (UINT32));
  ProtectiveMbr->Signature                   = 0xAA55;

  if (mGptGen) {
    SaveFileToDisk (L"GptPMbr.bin", BlockSize, ProtectiveMbr);
  }

  if (mGptFlash) {
    Status = PartData->DiskIo->WriteDisk (
              PartData->DiskIo,
              PartData->BlockIo->Media->MediaId,
              0,
              BlockSize,
              ProtectiveMbr
              );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Write Protective MBR failed\n"));
      FreePool (ProtectiveMbr);
      return Status;
    }
  }

  FreePool (ProtectiveMbr);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
GptWritePartitionTable (
  IN PARTITON_DATA      *PartData
  )
{
  EFI_STATUS                  Status;
  UINT64                      EntriesSize;
  EFI_PARTITION_TABLE_HEADER  *PrimaryHeader;
  EFI_PARTITION_TABLE_HEADER  *BackupHeader;
  UINT32                      Crc32;
  UINT32                      BlockSize;
  UINT64                      LastBlock;
  UINT8                       *PrimaryBuffer;
  UINT8                       *BackupBuffer;
  UINTN                       BufferSize;

  PrimaryHeader = &mPartHeader;
  BlockSize = PartData->BlockIo->Media->BlockSize;
  LastBlock = PartData->BlockIo->Media->LastBlock;

  EntriesSize = PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry;
  PrimaryHeader->MyLBA = PRIMARY_PART_HEADER_LBA;
  PrimaryHeader->AlternateLBA = LastBlock;
  PrimaryHeader->PartitionEntryLBA = 2;

  Status = gBS->CalculateCrc32 (mPartitionEntries, EntriesSize, &Crc32);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Partition Entries Crc calculation failed\n"));
    return Status;
  }

  PrimaryHeader->PartitionEntryArrayCRC32 = Crc32;

  Status = SetGptHdrCrc (PrimaryHeader);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GPT Primary header Crc calculation failed\n"));
    return Status;
  }


  if (mGptGen) {
    BufferSize = 1 * BlockSize + EntriesSize;
    PrimaryBuffer = AllocateZeroPool (BufferSize);
    if (PrimaryBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (PrimaryBuffer, PrimaryHeader, sizeof (EFI_PARTITION_TABLE_HEADER));
    CopyMem (PrimaryBuffer + BlockSize, mPartitionEntries, EntriesSize);

    SaveFileToDisk (L"GptPrimary.bin", BufferSize, PrimaryBuffer);
    FreePool (PrimaryBuffer);
  }

  //
  // Write Primary GPT table to disk.
  //
  if (mGptFlash) {
    Status = WriteGptTableToDisk (PartData, PrimaryHeader);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Write Primary GPT table to disk failed\n"));
      return Status;
    }
  }

  BackupHeader = AllocateZeroPool (sizeof (EFI_PARTITION_TABLE_HEADER));
  if (BackupHeader == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (BackupHeader, PrimaryHeader, sizeof (EFI_PARTITION_TABLE_HEADER));
  BackupHeader->MyLBA = PrimaryHeader->AlternateLBA;
  BackupHeader->AlternateLBA = PrimaryHeader->MyLBA;
  BackupHeader->PartitionEntryLBA = BackupHeader->MyLBA - EntriesSize / BlockSize;

  Status = SetGptHdrCrc (BackupHeader);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GPT Backup header Crc calculation failed\n"));
    FreePool (BackupHeader);
    return Status;
  }

  if (mGptGen) {
    BackupBuffer = AllocateZeroPool (BufferSize);
    if (BackupBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (BackupBuffer, mPartitionEntries, EntriesSize);
    CopyMem (BackupBuffer + EntriesSize, BackupHeader, sizeof (EFI_PARTITION_TABLE_HEADER));

    SaveFileToDisk (L"GptBackup.bin", BufferSize, BackupBuffer);
    FreePool (BackupBuffer);
  }

  //
  // Write Backup GPT table to disk.
  //
  if (mGptFlash) {
    Status = WriteGptTableToDisk (PartData, BackupHeader);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Write Backup GPT table to disk failed\n"));
      FreePool (BackupHeader);
      return Status;
    }
  }
  FreePool (BackupHeader);

  //
  // Write Protective MBR to disk.
  //
  Status = WriteProtectiveMbr (PartData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "WriteProtectiveMbr failed\n"));
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
GptCreate (
  IN PARTITON_DATA      *PartData,
  IN GPT_BIN_PART       *Gbp,
  IN UINT32             StartLba,
  IN UINT32             PartCount
  )
{
  EFI_STATUS         Status;

  if (PartCount > GPT_ENTRIES) {
    DEBUG ((DEBUG_ERROR, "Maximum number of partition supported is %d\n", GPT_ENTRIES));
    return EFI_INVALID_PARAMETER;
  }

  GptNew (PartData, &mPartHeader, StartLba);

  Status = GptCheckPartitionList (PartData, Gbp, PartCount);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GptCheckPartitionList failed\n"));
    return Status;
  }

  SetMem (mPartitionEntries, sizeof (mPartitionEntries), 0);
  GptFillEntries (PartData, PartCount, Gbp, mPartitionEntries);

  Status = GptWritePartitionTable (PartData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GptWritePartitionTable failed\n"));
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  This routine will read GPT partition table header and validate it.

  @param[in] PartData             The pointer of parent partition data.
  @param[in] Data                 The pointer of GPT metadata or GPT table.
  @param[in] Size                 The size of GPT metadata or GPT table.

  @retval TRUE                    The partition table is valid.
  @retval FALSE                   The partition table is not valid.

**/
BOOLEAN
ValidGptTable (
  IN PARTITON_DATA    *PartData,
  IN VOID             *Data,
  IN UINTN            Size
  )
{
  EFI_STATUS                  Status;
  UINT32                      BlockSize;
  EFI_PARTITION_TABLE_HEADER  *PartHeader;
  EFI_PARTITION_TABLE_HEADER  *TempHeader;
  UINT32                      Crc32;
  VOID                        *EntriesPtr;
  UINT64                      EntriesSize;

  BlockSize = PartData->BlockIo->Media->BlockSize;
  PartHeader = (EFI_PARTITION_TABLE_HEADER *) ((UINT8 *) Data + BlockSize);

  TempHeader = AllocateZeroPool (sizeof (EFI_PARTITION_TABLE_HEADER));
  if (TempHeader == NULL) {
    return FALSE;
  }
  CopyMem (TempHeader, PartHeader, sizeof (EFI_PARTITION_TABLE_HEADER));
  TempHeader->Header.CRC32 = 0;

  Status = gBS->CalculateCrc32 (TempHeader, sizeof (EFI_PARTITION_TABLE_HEADER), &Crc32);
  if (EFI_ERROR (Status)) {
    FreePool (TempHeader);
    return FALSE;
  }

  if ((PartHeader->Header.Signature != EFI_PTAB_HEADER_ID) ||
      (Crc32 != PartHeader->Header.CRC32) ||
      (PartHeader->MyLBA != PRIMARY_PART_HEADER_LBA) ||
      (PartHeader->SizeOfPartitionEntry < sizeof (EFI_PARTITION_ENTRY))
      ) {
    DEBUG ((DEBUG_ERROR, "Invalid efi partition table header\n"));
    FreePool (TempHeader);
    return FALSE;
  }

  FreePool (TempHeader);

  //
  // Ensure the NumberOfPartitionEntries * SizeOfPartitionEntry doesn't overflow.
  //
  if (PartHeader->NumberOfPartitionEntries > DivU64x32 (MAX_UINTN, PartHeader->SizeOfPartitionEntry)) {
    return FALSE;
  }

  EntriesSize   = PartHeader->NumberOfPartitionEntries * PartHeader->SizeOfPartitionEntry;

  if (Size < (2 * BlockSize + EntriesSize)) {
    return FALSE;
  }

  EntriesPtr = (UINT8 *) PartHeader + BlockSize;

  Status = gBS->CalculateCrc32 (EntriesPtr, EntriesSize, &Crc32);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[ValidGptTable] Partition Entries Crc calculation failed\n"));
    return FALSE;
  }

  if (PartHeader->PartitionEntryArrayCRC32 != Crc32) {
    DEBUG ((DEBUG_ERROR, "Invalid PartitionEntryArrayCRC32\n"));
    return FALSE;
  }

  DEBUG ((DEBUG_INFO, "Valid efi partition table header\n"));
  return TRUE;
}

/**
  Get GPT table header and validate it.

  @param[in] PartData             The pointer of parent partition data.
  @param[in] Data                 The pointer of GPT metadata or GPT table.
  @param[in] Size                 The size of GPT metadata or GPT table.

  @retval EFI_SUCCESS             Operation completed successfully.
  @retval others                  Some error occurs when executing this routine.

**/
EFI_STATUS
EFIAPI
GetFullGptHeader (
  IN PARTITON_DATA    *PartData,
  IN VOID             *Data,
  IN UINTN            Size
  )
{
  UINT32           BlockSize;

  BlockSize = PartData->BlockIo->Media->BlockSize;

  if (Size < BlockSize) {
    return EFI_NOT_FOUND;
  }

  if (!ValidGptTable (PartData, Data, Size)) {
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

/**
  Write GPT table RAW data to GPT location directly.

  @param[in] PartData             The pointer of parent partition data.
  @param[in] Data                 The pointer of GPT table.

  @retval EFI_SUCCESS             Operation completed successfully.
  @retval others                  Some error occurs when executing this routine.

**/
EFI_STATUS
EFIAPI
WriteGptRaw (
  IN PARTITON_DATA    *PartData,
  IN VOID             *Data
  )
{
  EFI_STATUS                  Status;
  UINT32                      BlockSize;
  UINTN                       FlashGptSize;
  UINT64                      EntriesSize;
  EFI_PARTITION_TABLE_HEADER  *PartHeader;

  BlockSize   = PartData->BlockIo->Media->BlockSize;
  PartHeader  = (EFI_PARTITION_TABLE_HEADER *) ((UINT8 *) Data + BlockSize);
  EntriesSize = PartHeader->NumberOfPartitionEntries * PartHeader->SizeOfPartitionEntry;

  //
  // 1 block for the Protective MBR, 1 block for the Partition Table Header,
  // and x blocks for the GPT Partition Entry Array.
  //
  FlashGptSize = 2 * BlockSize + EntriesSize;

  Status = PartData->DiskIo->WriteDisk (
             PartData->DiskIo,
             PartData->BlockIo->Media->MediaId,
             0,
             FlashGptSize,
             Data
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Write GPT RAW failed\n"));
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FlashGpt (
  IN PARTITON_DATA    *PartData,
  IN VOID             *Data,
  IN UINTN            Size
  )
{
  EFI_STATUS           Status;
  GPT_BIN_HEADER       *GpHdr;
  GPT_BIN_PART         *GpPart;

  if (PartData == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = GetFullGptHeader (PartData, Data, Size);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }
  if (!EFI_ERROR (Status)) {
    return WriteGptRaw (PartData, Data);
  }

  GpHdr  = Data;
  GpPart = (GPT_BIN_PART *) &GpHdr[1];

  if (Size < sizeof (GPT_BIN_HEADER)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Size != sizeof (GPT_BIN_HEADER) + (GpHdr->NPart * sizeof (GPT_BIN_PART))) {
    return EFI_INVALID_PARAMETER;
  }

  if (GpHdr->Magic != GPT_BIN_MAGIC) {
    return EFI_INVALID_PARAMETER;
  }

  Status = GptCreate (PartData, GpPart, GpHdr->StartLba, GpHdr->NPart);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Flush the Block Device after GPT table flashed.

  @param[in] PartData             The pointer of parent partition data.

  @retval EFI_SUCCESS             Operation completed successfully.
  @retval others                  Some error occurs when executing this routine.

**/
EFI_STATUS
EFIAPI
GptSync (
  IN PARTITON_DATA    *PartData
  )
{
  EFI_STATUS         Status;

  Status = PartData->BlockIo->FlushBlocks (PartData->BlockIo);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to flush block io interface.\n"));
  }

  return Status;
}

/**
  The routine issues dummy read for every physical block device to cause
  the BlockIo re-installed if media change happened.

  @param[in] VOID

**/
VOID
ProbeForMediaChange (
  VOID
  )
{
  EFI_STATUS                            Status;
  UINTN                                 HandleCount;
  EFI_HANDLE                            *Handles;
  EFI_BLOCK_IO_PROTOCOL                 *BlockIo;
  UINTN                                 Index;

  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiBlockIoProtocolGuid,
         NULL,
         &HandleCount,
         &Handles
         );
  //
  // Probe for media change for every physical block io
  //
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlockIo
                    );
    if (!EFI_ERROR (Status)) {
      if (!BlockIo->Media->LogicalPartition) {
        //
        // Per spec:
        //   The function (ReadBlocks) must return EFI_NO_MEDIA or
        //   EFI_MEDIA_CHANGED even if LBA, BufferSize, or Buffer are invalid so the caller can probe
        //   for changes in media state.
        //
        BlockIo->ReadBlocks (
                   BlockIo,
                   BlockIo->Media->MediaId,
                   0,
                   0,
                   NULL
                   );
      }
    }
  }
}

/**
  Re-Enumerate disk partition after GPT table flashed.

  @param[in] PartData             The pointer of parent partition data.

  @retval EFI_SUCCESS             Operation completed successfully.
  @retval others                  Some error occurs when executing this routine.

**/
EFI_STATUS
EFIAPI
ReEnumeratePartitions (
  IN PARTITON_DATA    *PartData
  )
{
  EFI_STATUS                 Status;
  EFI_HANDLE                 Handle;
  EFI_DEVICE_PATH_PROTOCOL   *TempDevicePath;

  if (PartData == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Flush the Block Device after GPT table flashed.
  //
  Status = GptSync (PartData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "GptSync failed, status: %r.\n", Status));
    return Status;
  }

  TempDevicePath = PartData->ParentDevicePath;

  Status = gBS->LocateDevicePath (
                  &gEfiBlockIoProtocolGuid,
                  &TempDevicePath,
                  &Handle
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Couldn't locate the handle, status: %r\n", Status));
    return Status;
  }

  //
  // Reinstalls BlockIo protocol interface on a device handle.
  //
  Status = gBS->ReinstallProtocolInterface (
                  Handle,
                  &gEfiBlockIoProtocolGuid,
                  PartData->BlockIo,
                  PartData->BlockIo
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "ReinstallProtocolInterface failed, status: %r\n", Status));
    return Status;
  }

  //
  // Dummy read for every physical block device to cause the BlockIo
  // re-installed if media change happened.
  //
  ProbeForMediaChange ();

  DEBUG ((DEBUG_INFO, "ReEnumerate partitions successfully.\n"));

  return EFI_SUCCESS;
}

VOID
EFIAPI
ShowHelpInfo (
  VOID
  )
{
  Print (L"Help info:\n");
  Print (L"  GptGen.efi gen gpt.bin (GptPrimary.bin/GptBackup.bin/GptPMbr.bin)\n");
  Print (L"  GptGen.efi flash gpt.bin\n\n");
  Print (L"  GptGen.efi all gpt.bin\n\n");
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
  EFI_STATUS                Status;
  VOID                      *Buffer;
  UINTN                     BufferSize;

  if (Argc == 1) {
    ShowHelpInfo ();
    return EFI_INVALID_PARAMETER;
  }

  if ((!StrCmp (Argv[1], L"gen")) || (!StrCmp (Argv[1], L"GEN"))) {
    mGptGen = TRUE;
  } else if ((!StrCmp (Argv[1], L"flash")) || (!StrCmp (Argv[1], L"FLASH"))) {
    mGptFlash = TRUE;
  } else if ((!StrCmp (Argv[1], L"all")) || (!StrCmp (Argv[1], L"ALL"))) {
    mGptGen = TRUE;
    mGptFlash = TRUE;
  } else {
    ShowHelpInfo ();
    return EFI_INVALID_PARAMETER;
  }

  mPartData = AllocateZeroPool (sizeof (PARTITON_DATA));
  if (mPartData == NULL) {
    DEBUG ((DEBUG_ERROR, "Fail to allocate the partition data.\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = InitDevicePath ();
  if (EFI_ERROR (Status)) {
    Print (L"InitDevicePath failed.\n");
    FreePool (mPartData);
    return Status;
  }

  Status = ReadFileFromDisk (Argv[2], &BufferSize, &Buffer);
  if (EFI_ERROR (Status)) {
    Print (L"Read GPT metadata failed. %r\n", Status);
    FreePool (mPartData);
    return Status;
  }

  Status = FlashGpt (mPartData, Buffer, BufferSize);
  if (EFI_ERROR (Status)) {
    Print (L"FlashGpt failed. %r\n", Status);
    FreePool (mPartData);
    return Status;
  }

  if (mGptFlash) {
    Status = ReEnumeratePartitions (mPartData);
    if (EFI_ERROR (Status)) {
      Print (L"ReEnumeratePartitions failed. %r\n", Status);
    }
  }

  Print (L"GPT operation successfully.\n");

  if (Buffer != NULL) {
    FreePool (Buffer);
  }

  if (mPartData != NULL) {
    FreePool (mPartData);
  }

  return 0;
}
