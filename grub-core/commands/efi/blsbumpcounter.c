/*-*- Mode: C; c-basic-offset: 2; indent-tabs-mode: t -*-*/

/* bls.c - implementation of the boot loader spec */

/*
 *  GRUB  --  GRand Unified Bootloader
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/extcmd.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/lib/envblk.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/filesystem.h>

#include <stddef.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_BLS_CONFIG_PATH "\\loader\\entries\\"

#define GRUB_EFI_LOADER_GUID \
        { 0x4a67b082, 0x0a4c, 0x41cf, { 0xb6, 0xc7, 0x44, 0x0b, 0x29, 0xbb, 0x8c, 0x4f } }

static grub_guid_t grub_simple_file_system_guid = GRUB_EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static grub_guid_t grub_efi_loader_guid = GRUB_EFI_LOADER_GUID;

static grub_err_t
grub_cmd_bumpcounters (grub_extcmd_context_t ctxt __attribute__ ((unused)),
         int argc, char **args)
{
  grub_efi_file_info_t *file_info = NULL;
  grub_efi_file_protocol_t *handle = NULL;
  grub_efi_file_protocol_t *root = NULL;
  grub_efi_simple_file_system_protocol_t *volume = NULL;
  char* id = NULL;

  grub_dprintf("bls_bumpcounter", "starting bumpcounter\n");
  /* There should be exactly two arguments, the entry that is getting booted and the disk where
     it can be found */
  if (argc != 1) {
    grub_dprintf("bls_bumpcounter", "one argument should be passed\n");
    return GRUB_ERR_BAD_ARGUMENT;
  }
  id = args[0];

  /* Look for the start of the count
     If no '+' symbol has been found, the boot counting isn't enabled for the selected entry */
  if (grub_strrchr(id, '+') == NULL) {
    grub_dprintf("bls_bumpcounter", "boot counting is not in effect for id %s\n", id);
    return GRUB_ERR_NONE;
  }

  grub_efi_loaded_image_t *image = NULL;
  grub_dprintf("bls_bumpcounter", "Using loaded EFI image device\n");
  image = grub_efi_get_loaded_image (grub_efi_image_handle);

  if (!image) {
    grub_dprintf("bls_bumpcounter", "grub_efi_get_loaded_image failed\n");
    return 0;
  }

  grub_efi_status_t err;
  grub_efi_boot_services_t *bs;
  bs = grub_efi_system_table->boot_services;
  err = bs->handle_protocol (image->device_handle,
				(void *) &grub_simple_file_system_guid, (void *) &volume);
  if (err != GRUB_EFI_SUCCESS) {
    grub_dprintf("bls_bumpcounter", "Cannot get handle to EFI_SIMPLE_FILE_SYSTEM_PROTOCOL: %lu\n", (unsigned long)err);
    return GRUB_ERR_BAD_DEVICE; 
  }
  volume->OpenVolume(volume, &root);
  if (err != GRUB_EFI_SUCCESS) {
    grub_dprintf("bls_bumpcounter", "Cannot open the volume: %lu\n", (unsigned long)err);
    return GRUB_ERR_BAD_DEVICE;
  }

  char *blsdir = (char *)grub_env_get ("blsdir");
  char *tmp = NULL;
  if (blsdir) {
    tmp = blsdir;
    while (*tmp) {
      if (*tmp == '/') {
        /* Replace linux path delimiter (/) with EFI compatible (\) */
        *tmp = '\\';
      }
      tmp++;
    }
  } else {
    blsdir = (char *)GRUB_BLS_CONFIG_PATH;
  }

  unsigned long int len = grub_strlen(blsdir) + grub_strlen(id) + sizeof(".conf") + 1;
  grub_efi_char16_t* old_path = grub_malloc(len * sizeof(grub_efi_char16_t));
  if (!old_path)
  {
    grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
    goto finish;
  }
  grub_efi_char16_t* tmp_path = old_path;
  tmp = blsdir;
  while (*tmp) {
      *tmp_path++ = (grub_efi_char16_t)*tmp++;
  }
  tmp = id;
  while (*tmp) {
      *tmp_path++ = (grub_efi_char16_t)*tmp++;
  }
  static const char* ext = ".conf";
  tmp = (char *)ext;
  while (*tmp) {
      *tmp_path++ = (grub_efi_char16_t)*tmp++;
  }
  *tmp_path = (grub_efi_char16_t)'\0';

  err = root->Open(root, &handle, old_path, GRUB_EFI_FILE_MODE_READ|GRUB_EFI_FILE_MODE_WRITE, 0);
  grub_free(old_path);
  if (err != GRUB_EFI_SUCCESS) {
    grub_dprintf("bls_bumpcounter", "Cannot open the entry %s%s.conf : %lu\n", blsdir, id, (unsigned long)err);
    goto finish;
  }

  /* Just like get_file_info works in systemd:src/boot/efi/util.c, get the file_info */
  grub_efi_uint64_t size = offsetof(grub_efi_file_info_t, FileName) + 256U * sizeof(grub_efi_char16_t);
  file_info = grub_malloc(size);
  if (!file_info)
  {
    grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
    goto finish;
  }
  grub_guid_t grub_efi_file_info_guid = GRUB_EFI_FILE_INFO_ID;
  err = handle->GetInfo(handle, &grub_efi_file_info_guid, &size, file_info);
  if (err == GRUB_EFI_BUFFER_TOO_SMALL) {
    grub_free(file_info);
    file_info = grub_malloc(size);
    if (!file_info) {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("out of memory"));
      goto finish;
    }
    err = handle->GetInfo(handle, &grub_efi_file_info_guid, &size, file_info);
  }

  if (err != GRUB_EFI_SUCCESS) {
    grub_dprintf("bls_bumpcounter", "Cannot get the file_info of the entry: %lu\n", (unsigned long)err);
    goto finish;
  }

  /* Calculate the new filename with the bumped counter
     Look for the start of the count */
  tmp = grub_strrchr(id, '+');
  *tmp = '\0';
  int tries = -1;
  int tries_left = grub_strtol(++tmp, (const char**) &tmp, 10);
  /* The parsing succeeded */
  if (tmp != NULL) {
    if (tries_left > 0) {
      tries_left--;
    }
    if (*tmp == '-') {
      tmp++;
      tries = grub_strtol(tmp, (const char**) &tmp, 10);
      if (tmp != NULL) {
        tries++;
      } else {
        tries = -1;
      }
    }
  } else {
      goto finish;
  }

  char *new_path;
  if (tries == -1) {
    /* This is the first try, rename accordingly */
    new_path = grub_xasprintf ("%s+%d-1.conf", id, tries_left);
  } else {
    new_path = grub_xasprintf ("%s+%d-%d.conf", id, tries_left, tries);
  }
  grub_dprintf("bls_bumpcounter", "renaming entry to %s\n", new_path);

  /* Copy the new filename into the file_info struct */
  char* src = new_path;
  grub_efi_char16_t *dst = file_info->FileName;
  while (*src) {
    *dst++ = (grub_efi_char16_t) *src++;
  }
  *dst = (grub_efi_char16_t) '\0';

  handle->SetInfo(handle, &grub_efi_file_info_guid, size, file_info);

  if (err != GRUB_EFI_SUCCESS) {
    grub_dprintf("bls_bumpcounter", "Cannot rename file: %lu\n", (unsigned long)err);
    goto finish;
  }

  handle->Flush(handle);
  grub_dprintf("bls_bumpcounter", "entry renamed\n");
  handle->Close(handle);

  char* loader_boot_count_path = grub_xasprintf("%s%s", blsdir, new_path);
  grub_free(new_path);
  grub_efi_set_variable_to_string("LoaderBootCountPath", &grub_efi_loader_guid, loader_boot_count_path,
					      GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS |
					      GRUB_EFI_VARIABLE_RUNTIME_ACCESS);
  grub_free(loader_boot_count_path);

  if (err != GRUB_EFI_SUCCESS) {
      goto finish;
  }

  grub_free(file_info);

  return GRUB_ERR_NONE;

finish:
  grub_free(file_info);

  return GRUB_ERR_BAD_DEVICE;
}


static grub_extcmd_t cmd;

GRUB_MOD_INIT(blsbumpcounter)
{
  grub_dprintf("bls_bumpcounter", "%s got here\n", __func__);
  cmd = grub_register_extcmd ("bls_bumpcounter",
                  grub_cmd_bumpcounters,
                  0,
                  NULL,
                  N_("Bump the boot entry counting."),
                  NULL);
}

GRUB_MOD_FINI(blsbumpcounter)
{
  grub_unregister_extcmd (cmd);
}
