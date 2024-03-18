/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
 *  Copyright (C) 2024 Free Software Foundation, Inc.
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

#include <grub/dl.h>
#include <grub/list.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/key_protector.h>

GRUB_MOD_LICENSE ("GPLv3+");

#ifdef GRUB_MACHINE_EFI
#include <grub/efi/efi.h>
#endif

struct grub_key_protector *grub_key_protectors = NULL;

grub_err_t
grub_key_protector_register (struct grub_key_protector *protector)
{
  if (protector == NULL || protector->name == NULL || protector->name[0] == '\0')
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "Invalid key protector for registration");

  if (grub_key_protectors != NULL &&
      grub_named_list_find (GRUB_AS_NAMED_LIST (grub_key_protectors), protector->name) != NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "Key protector '%s' already registered", protector->name);

  grub_list_push (GRUB_AS_LIST_P (&grub_key_protectors), GRUB_AS_LIST (protector));

  return GRUB_ERR_NONE;
}

grub_err_t
grub_key_protector_unregister (struct grub_key_protector *protector)
{
  if (protector == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "Invalid key protector for unregistration");

  grub_list_remove (GRUB_AS_LIST (protector));

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_key_protector_check_blocklist (void)
{
#ifdef GRUB_MACHINE_EFI
  static grub_guid_t systemd_guid = GRUB_EFI_SYSTEMD_GUID;
  grub_efi_status_t status;
  grub_size_t size = 0;
  grub_uint8_t *systemdoptions = NULL;

  /* SystemdOptions may contain malicious kernel command lines. */
  status = grub_efi_get_variable ("SystemdOptions", &systemd_guid,
				  &size, (void **) &systemdoptions);
  if (status != GRUB_EFI_NOT_FOUND)
  {
    grub_free (systemdoptions);
    return grub_error (GRUB_ERR_ACCESS_DENIED, N_("SystemdOptions detected"));
  }
#endif

  return GRUB_ERR_NONE;
}

grub_err_t
grub_key_protector_recover_key (const char *protector, grub_uint8_t **key,
				grub_size_t *key_size)
{
  struct grub_key_protector *kp = NULL;
  grub_err_t err;

  if (grub_key_protectors == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "No key protector registered");

  if (protector == NULL || protector[0] == '\0')
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "Invalid key protector");

  kp = grub_named_list_find (GRUB_AS_NAMED_LIST (grub_key_protectors), protector);
  if (kp == NULL)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "Key protector '%s' not found", protector);

  err = grub_key_protector_check_blocklist ();
  if (err != GRUB_ERR_NONE)
    return err;

  return kp->recover_key (key, key_size);
}
