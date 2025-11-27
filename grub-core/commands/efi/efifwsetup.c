/* fwsetup.c - Reboot into firmware setup menu. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2012  Free Software Foundation, Inc.
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

#include <grub/types.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/normal.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_efi_boolean_t efifwsetup_is_supported (void);

static grub_err_t
grub_cmd_fwsetup (grub_command_t cmd __attribute__ ((unused)),
		  int argc __attribute__ ((unused)),
		  char **args __attribute__ ((unused)))
{
  grub_efi_uint64_t *old_os_indications;
  grub_efi_uint64_t os_indications = GRUB_EFI_OS_INDICATIONS_BOOT_TO_FW_UI;
  grub_err_t status;
  grub_size_t oi_size;
  static grub_guid_t global = GRUB_EFI_GLOBAL_VARIABLE_GUID;

  if (argc >= 1 && grub_strcmp(args[0], "--is-supported") == 0)
    return !efifwsetup_is_supported ();

  if (!efifwsetup_is_supported ())
	  return grub_error (GRUB_ERR_INVALID_COMMAND,
			     N_("reboot to firmware setup is not supported by the current firmware"));

  grub_efi_get_variable ("OsIndications", &global, &oi_size,
			 (void **) &old_os_indications);

  if (old_os_indications != NULL && oi_size == sizeof (os_indications))
    os_indications |= *old_os_indications;

  grub_free (old_os_indications);

  status = grub_efi_set_variable ("OsIndications", &global, &os_indications,
				  sizeof (os_indications));
  if (status != GRUB_ERR_NONE)
    return status;

  grub_reboot ();

  return GRUB_ERR_BUG;
}

static grub_command_t cmd = NULL, cmd_fwsetup_auto = NULL;

static grub_efi_boolean_t
efifwsetup_is_supported (void)
{
  grub_efi_uint64_t *os_indications_supported = NULL;
  grub_size_t oi_size = 0;
  static grub_guid_t global = GRUB_EFI_GLOBAL_VARIABLE_GUID;
  grub_efi_boolean_t ret = 0;

  grub_efi_get_variable ("OsIndicationsSupported", &global, &oi_size,
			 (void **) &os_indications_supported);

  if (!os_indications_supported)
    goto done;

  if (*os_indications_supported & GRUB_EFI_OS_INDICATIONS_BOOT_TO_FW_UI)
    ret = 1;

 done:
  grub_free (os_indications_supported);
  return ret;
}

static grub_err_t
grub_cmd_efifwsetup_auto (grub_command_t command __attribute__ ((unused)),
			  int argc __attribute__ ((unused)),
			  char **args __attribute__ ((unused)))
{
  const char *argv[] = { "UEFI Firmware Settings" };

  if (efifwsetup_is_supported () == false)
    return GRUB_ERR_NONE;

  grub_normal_add_menu_entry (1,
			      argv,
			      NULL,
			      "uefi-firmware",
			      NULL,
			      NULL,
			      NULL,
			      "fwsetup\n",
			      0,
			      0,
			      NULL,
			      NULL);
  return GRUB_ERR_NONE;
}

GRUB_MOD_INIT (efifwsetup)
{
  cmd = grub_register_command ("fwsetup", grub_cmd_fwsetup, NULL,
                               N_("Reboot into firmware setup menu."));
  cmd_fwsetup_auto = grub_register_command ("efifwsetup_auto", grub_cmd_efifwsetup_auto,
			       NULL, N_("Show UEFI fwsetup menu automatically."));
}

GRUB_MOD_FINI (efifwsetup)
{
  if (cmd)
    grub_unregister_command (cmd);
  if (cmd_fwsetup_auto != NULL)
    grub_unregister_command (cmd_fwsetup_auto);
}
