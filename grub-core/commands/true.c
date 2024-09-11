/* true.c - true and false commands.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
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
#include <grub/command.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_true (struct grub_command *cmd __attribute__ ((unused)),
	       int argc __attribute__ ((unused)),
	       char *argv[] __attribute__ ((unused)))
{
  return 0;
}

static grub_err_t
grub_cmd_false (struct grub_command *cmd __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char *argv[] __attribute__ ((unused)))
{
  return grub_error (GRUB_ERR_TEST_FAILURE, N_("false"));
}

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/disk.h>
#include <grub/device.h>
#include <grub/partition.h>
#include <grub/file.h>
#include <grub/normal.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>

static int
print_devices (const char *name, void *data)
{
  (void) data;
  grub_disk_t disk;
  int is_crypto = 0;

  disk = grub_disk_open (name);

  if (!disk)
    {
      grub_printf ("(%s) ERR: ", name);
      grub_print_error ();
      return 0;
    }

  is_crypto = grub_disk_is_crypto (disk);
  grub_printf ("(%s) is_crypto: %d\n", name, is_crypto);

  if (is_crypto)
    {
      char *buf;
      grub_file_t file;

      const char *sig[] = {"/boot/grub2/grub.cfg", "/grub2/grub.cfg", NULL};
      const char **ps;

      for (ps = sig; *ps; ps++)
	grub_printf ("test sigs 1 %s\n", *ps);

      grub_printf ("??\n");

      /* TODO /grub2/grub.cfg */
      buf = grub_xasprintf ("(%s)/boot/grub2/grub.cfg", name);
      if (! buf)
	return 1;

      file = grub_file_open (buf, GRUB_FILE_TYPE_FS_SEARCH
			     | GRUB_FILE_TYPE_NO_DECOMPRESS);
      if (file)
	{
	  grub_printf ("(%s) is root!\n", name);
	  grub_file_close (file);
	}
      else
	grub_print_error ();

      grub_free (buf);
    }

  grub_disk_close (disk);
  return 0;
}

static grub_err_t
grub_cmd_lscryptdev (struct grub_command *cmd __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char *argv[] __attribute__ ((unused)))
{
  grub_device_iterate (print_devices, NULL);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd_true, cmd_false;
static grub_command_t cmd_lscryptdev;


GRUB_MOD_INIT(true)
{
  cmd_true =
    grub_register_command ("true", grub_cmd_true,
			   /* TRANSLATORS: it's a command description.  */
			   0, N_("Do nothing, successfully."));
  cmd_false =
    grub_register_command ("false", grub_cmd_false,
			   /* TRANSLATORS: it's a command description.  */
			   0, N_("Do nothing, unsuccessfully."));
  cmd_lscryptdev =
    grub_register_command ("lscryptdev", grub_cmd_lscryptdev,
			   /* TRANSLATORS: it's a command description.  */
			   0, N_("List all encrypted devices."));
}

GRUB_MOD_FINI(true)
{
  grub_unregister_command (cmd_true);
  grub_unregister_command (cmd_false);
  grub_unregister_command (cmd_lscryptdev);
}
