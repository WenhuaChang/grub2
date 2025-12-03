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

#include <grub/list.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/file.h>
#include <grub/normal.h>
#include <grub/lib/envblk.h>
#include <grub/file.h>
#include <grub/normal.h>

#include <stdbool.h>

GRUB_MOD_LICENSE ("GPLv3+");

/*
 * TODO:
 *  Need support in Btrfs fs layer to fully work:
 *  1. Resolve symlinks to vmlinuz
 *  2. List Readonly snapshot
 *  3. Test File on separate subvolume
 * Also
 *  Parse snapshot's xmlinfo to display on menu title
 * */

/*
 * It sort of work with this grub.cfg sample:
 *
 *   loopback loop0 (host)/dev/vda2
 *
 *   btrfs-list-subvols -p -o allsubvols (loop0)
 *   for s in $allsubvols; do
 *      btrfs_snapcfg loop0 $s
 *   done
 */

static const struct grub_arg_option options[] = { { 0, 0, 0, 0, 0, 0 } };

static bool
is_file_present (const char *dev, const char *subvol, const char *path)
{
  grub_file_t file;
  char *abspath;

  abspath = grub_xasprintf ("(%s)/%s%s", dev, subvol, path);

  if (abspath == NULL)
    return false;

  /* HACK !!!!
   *
   * Need Btrfs function to check file on non-default subvolume
   * */
  grub_env_set ("btrfs_relative_path", "0");

  file = grub_file_open (abspath, GRUB_FILE_TYPE_GET_SIZE | GRUB_FILE_TYPE_NO_DECOMPRESS);
  if (file == NULL)
    {
      grub_env_set ("btrfs_relative_path", "1");
      grub_free (abspath);
      return false;
    }
  if (grub_file_size (file) == 0)
    {
      grub_file_close (file);
      grub_env_set ("btrfs_relative_path", "1");
      grub_free (abspath);
      return false;
    }

  grub_file_close (file);
  grub_env_set ("btrfs_relative_path", "1");
  grub_free (abspath);

  return true;
}

static char *
setparams_prefix (int argc, char **args)
{
  int i;
  int j;
  char *p;
  char *result;
  grub_size_t len = 10;

  /* Count resulting string length */
  for (i = 0; i < argc; i++)
    {
      len += 3; /* 3 = 1 space + 2 quotes */
      p = args[i];
      while (*p)
	len += (*p++ == '\'' ? 4 : 1);
    }

  result = grub_malloc (len + 2);
  if (! result)
    return 0;

  grub_strcpy (result, "setparams");
  p = result + 9;

  for (j = 0; j < argc; j++)
    {
      *p++ = ' ';
      *p++ = '\'';
      p = grub_strchrsub (p, args[j], '\'', "'\\''");
      *p++ = '\'';
    }
  *p++ = '\n';
  *p = '\0';
  return result;
}

static void
add_snapshot_entry (const char *subvol)
{
  char *argv[3] = {grub_xasprintf ("Snapshot: %s", subvol),  grub_strdup (subvol), NULL};
  int index;
  char *src = NULL;
  char *prefix;

  /* TODO : Add info from info.xml */
  src = grub_xasprintf ("saved_subvol=$btrfs_subvol\n"
			"btrfs_subvol=\"$2\"\n"
			"extra_cmdline=\"rootflags=subvol=$2\"\n"
			"export extra_cmdline\n"
			"snapshot_num=3\n"
			"export snapshot_num\n"
			"configfile \"/boot/grub2/grub.cfg\"\n"
			"btrfs_subvol=$saved_subvol\n");

  if (src == NULL)
    return;

  prefix = setparams_prefix (2, argv);
  if (prefix == NULL)
    return;

  grub_normal_add_menu_entry (2, (const char**) argv, NULL, NULL, NULL, NULL, prefix, src, 0, 0, &index, NULL);

  grub_free (argv[0]);
  grub_free (argv[1]);
  grub_free (prefix);
}

static grub_err_t
grub_cmd_btrfs_snapcfg (grub_extcmd_context_t ctxt UNUSED,
		 int argc, char **argv)
{
  grub_device_t dev;
  grub_fs_t fs;

  if (argc < 2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "No DEVICE AND SUBVOL specified\n");

  dev = grub_device_open (argv[0]);
  if (dev == NULL)
    return grub_errno;

  fs = grub_fs_probe (dev);
  if (fs == NULL)
    {
      grub_device_close (dev);
      return grub_errno;
    }

  if (grub_strcmp (fs->name, "btrfs") != 0)
    {
      grub_device_close (dev);
      grub_printf ("Not a Btrfs File System!");
      return GRUB_ERR_NONE;
    }

  /* TODO: Add check for subvolume AND readonly */
  /* TODO: check if grub.cfg is present, iow bootable */
  if (is_file_present (argv[0], argv[1], "/boot/grub2/grub.cfg") == false)
    {
      grub_printf ("/boot/grub2/grub.cfg is not present in %s\n",  argv[1]);
      return GRUB_ERR_NONE;
    }
  grub_printf ("File check OK.\n");

  /* TODO: Parse info.xml */
  add_snapshot_entry (argv[1]);
  grub_print_error ();
  return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd_btrfs_snapcfg;

GRUB_MOD_INIT(btrfs_snapcfg)
{
  cmd_btrfs_snapcfg = grub_register_extcmd ("btrfs_snapcfg",
			      grub_cmd_btrfs_snapcfg,
			      0,
			      NULL,
			      "Create menu entry for booting Btrfs snapshot",
			      options);
}

GRUB_MOD_FINI(btrfs_snapcfg)
{
  grub_unregister_extcmd (cmd_btrfs_snapcfg);
}
