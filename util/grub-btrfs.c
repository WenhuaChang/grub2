/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009,2010 Free Software Foundation, Inc.
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

#include <config.h>
#include <grub/types.h>
#include <grub/emu/misc.h>
#include <grub/util/misc.h>
#include <grub/misc.h>
#include <grub/device.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/env.h>
#include <grub/term.h>
#include <grub/mm.h>
#include <grub/lib/hexdump.h>
#include <grub/crypto.h>
#include <grub/command.h>
#include <grub/i18n.h>
#include <grub/zfs/zfs.h>
#include <grub/emu/hostfile.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "progname.h"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#include "argp.h"
#pragma GCC diagnostic error "-Wmissing-prototypes"
#pragma GCC diagnostic error "-Wmissing-declarations"

struct arguments
{
  char *pathname;
};

static struct argp_option options[] = { { 0, 0, 0, 0, 0, 0 } };

static error_t
argp_parser (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0)
	arguments->pathname = xstrdup (arg);
      else
	{
	  /* Too many arguments. */
	  fprintf (stderr, _("Unknown extra argument `%s'."), arg);
	  fprintf (stderr, "\n");
	  argp_usage (state);
	}
      break;
    case ARGP_KEY_NO_ARGS:
      fprintf (stderr, "%s", _("No path is specified.\n"));
      argp_usage (state);
      exit (1);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options,	 argp_parser,
			    N_ ("PATH"), N_ ("Test for Btrfs list subvolume"),
			    NULL,	 NULL,
			    NULL };

static grub_err_t
execute_command (const char *name, int n, char **args)
{
  grub_command_t cmd;

  cmd = grub_command_find (name);
  if (! cmd)
    grub_util_error (_("can't find command `%s'"), name);

  return (cmd->func) (cmd, n, args);
}

int
main (int argc, char *argv[])
{
  struct arguments arguments;
  char *cmd_args[2];
  char *image;

  grub_util_host_init (&argc, &argv);

  memset (&arguments, 0, sizeof (struct arguments));

  /* Check for options.  */
  if (argp_parse (&argp, argc, argv, 0, 0, &arguments) != 0)
    {
      fprintf (stderr, "Error in parsing command line arguments\n");
      exit (1);
    }

  /* Initialize all modules. */
  image = grub_canonicalize_file_name (arguments.pathname);
  if (image == NULL)
    {
      fprintf (stderr,
	       "Error in getting canonical path for %s ",
	       arguments.pathname);
      exit (1);
    }

  grub_init_all ();

  cmd_args[0] = xstrdup ("loop0");
  cmd_args[1] = grub_xasprintf ("(host)%s", image);
  if (execute_command ("loopback", 2, cmd_args))
    grub_util_error ("`loopback' command fails: %s", grub_errmsg);

  free (cmd_args[0]);
  free (cmd_args[1]);
  cmd_args[0] = xstrdup ("(loop0)");
  if (execute_command ("btrfs-list-subvols", 1, (char **) cmd_args))
    grub_util_error ("`btrfs-list-subvols' command fails: %s", grub_errmsg);

  grub_fini_all ();
  return 0;
}
