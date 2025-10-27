/*-*- Mode: C; c-basic-offset: 2; indent-tabs-mode: t -*-*/

/* blsbumpcounter.c - implementation of boot counting for the Automatic Boot Assessment */

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
#include <grub/dl.h>

#include <stddef.h>

GRUB_MOD_LICENSE ("GPLv3+");


static grub_err_t
grub_cmd_bumpcounters (grub_extcmd_context_t ctxt __attribute__ ((unused)),
         int argc __attribute__ ((unused)), char **args __attribute__ ((unused)))
{
    /* placeholder, as blsbumpcounter only work on EFI platforms */
  return GRUB_ERR_NONE;
}


static grub_extcmd_t cmd;

GRUB_MOD_INIT(blsbumpcounter)
{
  cmd = grub_register_extcmd ("bls_bumpcounter",
                  grub_cmd_bumpcounters,
                  0,
                  NULL,
                  N_("Bump the boot entry counting (only works on EFI)."),
                  NULL);
}

GRUB_MOD_FINI(blsbumpcounter)
{
  grub_unregister_extcmd (cmd);
}
