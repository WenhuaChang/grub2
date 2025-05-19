/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013 Free Software Foundation, Inc.
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

#include <grub/util/install.h>
#include <grub/emu/hostdisk.h>
#include <grub/util/misc.h>
#include <grub/misc.h>
#include <grub/i18n.h>
#include <grub/emu/exec.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <grub/util/ofpath.h>
#define BOOTDEV_BUFFER  1000

static char *
get_ofpathname (const char *dev)
{
  size_t alloced = 4096;
  char *ret = xmalloc (alloced);
  size_t offset = 0;
  int fd;
  pid_t pid;

  pid = grub_util_exec_pipe ((const char * []){ "ofpathname", dev, NULL }, &fd);
  if (!pid)
    goto fail;

  FILE *fp = fdopen (fd, "r");
  if (!fp)
    goto fail;

  while (!feof (fp))
    {
      size_t r;
      if (alloced == offset)
       {
         alloced *= 2;
         ret = xrealloc (ret, alloced);
       }
      r = fread (ret + offset, 1, alloced - offset, fp);
      offset += r;
    }

  if (offset > 0 && ret[offset - 1] == '\n')
    offset--;
  if (offset > 0 && ret[offset - 1] == '\r')
    offset--;
  if (alloced == offset)
    {
      alloced++;
      ret = xrealloc (ret, alloced);
    }
  ret[offset] = '\0';

  fclose (fp);

  return ret;

 fail:
  grub_util_error (_("couldn't find IEEE1275 device path for %s.\nYou will have to set `boot-device' variable manually"),
		   dev);
}

static int
grub_install_remove_efi_entries_by_distributor (const char *efi_distributor)
{
  int fd;
  pid_t pid = grub_util_exec_pipe ((const char * []){ "efibootmgr", NULL }, &fd);
  char *line = NULL;
  size_t len = 0;
  int rc = 0;

  if (!pid)
    {
      grub_util_warn (_("Unable to open stream from %s: %s"),
		      "efibootmgr", strerror (errno));
      return errno;
    }

  FILE *fp = fdopen (fd, "r");
  if (!fp)
    {
      grub_util_warn (_("Unable to open stream from %s: %s"),
		      "efibootmgr", strerror (errno));
      return errno;
    }

  line = xmalloc (80);
  len = 80;
  while (1)
    {
      int ret;
      char *bootnum;
      ret = getline (&line, &len, fp);
      if (ret == -1)
	break;
      if (grub_memcmp (line, "Boot", sizeof ("Boot") - 1) != 0
	  || line[sizeof ("Boot") - 1] < '0'
	  || line[sizeof ("Boot") - 1] > '9')
	continue;
      if (!strcasestr (line, efi_distributor))
	continue;
      bootnum = line + sizeof ("Boot") - 1;
      bootnum[4] = '\0';
      if (!verbosity)
	rc = grub_util_exec ((const char * []){ "efibootmgr", "-q",
	      "-b", bootnum,  "-B", NULL });
      else
	rc = grub_util_exec ((const char * []){ "efibootmgr",
	      "-b", bootnum, "-B", NULL });
    }

  free (line);
  return rc;
}

int
grub_install_register_efi (const grub_disk_t *efidir_grub_disk,
			   const char *efifile_path,
			   const char *efi_distributor,
			   const char *force_disk)
{
  int ret;
  const grub_disk_t *curdisk;
  int ndev = 0;

  if (grub_util_exec_redirect_null ((const char * []){ "efibootmgr", "--version", NULL }))
    {
      /* TRANSLATORS: This message is shown when required executable `%s'
	 isn't found.  */
      grub_util_error (_("%s: not found"), "efibootmgr");
    }

  /* On Linux, we need the efivars kernel modules.  */
#ifdef __linux__
  grub_util_exec ((const char * []){ "modprobe", "-q", "efivars", NULL });
#endif
  /* Delete old entries from the same distributor.  */
  ret = grub_install_remove_efi_entries_by_distributor (efi_distributor);
  if (ret)
    return ret;

  for (curdisk = efidir_grub_disk; *curdisk; curdisk++)
    ndev++;

  for (curdisk = efidir_grub_disk; *curdisk; curdisk++)
    {
      const char * efidir_disk;
      int efidir_part;
      char *efidir_part_str;
      char *new_efi_distributor = NULL;
      grub_disk_t disk = *curdisk;

      efidir_disk = force_disk ? : grub_util_biosdisk_get_osdev (disk);
      if (!efidir_disk)
	grub_util_error (_("%s: no device for efi"), disk->name);

      efidir_part = disk->partition ? disk->partition->number + 1 : 1;
      efidir_part_str = xasprintf ("%d", efidir_part);
      if (ndev > 1)
	{
	  const char *p = grub_strrchr (efidir_disk, '/');
	  new_efi_distributor = xasprintf ("%s (%s%d)\n",
			efi_distributor,
			p ? p + 1: efidir_disk,
			efidir_part);
	}

      if (!verbosity)
	ret = grub_util_exec ((const char * []){ "efibootmgr", "-q",
	  "-c", "-d", efidir_disk,
	  "-p", efidir_part_str, "-w",
	  "-L", new_efi_distributor ? : efi_distributor, "-l",
	  efifile_path, NULL });
      else
	ret = grub_util_exec ((const char * []){ "efibootmgr",
	  "-c", "-d", efidir_disk,
	  "-p", efidir_part_str, "-w",
	  "-L", new_efi_distributor ? : efi_distributor, "-l",
	  efifile_path, NULL });
      free (efidir_part_str);
      free (new_efi_distributor);
      if (ret)
	return ret;
    }
  return 0;
}


char *
add_multiple_nvme_bootdevices (const char *install_device)
{
  char *sysfs_path, *nvme_ns, *ptr, *non_splitter_path;
  unsigned int nsid;
  char *multipath_boot, *ofpath, *ext_dir;
  struct dirent *ep, *splitter_ep;
  DIR *dp, *splitter_dp;
  char *cntl_id, *dirR1, *dirR2, *splitter_info_path;
  int is_FC = 0, is_splitter = 0;

  nvme_ns = grub_strstr (install_device, "nvme");
  nsid = of_path_get_nvme_nsid (nvme_ns);
  if (nsid == 0)
    return NULL;

  sysfs_path = nvme_get_syspath (nvme_ns);
  ofpath = xasprintf ("%s",get_ofpathname (nvme_ns));

  if (grub_strstr (ofpath, "fibre-channel"))
    {
      strcat (sysfs_path, "/device");
      is_FC = 1;
    }
  else
    {
      strcat (sysfs_path, "/subsystem");
      is_FC = 0;
    }
  if (is_FC == 0)
    {
      cntl_id = grub_strstr (nvme_ns, "e");
      dirR1 = xasprintf ("nvme%c",cntl_id[1]);

      splitter_info_path = xasprintf ("%s%s%s", "/sys/block/", nvme_ns, "/device");
      splitter_dp = opendir (splitter_info_path);
      if (!splitter_dp)
        return NULL;

      while ((splitter_ep = readdir (splitter_dp)) != NULL)
        {
          if (grub_strstr (splitter_ep->d_name, "nvme"))
	     {
	       if (grub_strstr (splitter_ep->d_name, dirR1))
	         continue;

              ext_dir = grub_strstr (splitter_ep->d_name, "e");
              if (!(grub_strstr (ext_dir, "n")))
	         {
                  dirR2 = xasprintf("%s", splitter_ep->d_name);
	           is_splitter = 1;
	           break;
	         }
	    }
        }
      closedir (splitter_dp);
    }
  sysfs_path = xrealpath (sysfs_path);
  dp = opendir (sysfs_path);
  if (!dp)
    return NULL;

  ptr = multipath_boot = xmalloc (BOOTDEV_BUFFER);
  if (is_splitter == 0 && is_FC == 0)
    {
      non_splitter_path = xasprintf ("%s%s%x:1 ", get_ofpathname (dirR1), "/namespace@", nsid);
      strncpy (ptr, non_splitter_path, strlen (non_splitter_path));
      ptr += strlen (non_splitter_path);
      free (non_splitter_path);
    }
  else
    {
      while ((ep = readdir (dp)) != NULL)
        {
          char *path;
          if (grub_strstr (ep->d_name, "nvme"))
            {
              if (is_FC == 0 && !grub_strstr (ep->d_name, dirR1) && !grub_strstr (ep->d_name, dirR2))
                continue;
              path = xasprintf ("%s%s%x ", get_ofpathname (ep->d_name), "/namespace@", nsid);
              if ((strlen (multipath_boot) + strlen (path)) > BOOTDEV_BUFFER)
                {
                  grub_util_warn (_("Maximum five entries are allowed in the bootlist"));
                  free (path);
                  break;
                }
              strncpy (ptr, path, strlen (path));
              ptr += strlen (path);
              free (path);
            }
        }
    }
  *--ptr = '\0';
  closedir (dp);

  return multipath_boot;
}

void
grub_install_register_ieee1275 (int is_prep, const char *install_device,
				int partno, const char *relpath)
{
  char *boot_device;

  if (grub_util_exec_redirect_null ((const char * []){ "ofpathname", "--version", NULL }))
    {
      /* TRANSLATORS: This message is shown when required executable `%s'
	 isn't found.  */
      grub_util_error (_("%s: not found"), "ofpathname");
    }

  /* Get the Open Firmware device tree path translation.  */
  if (!is_prep)
    {
      char *ptr;
      char *ofpath;
      const char *iptr;

      ofpath = get_ofpathname (install_device);
      boot_device = xmalloc (strlen (ofpath) + 1
			     + sizeof ("XXXXXXXXXXXXXXXXXXXX")
			     + 1 + strlen (relpath) + 1);
      ptr = grub_stpcpy (boot_device, ofpath);
      *ptr++ = ':';
      grub_snprintf (ptr, sizeof ("XXXXXXXXXXXXXXXXXXXX"), "%d",
		     partno);
      ptr += strlen (ptr);
      *ptr++ = ',';
      for (iptr = relpath; *iptr; iptr++, ptr++)
	{
	  if (*iptr == '/')
	    *ptr = '\\';
	  else
	    *ptr = *iptr;
	}
      *ptr = '\0';
    }
  else if (grub_strstr (install_device, "nvme"))
    {
      boot_device = add_multiple_nvme_bootdevices (install_device);
    }
  else
    {
      boot_device = get_ofpathname (install_device);
      if (grub_strstr (boot_device, "nvme-of"))
        {
          free (boot_device);
          boot_device = add_multiple_nvme_bootdevices (install_device);
        }
    }

  if (grub_util_exec ((const char * []){ "nvsetenv", "boot-device",
	  boot_device, NULL }))
    {
      char *cmd = xasprintf ("setenv boot-device %s", boot_device);
      grub_util_error (_("`nvsetenv' failed. \nYou will have to set `boot-device' variable manually.  At the IEEE1275 prompt, type:\n  %s\n"),
		       cmd);
      free (cmd);
    }

  free (boot_device);
}

void
grub_install_sgi_setup (const char *install_device,
			const char *imgfile, const char *destname)
{
  grub_util_exec ((const char * []){ "dvhtool", "-d",
	install_device, "--unix-to-vh",
	imgfile, destname, NULL });
  grub_util_warn ("%s", _("You will have to set `SystemPartition' and `OSLoader' manually."));
}

void
grub_install_zipl (const char *dest, int install, int force)
{
  if (grub_util_exec ((const char * []){ PACKAGE"-zipl-setup",
	verbosity ? "-v" : "",
	install ? "" : "--debug",
	!force ? "" : "--force",
	"-z", dest, NULL }))
    grub_util_error (_("`%s' failed.\n"), PACKAGE"-zipl-setup");
}

char *
grub_install_get_filesystem (const char *path)
{
  int fd;
  pid_t pid;
  FILE *fp;
  ssize_t len;
  char *buf = NULL;
  size_t bufsz = 0;

  pid = grub_util_exec_pipe ((const char * []){ "stat", "-f", "-c", "%T", path, NULL }, &fd);
  if (!pid)
    return NULL;

  fp = fdopen (fd, "r");
  if (!fp)
    return NULL;

  len = getline (&buf, &bufsz, fp);
  if (len == -1)
    {
      free (buf);
      fclose (fp);
      return NULL;
    }

  fclose (fp);

  if (len > 0 && buf[len - 1] == '\n')
    buf[len - 1] = '\0';

  return buf;
}
