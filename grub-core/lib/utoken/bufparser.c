/*
 *   Copyright (C) 2022, 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <unistd.h>
#include <string.h>
#include <grub/file.h>
#include "bufparser.h"

/* This should be moved to bufparser.h */
#define debug(fmt, ...) grub_dprintf ("utoken", fmt, ##__VA_ARGS__)

buffer_t *
buffer_read_file(const char *filename, int flags __attribute__ ((unused)))
{
  grub_file_t file = NULL;
  buffer_t *bp;
  grub_ssize_t count;

  if (!filename)
    fatal("No filename specified\n");

  file = grub_file_open(filename, GRUB_FILE_TYPE_SIGNATURE);
  if (!file)
    fatal("Unable to open file %s\n", filename);

  bp = buffer_alloc_write(file->size);
  if (bp == NULL)
    fatal("Cannot allocate buffer of %" PRIuGRUB_OFFSET " bytes for %s\n",
          file->size, filename);

  count = grub_file_read(file, bp->data, file->size);
  if (count < 0)
    fatal("Error while reading from %s\n", filename);

  if (count != file->size)
    fatal("Short read from %s\n", filename);

  grub_file_close(file);

  debug("Read %" PRIdGRUB_SSIZE " bytes from %s\n", count, filename);
  bp->wpos = count;
  return bp;
}

bool
buffer_print(buffer_t *bp)
{
  int n;
  char output[512];
  char *pout = output;
  int sz = sizeof(output)/sizeof(char) - 1;

  while (sz && (n = buffer_available(bp)) != 0) {
    grub_memcpy(pout, buffer_read_pointer(bp), n);
    buffer_skip(bp, n);
    sz -= n;
    pout += n;
  }

  *pout = '\0';
  grub_printf("%s", output);

  return true;
}

#if 0
bool
buffer_write_file(const char *filename, buffer_t *bp)
{
	const char *display_name = filename;
	unsigned int written = 0;
	int fd, n;
	bool closeit = true;

	if (filename == NULL || !strcmp(filename, "-")) {
		display_name = "<stdout>";
		closeit = false;
		fd = 1;
	} else
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
		fatal("Unable to open file %s: %m\n", display_name);
	}

	while ((n = buffer_available(bp)) != 0) {
		n = write(fd, buffer_read_pointer(bp), n);
		if (n < 0)
			fatal("write error on %s: %m\n", display_name);

		buffer_skip(bp, n);
		written += n;
	}

	if (closeit)
		close(fd);

	debug("Wrote %u bytes to %s\n", written, display_name);
	return true;
}
#endif
