#include <stdbool.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include "uusb.h"
#include "scard.h"
#include "bufparser.h"
#include "util.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define MAX_CARDOPTS	16

enum
{
  UTOKEN_OPTION_DEVICE,
  UTOKEN_OPTION_TYPE,
  UTOKEN_OPTION_PIN,
  UTOKEN_OPTION_OUTPUT,
  UTOKEN_OPTION_CARD_OPTION,
};

static const struct grub_arg_option
grub_utoken_decrypt_options[] =
  {
    {
      .longarg  = "device",
      .shortarg = 'D',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "type",
      .shortarg = 'T',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "pin",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "output",
      .shortarg = 'o',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    {
      .longarg  = "card-option",
      .shortarg = 'C',
      .flags    = GRUB_ARG_OPTION_REPEATABLE,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      = N_(""),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

static buffer_t *
doit(uusb_dev_t *dev, const char *pin, buffer_t *ciphertext, unsigned int ncardopts, char **cardopts)
{
	ccid_reader_t *reader;
	ifd_card_t *card;
	buffer_t *cleartext;

	if (!(reader = ccid_reader_create(dev))) {
		error("Unable to create reader for USB device\n");
		return NULL;
	}

	if (!ccid_reader_select_slot(reader, 0))
		return NULL;

	card = ccid_reader_identify_card(reader, 0);
	if (card == NULL)
		return NULL;

	if (ncardopts) {
		unsigned int i;
		for (i = 0; i < ncardopts; ++i) {
			if (!ifd_card_set_option(card, cardopts[i]))
				return NULL;
		}
	}

	if (!ifd_card_connect(card))
		return NULL;

	if (pin != NULL) {
		unsigned int retries_left;

		if (!ifd_card_verify(card, pin, strlen(pin), &retries_left)) {
			error("Wrong PIN, %u attempts left\n", retries_left);
			return NULL;
		}

		infomsg("Successfully verified PIN.\n");
	}

	cleartext = ifd_card_decipher(card, ciphertext);
	if (cleartext == NULL) {
		error("Card failed to decrypt secret\n");
		return NULL;
	}

	return cleartext;
}

static grub_err_t
grub_utoken_decrypt (grub_extcmd_context_t ctxt,
    int argc,
    char **args)
{
  buffer_t *secret;
  buffer_t *cleartext;
  char *cardopts[MAX_CARDOPTS];
  unsigned int ncardopts = 0;
  char *opt_device = NULL;
  char *opt_type = NULL;
  char *opt_pin = NULL;
  char *opt_input = NULL;
  char *opt_output = NULL;
  uusb_dev_t *dev = NULL;

  struct grub_arg_list *state = ctxt->state;

  if (!argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "no secret file provided");

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "expect only one secret file");

  if (state[UTOKEN_OPTION_DEVICE].set)
    opt_device = state[UTOKEN_OPTION_DEVICE].arg;

  if (state[UTOKEN_OPTION_TYPE].set)
    opt_type = state[UTOKEN_OPTION_TYPE].arg;

  if (state[UTOKEN_OPTION_PIN].set)
    opt_pin = state[UTOKEN_OPTION_PIN].arg;

  if (state[UTOKEN_OPTION_OUTPUT].set)
    opt_output = state[UTOKEN_OPTION_OUTPUT].arg;

  if (state[UTOKEN_OPTION_CARD_OPTION].set)
    {
      int i;

      for (ncardopts = 0; state[UTOKEN_OPTION_CARD_OPTION].args[ncardopts]; ncardopts++);

      if (ncardopts > MAX_CARDOPTS)
	return grub_error (GRUB_ERR_BAD_ARGUMENT, "Too many card options");

      for (i = 0; i < ncardopts; i++)
	cardopts[i] = state[UTOKEN_OPTION_CARD_OPTION].args[i];
    }

  opt_input = args[0];
  secret = buffer_read_file(opt_input, 0);

  if (opt_type) {
    uusb_type_t type;

    if (!usb_parse_type(opt_type, &type))
      return GRUB_ERR_BAD_ARGUMENT;
    dev = usb_open_type(&type);
  }

  if (dev == NULL)
    return GRUB_ERR_BAD_ARGUMENT;
  
  yubikey_init();
  if (!(cleartext = doit(dev, opt_pin, secret, ncardopts, cardopts)))
    return GRUB_ERR_BUG;
  infomsg("Writing data to \"<stdout>\"\n");
  buffer_print(cleartext);
  infomsg("\n");
  buffer_free(cleartext);
  return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(utoken)
{
  cmd = grub_register_extcmd ("utoken_decrypt",
	grub_utoken_decrypt, 0,
	N_("[-D device] "
	   "[-T type] "
	   "[-p pin] "
	   "[-o output] "
	   "[-C card-option] "
	   "secret_file"),
	N_("Decrypt secret_file by USB CCID device."),
	grub_utoken_decrypt_options);
}

GRUB_MOD_FINI(utoken)
{
  grub_unregister_extcmd (cmd);
}
