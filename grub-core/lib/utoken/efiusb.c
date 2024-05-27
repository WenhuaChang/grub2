#include <stdbool.h>
#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_EFI_USB_IO_GUID \
  { 0x2B2F68D6, 0x0CD2, 0x44cf, \
    {0x8E, 0x8B, 0xBB, 0xA2, 0x0B, 0x1B, 0x5B, 0x75 } \
  }
struct grub_efi_usb_device_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_uint16_t   bcd_usb;
  grub_efi_uint8_t    device_class;
  grub_efi_uint8_t    device_sub_class;
  grub_efi_uint8_t    device_protocol;
  grub_efi_uint8_t    max_packet_size;
  grub_efi_uint16_t   id_vendor;
  grub_efi_uint16_t   id_product;
  grub_efi_uint16_t   bcd_device;
  grub_efi_uint8_t    str_manufacturer;
  grub_efi_uint8_t    str_product;
  grub_efi_uint8_t    str_serial_number;
  grub_efi_uint8_t    num_configurations;
} GRUB_PACKED;

typedef struct grub_efi_usb_device_descriptor grub_efi_usb_device_descriptor_t; 

struct grub_efi_usb_io {
  void (__grub_efi_api *control_transfer)(void);
  void (__grub_efi_api *bulk_transfer)(void);
  void (__grub_efi_api *async_interrupt_transfer)(void);
  void (__grub_efi_api *sync_interrupt_transfer)(void);
  void (__grub_efi_api *isochronous_transfer)(void);
  void (__grub_efi_api *async_isochronous_transfer)(void);
  grub_efi_status_t
  (__grub_efi_api *get_device_descriptor) (
      struct grub_efi_usb_io *this,
      grub_efi_usb_device_descriptor_t *device_descriptor);
  void (__grub_efi_api *get_config_descriptor)(void);
  void (__grub_efi_api *get_interface_descriptor)(void);
  void (__grub_efi_api *get_endpoint_descriptor)(void);
  void (__grub_efi_api *get_string_descriptor)(void);
  void (__grub_efi_api *get_supported_languages)(void);
  void (__grub_efi_api *port_reset)(void);
};

typedef struct grub_efi_usb_io grub_efi_usb_io_t;

static grub_guid_t usb_io_guid = GRUB_EFI_USB_IO_GUID;

static grub_err_t
grub_cmd_efiusb_test (grub_command_t cmd __attribute__ ((unused)),
		  int argc __attribute__ ((unused)),
		  char **args __attribute__ ((unused)))
{
  grub_efi_uintn_t num_handles;
  grub_efi_handle_t *handles;
  unsigned i;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &usb_io_guid,
				    0, &num_handles);
  if (!handles)
    return GRUB_ERR_NONE;

  for (i = 0; i < num_handles; i++)
    {
      grub_efi_handle_t handle = handles[i];
      grub_efi_device_path_t *dp;
      grub_efi_usb_io_t *usbio;
      grub_efi_usb_device_descriptor_t desc;
      grub_efi_status_t status;

      dp = grub_efi_get_device_path (handle);
      if (dp)
	grub_efi_print_device_path (dp);

      usbio = grub_efi_open_protocol (handle, &usb_io_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
      if (!usbio)
	continue;

      status = usbio->get_device_descriptor (usbio, &desc);
      if (status == GRUB_EFI_SUCCESS)
	grub_printf ("%04x %04x\n", desc.id_vendor, desc.id_product);
    }

  return GRUB_ERR_NONE;
}

static grub_command_t cmd;

GRUB_MOD_INIT(utoken_efiusb)
{
  cmd = grub_register_command ("efiusb", grub_cmd_efiusb_test,
			       0, N_("Test EFI USB support."));
}

GRUB_MOD_FINI(utoken_efiusb)
{
  grub_unregister_command (cmd);
}
