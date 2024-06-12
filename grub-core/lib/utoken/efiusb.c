#include "grub/usb.h"
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

struct grub_efi_usb_config_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_uint16_t   total_length;
  grub_efi_uint8_t    num_interfaces;
  grub_efi_uint8_t    configuration_value;
  grub_efi_uint8_t    configuration;
  grub_efi_uint8_t    attributes;
  grub_efi_uint8_t    max_power;
} GRUB_PACKED;

typedef struct grub_efi_usb_config_descriptor grub_efi_usb_config_descriptor_t; 

struct grub_efi_usb_interface_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_uint8_t    interface_number;
  grub_efi_uint8_t    alternate_setting;
  grub_efi_uint8_t    num_endpoints;
  grub_efi_uint8_t    interface_class;
  grub_efi_uint8_t    interface_subclass;
  grub_efi_uint8_t    interface_protocol;
  grub_efi_uint8_t    interface;
} GRUB_PACKED;

typedef struct grub_efi_usb_interface_descriptor grub_efi_usb_interface_descriptor_t; 

struct grub_efi_usb_endpoint_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_uint8_t    endpoint_address;
  grub_efi_uint8_t    attributes;
  grub_efi_uint16_t   max_packet_size;
  grub_efi_uint8_t    interval;
} GRUB_PACKED;

typedef struct grub_efi_usb_endpoint_descriptor grub_efi_usb_endpoint_descriptor_t; 

struct grub_efi_usb_string_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_char16_t   string[1];
} GRUB_PACKED;

typedef struct grub_efi_usb_string_descriptor grub_efi_usb_string_descriptor_t; 

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
  grub_efi_status_t
  (__grub_efi_api *get_config_descriptor) (
      struct grub_efi_usb_io *this,
      grub_efi_usb_config_descriptor_t *configuration_descriptor);
  grub_efi_status_t
  (__grub_efi_api *get_interface_descriptor) (
      struct grub_efi_usb_io *this,
      grub_efi_usb_interface_descriptor_t *interface_descriptor);
  grub_efi_status_t
  (__grub_efi_api *get_endpoint_descriptor) (
      struct grub_efi_usb_io *this,
      grub_efi_uint8_t endpoint_index,
      grub_efi_usb_endpoint_descriptor_t *endpoint_descriptor);
  grub_efi_status_t
  (__grub_efi_api *get_string_descriptor) (
      struct grub_efi_usb_io *this,
      grub_efi_uint16_t lang_id,
      grub_efi_uint8_t string_id,
      grub_efi_char16_t **string);
  void (__grub_efi_api *get_supported_languages)(void);
  grub_efi_status_t
  (__grub_efi_api *port_reset) (struct grub_efi_usb_io *this);
};

typedef enum {
  //
  // USB request type
  //
  USB_REQ_TYPE_STANDARD = (0x00 << 5),
  USB_REQ_TYPE_CLASS    = (0x01 << 5),
  USB_REQ_TYPE_VENDOR   = (0x02 << 5),

  //
  // Standard control transfer request type, or the value
  // to fill in EFI_USB_DEVICE_REQUEST.Request
  //
  USB_REQ_GET_STATUS     = 0x00,
  USB_REQ_CLEAR_FEATURE  = 0x01,
  USB_REQ_SET_FEATURE    = 0x03,
  USB_REQ_SET_ADDRESS    = 0x05,
  USB_REQ_GET_DESCRIPTOR = 0x06,
  USB_REQ_SET_DESCRIPTOR = 0x07,
  USB_REQ_GET_CONFIG     = 0x08,
  USB_REQ_SET_CONFIG     = 0x09,
  USB_REQ_GET_INTERFACE  = 0x0A,
  USB_REQ_SET_INTERFACE  = 0x0B,
  USB_REQ_SYNCH_FRAME    = 0x0C,

  //
  // Usb control transfer target
  //
  USB_TARGET_DEVICE    = 0,
  USB_TARGET_INTERFACE = 0x01,
  USB_TARGET_ENDPOINT  = 0x02,
  USB_TARGET_OTHER     = 0x03,

  //
  // USB Descriptor types
  //
  USB_DESC_TYPE_DEVICE    = 0x01,
  USB_DESC_TYPE_CONFIG    = 0x02,
  USB_DESC_TYPE_STRING    = 0x03,
  USB_DESC_TYPE_INTERFACE = 0x04,
  USB_DESC_TYPE_ENDPOINT  = 0x05,
  USB_DESC_TYPE_HID       = 0x21,
  USB_DESC_TYPE_REPORT    = 0x22,

  //
  // Features to be cleared by CLEAR_FEATURE requests
  //
  USB_FEATURE_ENDPOINT_HALT = 0,

  //
  // USB endpoint types: 00: control, 01: isochronous, 10: bulk, 11: interrupt
  //
  USB_ENDPOINT_CONTROL   = 0x00,
  USB_ENDPOINT_ISO       = 0x01,
  USB_ENDPOINT_BULK      = 0x02,
  USB_ENDPOINT_INTERRUPT = 0x03,

  USB_ENDPOINT_TYPE_MASK = 0x03,
  USB_ENDPOINT_DIR_IN    = 0x80,

  //
  // Use 200 ms to increase the error handling response time
  //
  EFI_USB_INTERRUPT_DELAY = 2000000
} USB_TYPES_DEFINITION;

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
      grub_efi_usb_interface_descriptor_t interface_desc;
      grub_efi_status_t status;
      int j;

      dp = grub_efi_get_device_path (handle);
      if (dp)
	grub_efi_print_device_path (dp);

      usbio = grub_efi_open_protocol (handle, &usb_io_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
      if (!usbio)
	continue;

      status = usbio->get_device_descriptor (usbio, &desc);
      if (status == GRUB_EFI_SUCCESS)
	grub_printf ("id (vendor product) %04x %04x\n", desc.id_vendor, desc.id_product);
      status = usbio->get_interface_descriptor (usbio, &interface_desc);
      if (status == GRUB_EFI_SUCCESS)
	grub_printf ("interface (class subclass) %04x %04x\n", interface_desc.interface_class, interface_desc.interface_subclass);
      else
        grub_printf ("no interface");

      if (interface_desc.interface_class != GRUB_USB_CLASS_SMART_CARD)
	continue;

      grub_printf ("ccid interface:\n");

      for (j = 0; j < interface_desc.num_endpoints; j++)
	{
	  struct grub_usb_desc_endp endp;
	  status = usbio->get_endpoint_descriptor (usbio, j, (grub_efi_usb_endpoint_descriptor_t *) &endp);

	  if (status != GRUB_EFI_SUCCESS)
	    continue;

	  if (endp.endp_addr & 128)
	    {
	      if (grub_usb_get_ep_type (&endp) == GRUB_USB_EP_BULK)
		grub_printf ("  Bulk IN 0x%02x\n", endp.endp_addr);
	      else if (grub_usb_get_ep_type (&endp) == GRUB_USB_EP_INTERRUPT)
		grub_printf ("  Interrupt IN 0x%02x\n", endp.endp_addr);
	    }
	  else if (grub_usb_get_ep_type (&endp) == GRUB_USB_EP_BULK)
	    grub_printf ("  Bulk OUT 0x%02x\n", endp.endp_addr);
	}
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
