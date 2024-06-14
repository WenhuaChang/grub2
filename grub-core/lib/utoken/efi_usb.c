#include "grub/usb.h"
#include "grub/usbtrans.h"
#include <stdbool.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include "uusb.h"
#include "uusb_impl.h"
#include "util.h"
#include "scard.h"
#include "bufparser.h"

#define GRUB_EFI_USB_IO_GUID \
  { 0x2B2F68D6, 0x0CD2, 0x44cf, \
    {0x8E, 0x8B, 0xBB, 0xA2, 0x0B, 0x1B, 0x5B, 0x75 } \
  }

typedef enum {
  grub_efi_usb_data_in,
  grub_efi_usb_data_out,
  grub_efi_usb_no_data
} grub_efi_usb_data_direction_t;

/* USB Transfer Results */
#define GRUB_EFI_USB_NOERROR         0x00
#define GRUB_EFI_USB_ERR_NOTEXECUTE  0x01
#define GRUB_EFI_USB_ERR_STALL       0x02
#define GRUB_EFI_USB_ERR_BUFFER      0x04
#define GRUB_EFI_USB_ERR_BABBLE      0x08
#define GRUB_EFI_USB_ERR_NAK         0x10
#define GRUB_EFI_USB_ERR_CRC         0x20
#define GRUB_EFI_USB_ERR_TIMEOUT     0x40
#define GRUB_EFI_USB_ERR_BITSTUFF    0x80
#define GRUB_EFI_USB_ERR_SYSTEM      0x100

struct grub_efi_usb_device_request {
  grub_efi_uint8_t     request_type;
  grub_efi_uint8_t     request;
  grub_efi_uint16_t    value;
  grub_efi_uint16_t    index;
  grub_efi_uint16_t    length;
} GRUB_PACKED;

typedef struct grub_efi_usb_device_request grub_efi_usb_device_request_t;

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

struct grub_efi_usb_ccid_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_uint16_t   bcdccid;
  grub_efi_uint8_t    max_slot_index;
  grub_efi_uint8_t    voltage_support;
  grub_efi_uint32_t   protocols;
  grub_efi_uint32_t   default_clock;
  grub_efi_uint32_t   maximum_clock;
  grub_efi_uint8_t    num_clock_rates_supported;
  grub_efi_uint32_t   data_rate;
  grub_efi_uint32_t   max_data_rate;
  grub_efi_uint8_t    num_data_rates_supported;
  grub_efi_uint32_t   max_ifsd;
  grub_efi_uint32_t   synch_protocols;
  grub_efi_uint32_t   mechanical;
  grub_efi_uint32_t   features;
  grub_efi_uint32_t   max_ccid_message_length;
  grub_efi_uint8_t    class_get_response;
  grub_efi_uint8_t    class_envelope;
  grub_efi_uint16_t   lcd_layout;
  grub_efi_uint8_t    pin_support;
  grub_efi_uint8_t    max_ccid_busy_slots;
} GRUB_PACKED;

typedef struct grub_efi_usb_ccid_descriptor grub_efi_usb_ccid_descriptor_t; 

struct grub_efi_usb_string_descriptor {
  grub_efi_uint8_t    length;
  grub_efi_uint8_t    descriptor_type;
  grub_efi_char16_t   string[1];
} GRUB_PACKED;

typedef struct grub_efi_usb_string_descriptor grub_efi_usb_string_descriptor_t; 

struct grub_efi_usb_io {
  grub_efi_status_t (__grub_efi_api *control_transfer) (
      struct grub_efi_usb_io *this,
      grub_efi_usb_device_request_t *request,
      grub_efi_usb_data_direction_t direction,
      grub_efi_uint32_t timeout,
      void *data,
      grub_efi_uintn_t data_length,
      grub_efi_uint32_t *status);

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

struct grub_usb_desc_head {
  grub_efi_uint8_t len;
  grub_efi_uint8_t type;
} GRUB_PACKED;

typedef struct grub_usb_desc_head grub_usb_desc_head_t;

bool
usb_parse_type(const char *string, uusb_type_t *type)
{
  char *copy, *s;
  const char *end;

  type->idVendor = 0;
  type->idProduct = 0;

  if (!(copy = strdup(string)))
    return false;

  s = strchr(copy, ':');
  if (s)
    *s++ = '\0';

  type->idVendor = strtoul(copy, &end, 16);
  if (*end)
    goto bad;

  if (s)
    {
      type->idProduct = strtoul(s, &end, 16);
      if (*end)
	goto bad;
    }

  free(copy);
  return true;

 bad:
  error("Cannot parse USB vendor:product string \"%s\"\n", string);
  return false;
}

static void
process_device_descriptor (
    grub_efi_usb_device_descriptor_t *desc,
    uusb_device_descriptor_t *dd)
{
  dd->bDevice.class = desc->device_class;
  dd->bDevice.subclass = desc->device_sub_class;
  dd->bDevice.protocol = desc->device_protocol;
  dd->bMaxPacketSize0 = desc->max_packet_size;
  dd->idVendor = desc->id_vendor;
  dd->idProduct = desc->id_product;
  dd->bNumConfigurations = desc->num_configurations;
  grub_printf ("In process_device_descriptor\n");
}


struct grub_efi_usb_ccid_dev {
  grub_efi_usb_io_t *usbio;
  grub_efi_handle_t handle;
};

typedef struct grub_efi_usb_ccid_dev grub_efi_usb_ccid_dev_t;

uusb_dev_t *
usb_open_type(const uusb_type_t *type)
{
  grub_efi_uintn_t num_handles;
  grub_efi_handle_t *handles;
  unsigned i;
  grub_efi_usb_device_descriptor_t desc;
  grub_efi_usb_interface_descriptor_t interface_desc;
  grub_efi_usb_ccid_dev_t *dev;
  uusb_dev_t *ret = NULL;
  grub_efi_usb_io_t *usbio = NULL;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &usb_io_guid,
				    0, &num_handles);
  if (!handles)
    return NULL;

  for (i = 0; i < num_handles; i++)
    {
      grub_efi_status_t status;
      grub_efi_handle_t handle = handles[i];

      usbio = grub_efi_open_protocol (handle, &usb_io_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);
      if (!usbio)
	continue;

      status = usbio->get_interface_descriptor (usbio, &interface_desc);
      if (status != GRUB_EFI_SUCCESS)
	continue;

      if (interface_desc.interface_class != GRUB_USB_CLASS_SMART_CARD)
	continue;

      status = usbio->get_device_descriptor (usbio, &desc);
      if (status != GRUB_EFI_SUCCESS)
	continue;

      if (type->idProduct && desc.id_product != type->idProduct)
	continue;

      if (type->idVendor && desc.id_vendor != type->idVendor)
	continue;

      ret = grub_malloc (sizeof (*ret));
      break;
    }

  if (ret)
    {
      dev = grub_malloc (sizeof(*dev));
      if (!dev)
	{
	  grub_free (ret);
	  return NULL;
	}
      ret->type.idProduct = desc.id_product;
      ret->type.idVendor = desc.id_vendor;
      process_device_descriptor (&desc, &ret->descriptor);
      dev->usbio = usbio;
      dev->handle = handles[i];
      ret->dev = dev;
    }

  return ret;
}

