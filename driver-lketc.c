/*
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Lketc Integrated Systems Limited
 * Copyright 2014 Dominik Lehner
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef WIN32
  #include <sys/select.h>
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include "compat.h"
  #include <windows.h>
  #include <io.h>
#endif

#include "miner.h"
#include "usbutils.h"
#include "fpgautils.h"
#include "elist.h"
#include "util.h"
#include "driver-lketc.h"

#define using_libusb(info) ((info)->using_libusb > 0)
#define using_serial(info) ((info)->using_libusb == 0)

// Configuration options
extern bool opt_lketc_debug;
extern int opt_lketc_chips_count;		// number of Lketc chips chained together
extern int opt_lketc_chip_clk;			// frequency to run chips with
extern bool opt_lketc_nocheck_golden;		// bypass hashrate check

//static int opt_lketc_chips_count_max = 1;	// smallest power of 2 >= opt_lketc_chips_count
						// is currently auto-calculated

// Index for device-specific options
//static int option_offset = -1;

// Unset upon first hotplug check
static bool initial_startup_phase = true;

static struct name_chip_map {
	char	*model_name;
	int	chips_count;
} lketc_models[] = {
	{ "Stick",		1  },
	{ "Board",		2  },
	{ NULL, 0 }
};

/************************************************************
 * Utility Functions
 ************************************************************/

static void flush_uart(int fd)
{
#ifdef WIN32
	const HANDLE fh = (HANDLE)_get_osfhandle(fd);
	PurgeComm(fh, PURGE_RXCLEAR);
#else
	tcflush(fd, TCIFLUSH);
#endif
}

static int __maybe_unused flush_fd(int fd)
{
	static char discard[10];
	return read(fd, discard, sizeof(discard));
}

static void rev(unsigned char *s, size_t l)
{
	size_t i, j;
	unsigned char t;

	for (i = 0, j = l - 1; i < j; i++, j--) {
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
}

static int log_2(int value)
{
	int x = 0;
	while (value > 1) {
		value >>= 1;
		x++;
	}
	return x;
}

static uint32_t __maybe_unused chip_index(uint32_t value, int bit_num)
{
	uint32_t newvalue = 0;
	int i;

	// isolate bits 19-28, then shift right to get the
	// highest bits that distinguish multiple chips
	value = (value & 0x1ff80000) >> (29 - bit_num);

	for (i = 0; i < bit_num; i++) {
		newvalue = newvalue << 1;
		newvalue += value & 0x01;
		value = value >> 1;
	}

	return newvalue;
}

static int lowest_pow2(int min)
{
	int i;
	for (i = 1; i < 1024; i = i * 2) {
		if (min <= i){
			return i;
		}
	}
	return 1024;
}

static void notify_send_work_thread(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	cgsem_post(&info->wusem);
}

/************************************************************
 * I/O helper functions
 ************************************************************/

#define lketc_serial_open_detect(devpath, baud, purge) serial_open_ex(devpath, baud, LKETC_READ_FAULT_DECISECONDS, 0, purge, true)
#define lketc_serial_open(devpath, baud, purge) serial_open_ex(devpath, baud, LKETC_READ_FAULT_DECISECONDS, 0, purge, true)
#define lketc_serial_close(fd) close(fd)

static bool lketc_reopen(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	int try, fd = -1;

	if (!using_serial(info))  // sanity check
		return false;

	if (info->device_fd != -1) {
		applog(LOG_DEBUG, "Closing %s%d on %s (fd=%d)",
			lketc->drv->name, lketc->device_id, lketc->device_path, info->device_fd);
		lketc_serial_close(info->device_fd);
		info->device_fd = -1;
		cgsleep_ms(2000);
	}

	applog(LOG_DEBUG, "Attempting to open %s%d on %s",
		lketc->drv->name, lketc->device_id, lketc->device_path);

	for (try = 0; try < 3; ++try) {
		fd = lketc_serial_open(lketc->device_path, info->baud, true);
		if (likely(fd > -1))
			break;
		cgsleep_ms(3000);
	}

	if (unlikely(fd < 0)) {
		applog(LOG_ERR, "Failed to open %s%d on %s (%d attempts)",
			lketc->drv->name, lketc->device_id, lketc->device_path, try);
		return false;
	}

	info->device_fd = fd;

	applog(LOG_DEBUG, "Successfully opened %s%d on %s (%d attempts, fd=%d)",
		lketc->drv->name, lketc->device_id, lketc->device_path, try, info->device_fd);

	return true;
}

static int lketc_serial_write(int fd, const void *buf, size_t len)
{
	ssize_t ret;
	size_t total = 0;

#if LKETC_PROTOCOL_DEBUG
	if (opt_lketc_debug) {
		char *hexstr;
		hexstr = bin2hex(buf, len);
		applog(LOG_DEBUG, "> %s", hexstr);
		free(hexstr);
	}
#endif

	while (total < len) {
#ifndef WIN32
		ret = write(fd, buf, len);
#else
		ret = win32write(fd, buf, len);
#endif
		if (ret < 0) {
			applog(LOG_ERR, "lketc_serial_write (%d): error on write: %s", fd, strerror(errno));
			return -1;
		}
		total += (size_t)ret;
	}

	return total;
}

static int lketc_serial_read(int fd, void *buf, size_t len, int read_count, struct timeval *tv_firstbyte)
{
	ssize_t ret;
	size_t total = 0;
	int rc = 0;

	while (total < len) {
#ifndef WIN32
		ret = read(fd, buf + total, len - total);
#else
		ret = win32read(fd, buf + total, len - total);
#endif
		if (ret < 0) {
			applog(LOG_ERR, "lketc_serial_read (%d): error on read: %s", fd, strerror(errno));
			return -1;
		}

		if (tv_firstbyte != NULL && total == 0)
			cgtime(tv_firstbyte);

		applog(LOG_DEBUG, "lketc_serial_read: read returned %d", (int)ret);

		if (ret == 0 && ++rc >= read_count)
			break;

		total += (size_t)ret;
	}

#if LKETC_PROTOCOL_DEBUG
	if (opt_lketc_debug) {
		char *hexstr;
		if (total > 0) {
			hexstr = bin2hex(buf, total);
			applog(LOG_DEBUG, "< %s", hexstr);
			free(hexstr);
		} else {
			applog(LOG_DEBUG, "< (no data)");
		}
	}
#endif

	return total;
}

/************************************************************
 * Detection and setup
 ************************************************************/

static unsigned char lketc_clk_to_freqcode(int clkfreq)
{
	if (clkfreq > LKETC_CLK_MAX) {
		applog(LOG_WARNING, "Clock frequency %d too high, resetting to %d",
								clkfreq, LKETC_CLK_MAX);
		clkfreq = LKETC_CLK_MAX;
	}

	if (clkfreq < LKETC_CLK_MIN) {
		applog(LOG_WARNING, "Clock frequency %d too low, resetting to %d",
								clkfreq, LKETC_CLK_MIN);
		clkfreq = LKETC_CLK_MIN;
	}

	return (unsigned char)((double)clkfreq * 2. / 3.);
}

static void lketc_get_device_options(const char *devid, int *chips_count, int *chip_clk, const char *options)
{
	char *p, *all, *found = NULL;
	long lval;
	int index = 0;
	char *lastslsh = MAX(strrchr(devid, '/'), strrchr(devid, '\\'));
	if (lastslsh != NULL)
		++lastslsh;

	// set global default options
	*chips_count = (opt_lketc_chips_count) ? opt_lketc_chips_count : LKETC_MIN_CHIPS;
	*chip_clk = (opt_lketc_chip_clk) ? opt_lketc_chip_clk : LKETC_CLK_MIN;

	if (options == NULL)
		return;

	all = strdup(options);

	for (p = strtok(all, ";"); p != NULL; p = strtok(NULL, ";")) {
		if (strncmp(p, devid, strlen(devid)) == 0) {
			found = p;
			break;
		}
		if (lastslsh != NULL && strncmp(p, lastslsh, strlen(lastslsh)) == 0) {
			found = p;
			break;
		}
	}

	if (found == NULL) {
		free(all);
		return;
	}

	for (p = strtok(found, ","); p != NULL; p = strtok(NULL, ",")) {
		lval = strtol(p, NULL, 10);

		switch (index++) {
			case 1:			// chip count
				if (lval < LKETC_MIN_CHIPS || lval > LKETC_MAX_CHIPS) {
					applog(LOG_ERR, "Invalid chip count %ld for Lketc device %s",
					       lval, devid);
					break;
				}
				*chips_count = (int)lval;
				break;
			case 2:			// clock
				if (lval < LKETC_CLK_MIN || lval > LKETC_CLK_MAX) {
					applog(LOG_ERR, "Invalid clock speed %ld for Lketc device %s",
					       lval, devid);
					break;
				}
				*chip_clk = (int)lval;
				break;
			default:
				break;
		}
	}

	free(all);
	return;
}

static char *lketc_device_name(int chips_count)
{
	struct name_chip_map *p;

	for (p = lketc_models; p->model_name != NULL; ++p) {
		if (p->chips_count == chips_count)
			return p->model_name;
	}

	return NULL;
}

static int lketc_usb_control_transfer_data(struct cgpu_info *lketc, uint8_t request_type, uint8_t bRequest,
		uint16_t wValue, uint16_t wIndex, uint32_t *data, int siz, enum usb_cmds cmd)
{
	int err = usb_transfer_data(lketc, request_type, bRequest, wValue, wIndex, data, siz, cmd);
	if (err)
		applog(LOG_DEBUG, "%s%d: error %d on USB control transfer %s",
			lketc->drv->name, lketc->cgminer_id, err, usb_cmdname(cmd));
	return err;
}

static inline int lketc_usb_control_transfer(struct cgpu_info *lketc, uint8_t request_type, uint8_t bRequest,
		uint16_t wValue, uint16_t wIndex, enum usb_cmds cmd)
{
	return lketc_usb_control_transfer_data(lketc, request_type, bRequest, wValue, wIndex, NULL, 0, cmd);
}

static bool lketc_initialize_cp2102(struct cgpu_info *lketc)
{
	int interface = usb_interface(lketc);
	//uint32_t baudrate = CP210X_DATA_BAUD;

	// Enable the UART
	if (lketc_usb_control_transfer(lketc, CP210X_TYPE_OUT, CP210X_REQUEST_IFC_ENABLE,
			CP210X_VALUE_UART_ENABLE, interface, C_ENABLE_UART))
		return false;

	// Set data control
	if (lketc_usb_control_transfer(lketc, CP210X_TYPE_OUT, CP210X_REQUEST_DATA,
			CP210X_VALUE_DATA, interface, C_SETDATA))
		return false;

	// Lketcminers have baud hardcoded to 115200, and reject baud commands, even to same value
	// Set the baud
	//if (lketc_usb_control_transfer_data(lketc, CP210X_TYPE_OUT, CP210X_REQUEST_BAUD,
	//		0, interface, &baudrate, sizeof(baudrate), C_SETBAUD))
	//	return false;

	return true;
}

static bool lketc_initialize_usb(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	enum sub_ident ident;

	if (lketc->usbinfo.nodev)
		return false;

	ident = usb_ident(lketc);

	switch (ident) {
	case IDENT_LKE:
		info->read_data_offset = 0;
		return lketc_initialize_cp2102(lketc);
	default:
		applog(LOG_ERR, "lketc_initialize_usb called on wrong device, ident=%d", ident);
		return false;
	}
}

static struct cgpu_info *lketc_detect_one_usb(struct libusb_device *dev, struct usb_find_devices *found)
{
	struct cgpu_info *lketc;
	struct LKETC_INFO *info;

	lketc = usb_alloc_cgpu(&lketc_drv, 1);
	if (!usb_init(lketc, dev, found))
		goto usbdealloc;
	info = calloc(1, sizeof(struct LKETC_INFO));
	if (unlikely(!info))
		goto usbdealloc;

	lketc->device_data = info;
	lketc->deven = DEV_ENABLED;
	lketc->threads = 1;

	info->device_fd = -1;
	info->using_libusb = 1;
	if (lketc->usbdev->serial_string && strlen(lketc->usbdev->serial_string) > 4)
		lketc->unique_id = lketc->usbdev->serial_string;
	else
		lketc->unique_id = lketc->device_path;
	strncpy(info->device_name, lketc->unique_id, sizeof(info->device_name) - 1);
	info->device_name[sizeof(info->device_name) - 1] = '\0';

	lketc_get_device_options(lketc->unique_id, &info->chips_count, &info->chip_clk, opt_lketc_options);
	lketc->name = lketc_device_name(info->chips_count);
	info->freqcode = lketc_clk_to_freqcode(info->chip_clk);
	info->baud = LKETC_IO_SPEED;
	info->cores_per_chip = LKETC_CHIP_CORES;
	info->chips_count_max = lowest_pow2(info->chips_count);
	info->chips_bit_num = log_2(info->chips_count_max);
	info->next_chip_clk = -1;

	libusb_reset_device(lketc->usbdev->handle);
	update_usb_stats(lketc);

	lketc->usbdev->usb_type = USB_TYPE_STD;
	if (!lketc_initialize_usb(lketc)) {
		applog(LOG_ERR, "Failed to initialize Lketc USB-UART interface");
		goto alldealloc;
	}

	info->golden_speed_per_core = (((info->chip_clk * 2.) / 3.) * 1024.) / 8.;
	info->work_timeout.tv_sec = 4294967296LL / (info->golden_speed_per_core * info->cores_per_chip * info->chips_count_max) * 0.9;
	info->work_timeout.tv_usec = 0;
	info->read_count = (uint32_t)((4294967296LL*10)/(info->cores_per_chip*info->chips_count_max*info->golden_speed_per_core*2));
	info->read_count = info->read_count*3/4;

	if (!add_cgpu(lketc))
		goto alldealloc;

	return lketc;

alldealloc:
	usb_uninit(lketc);
	free(lketc->device_data);
	lketc->device_data = NULL;

usbdealloc:
	lketc = usb_free_cgpu(lketc);
	return NULL;
}

static bool lketc_detect_one_serial(const char *devpath)
{
	struct timeval tv_start, tv_finish;
	int i, fd, baud, cores_per_chip, chips_count_max, chips_count, chip_clk;
	//int this_option_offset = ++option_offset;
	unsigned char freqcode_init, freqcode;
	uint32_t nonce;
	uint64_t golden_speed_per_core;

	/* this check here is needed as a failsafe because the serial_detect
	 * functions do not keep track of devices already opened */
	for (i = 0; i < total_devices; ++i) {
		if (devices[i]->device_path && !strcasecmp(devices[i]->device_path, devpath))
			return false;
	}

	uint32_t golden_nonce_val = be32toh(0x268d0300); // 0xd26 = 3366
	unsigned char ob_bin[LKETC_COMMAND_PKT_LEN], nonce_bin[LKETC_EVENT_PKT_LEN];

	static const char golden_ob[] =
			"55aa0001"
			"00038000063b0b1b028f32535e900609c15dc49a42b1d8492a6dd4f8f15295c989a1decf584a6aa93be26066d3185f55ef635b5865a7a79b7fa74121a6bb819da416328a9bd2f8cef72794bf02000000";

	static const char golden_ob2[] =
			"55aa00ff"
			"c00278894532091be6f16a5381ad33619dacb9e6a4a6e79956aac97b51112bfb93dc450b8fc765181a344b6244d42d78625f5c39463bbfdc10405ff711dc1222dd065b015ac9c2c66e28da7202000000";

	lketc_get_device_options(devpath, &chips_count, &chip_clk, opt_lketc_options);
	baud = LKETC_IO_SPEED;				// baud rate is fixed
	cores_per_chip = LKETC_CHIP_CORES;		// cores/chip also fixed
	chips_count_max = lowest_pow2(chips_count);
	//if (chips_count > opt_lketc_chips_count_max)
	//	opt_lketc_chips_count_max = lowest_pow2(chips_count);
	//chips_count_max = opt_lketc_chips_count_max;

	if (initial_startup_phase)
		applog(LOG_INFO, "Lketc Detect: Attempting to open %s", devpath);

	fd = lketc_serial_open_detect(devpath, baud, true);
	if (unlikely(fd == -1)) {
		if (initial_startup_phase)
			applog(LOG_ERR, "Lketc Detect: Failed to open %s", devpath);
		return false;
	}

	freqcode = lketc_clk_to_freqcode(chip_clk);

	// from 150M step to the high or low speed. we need to add delay and resend to init chip
	if (chip_clk > 150)
		freqcode_init = lketc_clk_to_freqcode(165);
	else
		freqcode_init = lketc_clk_to_freqcode(139);

	flush_uart(fd);

	hex2bin(ob_bin, golden_ob2, sizeof(ob_bin));
	ob_bin[0] = freqcode_init;
	ob_bin[1] = ~freqcode_init;
	ob_bin[2] = 0x00;
	ob_bin[3] = 0x01;
	for (i = 0; i < 2; ++i) {
		lketc_serial_write(fd, ob_bin, sizeof(ob_bin));
		cgsleep_ms(500);	// what is the minimum the miners need/will accept?
		flush_uart(fd);
	}

	hex2bin(ob_bin, golden_ob2, sizeof(ob_bin));
	ob_bin[0] = freqcode;
	ob_bin[1] = ~freqcode;
	ob_bin[2] = 0x00;
	ob_bin[3] = 0x01;
	for (i = 0; i < 2; ++i) {
		lketc_serial_write(fd, ob_bin, sizeof(ob_bin));
		cgsleep_ms(500);
		flush_uart(fd);
	}

	if (!opt_lketc_nocheck_golden) {
		memset(nonce_bin, 0, sizeof(nonce_bin));

		hex2bin(ob_bin, golden_ob, sizeof(ob_bin));
		ob_bin[0] = freqcode;
		ob_bin[1] = ~freqcode;
		ob_bin[2] = 0x00;
		ob_bin[3] = 0x01;

		for (i = 0; i < 2; ++i) {
			lketc_serial_write(fd, ob_bin, sizeof(ob_bin));
			cgtime(&tv_start);
			if (lketc_serial_read(fd, nonce_bin, sizeof(nonce_bin), 25, &tv_finish) == sizeof(nonce_bin))
				break;
		}

		lketc_serial_close(fd);

		memcpy(&nonce, nonce_bin, sizeof(nonce_bin));
		nonce = be32toh(nonce);

		if (nonce != golden_nonce_val) {
			applog(LOG_ERR, "Lketc Detect: "
					"Test failed at %s: got %08x, should be: %08x",
					devpath, nonce, golden_nonce_val);
			return false;
		}

		golden_speed_per_core = (uint64_t)((double)0xd26 / tdiff(&tv_finish, &tv_start));

		if (opt_lketc_debug)
			applog(LOG_INFO, "Test succeeded at %s: got %08x",
					devpath, nonce);
	} else {
		lketc_serial_close(fd);
		golden_speed_per_core = (((chip_clk * 2.) / 3.) * 1024.) / 8.;
	}

	/* We have a real Lketc miner! */
	struct cgpu_info *lketc;
	struct LKETC_INFO *info;

	lketc = calloc(1, sizeof(struct cgpu_info));
	if (unlikely(!lketc))
		quit(1, "Failed to malloc struct cgpu_info");
	info = calloc(1, sizeof(struct LKETC_INFO));
	if (unlikely(!info))
		quit(1, "Failed to malloc struct LKETC_INFO");

	lketc->drv = &lketc_drv;
	lketc->name = lketc_device_name(chips_count);
	lketc->device_path = strdup(devpath);
	lketc->device_data = info;
	lketc->deven = DEV_ENABLED;
	lketc->threads = 1;

	applog(LOG_NOTICE, "Found Lketc at %s, mark as %d",
			devpath, lketc->device_id);

	applog(LOG_INFO, "Lketc: Init: %d baud=%d cores_per_chip=%d chips_count=%d",
			lketc->device_id, baud, cores_per_chip, chips_count);

	info->device_fd = -1;
	info->using_libusb = 0;

	lketc->unique_id = MAX(	strrchr(lketc->device_path, '/'),
				strrchr(lketc->device_path, '\\'));
	if (lketc->unique_id == NULL)
		lketc->unique_id = lketc->device_path;
	else
		++lketc->unique_id;
	strncpy(info->device_name, lketc->unique_id, sizeof(info->device_name) - 1);
	info->device_name[sizeof(info->device_name) - 1] = '\0';

	info->work_timeout.tv_sec = 4294967296LL / (golden_speed_per_core * cores_per_chip * chips_count_max) * 0.9;
	info->work_timeout.tv_usec = 0;
	info->golden_speed_per_core = golden_speed_per_core;
	info->read_count = (uint32_t)((4294967296LL*10)/(cores_per_chip*chips_count_max*golden_speed_per_core*2));
	info->read_count = info->read_count*3/4;
	info->next_chip_clk = -1;

	info->freqcode = freqcode;

	info->baud = baud;
	info->cores_per_chip = cores_per_chip;
	info->chips_count = chips_count;
	info->chips_count_max = chips_count_max;
	if ((chips_count_max & (chips_count_max - 1)) != 0)
		quit(1, "chips_count_max must be a power of 2");
	info->chip_clk = chip_clk;
	info->chips_bit_num = log_2(chips_count_max);
	info->read_data_offset = 0;

	if (!add_cgpu(lketc))
		quit(1, "Failed to add_cgpu");

	return true;
}

/************************************************************
 * Host <-> ASIC protocol implementation
 ************************************************************/

static void lketc_purge_work(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;

	mutex_lock(&info->lock);
	if (info->current_work != NULL) {
		free_work(info->current_work);
		info->current_work = NULL;
	}
	notify_send_work_thread(lketc);
	mutex_unlock(&info->lock);
}

#define nonce_range_start(cperc, cmax, core, chip) \
	(((0xffffffff / cperc + 1) * core) + ((0x1fffffff / cmax + 1) * chip))
static bool lketc_read_response(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	unsigned char evtpkt[LKETC_READ_BUFFER];
	uint32_t nonce, chip, core;
	int ret, err;
	double duration_s;
	bool valid;

	if (using_libusb(info)) {
		//err = usb_read_timeout(lketc, (char *)evtpkt, sizeof(evtpkt), &ret, 250, C_GETRESULTS);
		err = usb_read_once(lketc, (char *)evtpkt, sizeof(evtpkt), &ret, C_GETRESULTS);

#if LKETC_PROTOCOL_DEBUG
		if (opt_lketc_debug) {
			char *hexstr;
			hexstr = bin2hex(evtpkt, ret);
			applog(LOG_DEBUG, "< %s    err=%d ret=%d", hexstr, err, ret);
			free(hexstr);
		}
#endif

		if (err != LIBUSB_SUCCESS && err != LIBUSB_ERROR_TIMEOUT) {
			applog(LOG_ERR, "%s%d: USB read error: %s",
				lketc->drv->name, lketc->device_id, libusb_error_name(err));
			return false;
		}

		if (ret < LKETC_EVENT_PKT_LEN + info->read_data_offset)
			return true;
	} else {
		ret = lketc_serial_read(info->device_fd, evtpkt, LKETC_EVENT_PKT_LEN, 1, NULL);
		if (ret < 0) {			// error
			info->serial_reopen = true;
			notify_send_work_thread(lketc);
			return false;
		} else if (ret == 0) {		// timeout
			return true;
		}
		flush_uart(info->device_fd);
	}

	cgtime(&info->workend);

	memcpy(&nonce, evtpkt + info->read_data_offset, LKETC_EVENT_PKT_LEN);
	nonce = be32toh(nonce);

	mutex_lock(&info->lock);

	if (info->current_work == NULL) {	// work was flushed before we read response
		applog(LOG_DEBUG, "%s%d: Received nonce for flushed work",
			lketc->drv->name, lketc->device_id);
		mutex_unlock(&info->lock);
		return true;
	}

	valid = submit_nonce(info->thr, info->current_work, nonce);

	++info->workdone;

	core = (nonce & 0xe0000000) >> 29;		// core indicated by 3 highest bits
	chip = (nonce & 0x1ff80000) >> (29 - info->chips_bit_num);
	duration_s = tdiff(&info->workend, &info->workstart);

	if (chip < LKETC_MAX_CHIPS && core < LKETC_CHIP_CORES) {
		++info->nonce_count[chip][core];
		if (!valid)
			++info->error_count[chip][core];

		if (valid && duration_s > 0) {
			info->hashes_per_s = (nonce - nonce_range_start(info->cores_per_chip, info->chips_count_max, core, chip)) / duration_s * info->cores_per_chip * info->chips_count;
			info->last_nonce = nonce;
		}
	} else {
		applog(LOG_INFO, "%s%d: Corrupt nonce message received, cannot determine chip and core",
			lketc->drv->name, lketc->device_id);
	}

	mutex_unlock(&info->lock);

	return true;
}

static bool lketc_check_need_work(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	struct thr_info *thr = info->thr;
	struct work *work;
	bool need_work;

	need_work = (info->current_work == NULL);

	if (need_work) {
		work = get_work(thr, thr->id);  // get_work can block, so done outside mutex_lock

		mutex_lock(&info->lock);
		if (info->current_work == NULL) {  // verify still NULL
			work->devflag = false;
			info->current_work = work;
		} else {
			need_work = false;
		}
		mutex_unlock(&info->lock);

		if (!need_work)
			discard_work(work);
	}

	return need_work;
}

static bool lketc_send_work(struct cgpu_info *lketc, struct work *work)
{
	struct LKETC_INFO *info = lketc->device_data;
	unsigned char cmdpkt[LKETC_COMMAND_PKT_LEN];
	uint32_t diff_code, diff;
	int ret;

	diff = work->work_difficulty;
	if (diff < 1)
		diff = 1;

	diff_code = 0xffff / diff;
	applog(LOG_DEBUG, "lketc_send_work: diff=%d diff_code=%04x", diff, diff_code);

	cmdpkt[0] = info->freqcode;
	cmdpkt[1] = ~(info->freqcode);
	cmdpkt[2] = (diff_code & 0xff00) >> 8;
	cmdpkt[3] = (diff_code & 0x00ff);

	memcpy(cmdpkt + 4, work->data, 80);
	rev(cmdpkt + 4, 80);

	if (using_libusb(info)) {	// in libusb mode we send via usb ;)
#if LKETC_PROTOCOL_DEBUG
		if (opt_lketc_debug) {
			char *hexstr;
			hexstr = bin2hex(cmdpkt, sizeof(cmdpkt));
			applog(LOG_DEBUG, "> %s", hexstr);
			free(hexstr);
		}
#endif
		if (usb_write(lketc, (char *)cmdpkt, sizeof(cmdpkt), &ret, C_SENDWORK) != LIBUSB_SUCCESS ||
			ret != sizeof(cmdpkt))
			return false;
	} else {			// otherwise direct via serial port
		ret = lketc_serial_write(info->device_fd, cmdpkt, sizeof(cmdpkt));
		if (ret < 0) {
			info->serial_reopen = true;
			notify_send_work_thread(lketc);
			return false;
		}
	}

	return true;
}

static void *lketc_send_work_thread(void *data)
{
	struct cgpu_info *lketc = (struct cgpu_info *)data;
	struct LKETC_INFO *info = lketc->device_data;
	char threadname[24];
	struct timeval tv_now, tv_spent, tv_rem;
	int retval;

	snprintf(threadname, sizeof(threadname), "Lketc/%d", lketc->device_id);
	RenameThread(threadname);
	applog(LOG_INFO, "%s%d: serial I/O thread running, %s",
						lketc->drv->name, lketc->device_id, threadname);

	while (likely(!lketc->shutdown)) {
		if (unlikely(info->thr->pause || lketc->deven != DEV_ENABLED)) {
			cgsem_wait(&info->wusem);
			lketc_purge_work(lketc);
			continue;
		}

		if (unlikely(using_libusb(info) && lketc->usbinfo.nodev))
			break;

		if (unlikely(info->serial_reopen)) {
			if (using_serial(info) && !lketc_reopen(lketc)) {
				applog(LOG_ERR, "Failed to reopen %s%d on %s, shutting down",
					lketc->drv->name, lketc->device_id, lketc->device_path);
				break;
			}
			info->serial_reopen = false;
			lketc_purge_work(lketc);
		}

		lketc_check_need_work(lketc);

		mutex_lock(&info->lock);
		if (info->current_work && !info->current_work->devflag) {
			/* send task to device */
			if (opt_lketc_debug)
				applog(LOG_INFO, "Sending work");

			if (lketc_send_work(lketc, info->current_work)) {
				info->current_work->devflag = true;
				cgtime(&info->workstart);
				if (info->next_chip_clk != -1) {
					info->chip_clk = info->next_chip_clk;
					info->next_chip_clk = -1;
				}
			} else {
				applog(LOG_NOTICE, "%s%d: I/O error while sending work, will retry",
					lketc->drv->name, lketc->device_id);
				mutex_unlock(&info->lock);
				continue;
			}
		}
		mutex_unlock(&info->lock);

		cgtime(&tv_now);
		timersub(&tv_now, &info->workstart, &tv_spent);
		timersub(&info->work_timeout, &tv_spent, &tv_rem);

		if (opt_lketc_debug) {
			applog(LOG_DEBUG, "Workstart: %d.%06d", (int)info->workstart.tv_sec, (int)info->workstart.tv_usec);
			applog(LOG_DEBUG, "Spent: %d.%06d", (int)tv_spent.tv_sec, (int)tv_spent.tv_usec);
			applog(LOG_DEBUG, "Remaining: %d.%06d", (int)tv_rem.tv_sec, (int)tv_rem.tv_usec);
		}

		retval = cgsem_mswait(&info->wusem, (tv_rem.tv_sec < 1) ? 5000 : tv_rem.tv_sec * 1000);
		if (retval == ETIMEDOUT)
			lketc_purge_work(lketc);		// abandon current work
	}

	lketc->shutdown = true;
	return NULL;
}

/************************************************************
 * CGMiner Interface functions
 ************************************************************/

static int lketc_autoscan()
{
	int found = 0;
	applog(LOG_DEBUG, "lketc_autoscan() called");
	found += serial_autodetect_udev(lketc_detect_one_serial, LKETC_USB_ID_MODEL_STR1);
	return found;
}

static void lketc_detect(bool __maybe_unused hotplug)
{
	static int serial_usb = 0;

	if (initial_startup_phase && hotplug)
		initial_startup_phase = false;

	if (serial_usb == 0)
		serial_usb = (list_empty(&scan_devices)) ? -1 : 1;

	if (serial_usb < 0)
		usb_detect(&lketc_drv, lketc_detect_one_usb);
	else
		serial_detect_iauto(&lketc_drv, lketc_detect_one_serial, lketc_autoscan);
}

static bool lketc_prepare(struct thr_info *thr)
{
	struct cgpu_info *lketc = thr->cgpu;
	struct LKETC_INFO *info = lketc->device_data;

	applog(LOG_NOTICE, "%s%d opened on %s",
			lketc->drv->name, lketc->device_id, lketc->device_path);

	info->serial_reopen = (using_serial(info)) ? true : false;
	info->thr = thr;
	mutex_init(&info->lock);
	cgsem_init(&info->wusem);

	// Use qualitative value until first result is returned
	info->hashes_per_s = info->golden_speed_per_core * info->cores_per_chip * info->chips_count;

	return true;
}

static bool lketc_thread_init(struct thr_info *thr)
{
	struct cgpu_info *lketc = thr->cgpu;
	struct LKETC_INFO *info = lketc->device_data;

	if (pthread_create(&info->sworkpth, NULL, lketc_send_work_thread, lketc)) {
		applog(LOG_ERR, "%s%d: Failed to create I/O thread",
				lketc->drv->name, lketc->device_id);
		return false;
	}

	return true;
}

static int64_t lketc_scanwork(struct thr_info *thr)
{
	struct cgpu_info *lketc = thr->cgpu;
	struct LKETC_INFO *info = lketc->device_data;
	struct timeval old_scanwork_time;
	double elapsed_s;
	int64_t estimate_hashes;

	if (unlikely(using_libusb(info) && lketc->usbinfo.nodev))
		return -1;

	if (unlikely(using_serial(info) && info->serial_reopen)) {
		cgsleep_ms(500);
		return 0;
	}

	if (unlikely(!lketc_read_response(lketc)))  // reads either from serial or libusb or times out
		return 0;

	if (thr->work_restart || thr->work_update) {
		lketc_purge_work(lketc);
		thr->work_restart = false;
		thr->work_update = false;
	}

	mutex_lock(&info->lock);
	old_scanwork_time = info->scanwork_time;
	cgtime(&info->scanwork_time);
	elapsed_s = tdiff(&info->scanwork_time, &old_scanwork_time);
	estimate_hashes = elapsed_s * info->hashes_per_s;
	mutex_unlock(&info->lock);

	if (unlikely(estimate_hashes > 0xffffffff))
		estimate_hashes = 0xffffffff;

	return estimate_hashes;
}

#define lketc_update_work lketc_flush_work
static void lketc_flush_work(struct cgpu_info *lketc)
{
	lketc_purge_work(lketc);
	if (opt_lketc_debug)
		applog(LOG_INFO, "lketc_flush_work: Tickling I/O thread");
}

static struct api_data *lketc_api_stats(struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	struct api_data *root = NULL;
	static struct timeval tv_now, tv_diff, tv_diff2;
	static double khs_core, khs_chip, khs_board;

	cgtime(&tv_now);
	timersub(&tv_now, &(info->workstart), &tv_diff);
	timersub(&(info->workend), &(info->workstart), &tv_diff2);

	root = api_add_string(root, "Device Name", lketc->unique_id, false);
	khs_core = (double)info->golden_speed_per_core / 1000.;
	khs_chip = (double)info->golden_speed_per_core * (double)info->cores_per_chip / 1000.;
	khs_board = (double)info->golden_speed_per_core * (double)info->cores_per_chip * (double)info->chips_count / 1000.;
	root = api_add_khs(root, "KHS/Core", &khs_core, false);
	root = api_add_khs(root, "KHS/Chip", &khs_chip, false);
	root = api_add_khs(root, "KHS/Board", &khs_board, false);
	root = api_add_int(root, "Frequency", &(info->chip_clk), false);
	root = api_add_int(root, "Cores/Chip", &(info->cores_per_chip), false);
	root = api_add_int(root, "Chips Count", &(info->chips_count), false);
	root = api_add_timeval(root, "Time Spent Current Work", &tv_diff, false);
	root = api_add_timeval(root, "Work Timeout", &(info->work_timeout), false);
	/* It would be nice to report per chip/core nonce and error counts,
	 * but with more powerful miners with > 100 chips each with 8 cores
	 * there is too much information and we'd overflow the api buffer.
	 * Perhaps another api command to query individual chips? */

	/* these values are more for diagnostic and debugging */
	if (opt_lketc_debug) {
		root = api_add_int(root, "chips_count_max", &(info->chips_count_max), false);
		root = api_add_int(root, "chips_bit_num", &(info->chips_bit_num), false);
		root = api_add_uint32(root, "read_count", &(info->read_count), false);

		root = api_add_double(root, "hashes_per_s", &(info->hashes_per_s), false);
		root = api_add_uint32(root, "last_nonce", &(info->last_nonce), false);
		root = api_add_timeval(root, "last_nonce_time", &tv_diff2, false);
	}

	return root;
}

static void lketc_get_statline_before(char *buf, size_t bufsiz, struct cgpu_info *lketc)
{
	struct LKETC_INFO *info = lketc->device_data;
	if (lketc->name)
		tailsprintf(buf, bufsiz, "%-12s  %4d MHz  ", lketc->name, info->chip_clk);
	else
		tailsprintf(buf, bufsiz, "%4d chips  %4d MHz  ", info->chips_count, info->chip_clk);
}

static char *lketc_set_device(struct cgpu_info *lketc, char *option, char *setting, char *replybuf)
{
	struct LKETC_INFO *info = lketc->device_data;
	int val;

	if (strcasecmp(option, "help") == 0) {
		sprintf(replybuf, "freq: range %d-%d, abortwork: true/false",
				LKETC_CLK_MIN, LKETC_CLK_MAX);
		return replybuf;
	}

	if (strcasecmp(option, "freq") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing freq setting");
			return replybuf;
		}

		val = atoi(setting);
		if (val < LKETC_CLK_MIN || val > LKETC_CLK_MAX) {
			sprintf(replybuf, "invalid freq: '%s' valid range %d-%d",
					setting, LKETC_CLK_MIN, LKETC_CLK_MAX);
			return replybuf;
		}

		mutex_lock(&info->lock);
		info->next_chip_clk = val;
		info->freqcode = lketc_clk_to_freqcode(val);
		mutex_unlock(&info->lock);
		return NULL;
	}

	if (strcasecmp(option, "abortwork") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing true/false");
			return replybuf;
		}

		if (strcasecmp(setting, "true") != 0) {
			sprintf(replybuf, "not aborting current work");
			return replybuf;
		}

		lketc_purge_work(lketc);
		return NULL;
	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

static void lketc_thread_enable(struct thr_info *thr)
{
	struct cgpu_info *lketc = thr->cgpu;
	notify_send_work_thread(lketc);
}

static void lketc_shutdown(struct thr_info *thr)
{
	struct cgpu_info *lketc = thr->cgpu;
	struct LKETC_INFO *info = lketc->device_data;

	applog(LOG_NOTICE, "%s%d: Shutting down", lketc->drv->name, lketc->device_id);

	pthread_join(info->sworkpth, NULL);
	mutex_destroy(&info->lock);
	cgsem_destroy(&info->wusem);

	if (info->device_fd != -1) {
		lketc_serial_close(info->device_fd);
		info->device_fd = -1;
	}
}

struct device_drv lketc_drv = {
		.drv_id = DRIVER_lketc,
		.dname = "LKETC",
		.name = "LKE",
		.max_diff = 32768,
		.drv_detect = lketc_detect,
		.thread_prepare = lketc_prepare,
		.thread_init = lketc_thread_init,
		.hash_work = hash_driver_work,
		.scanwork = lketc_scanwork,
		.flush_work = lketc_flush_work,
		.update_work = lketc_update_work,
		.get_api_stats = lketc_api_stats,
		.get_statline_before = lketc_get_statline_before,
		.set_device = lketc_set_device,
		.thread_enable = lketc_thread_enable,
		.thread_shutdown = lketc_shutdown,
};
