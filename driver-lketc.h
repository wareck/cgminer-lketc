#ifndef INCLUDE_DRIVER_LKETC_H
#define INCLUDE_DRIVER_LKETC_H

#ifdef USE_LKETC

#define LKETC_PROTOCOL_DEBUG 1

#define LKETC_CHIP_GEN			1
#define LKETC_CHIP_GEN1_CORES		8
#define LKETC_CHIP_CORES			LKETC_CHIP_GEN1_CORES
#define LKETC_MIN_CHIPS			1
#define LKETC_MAX_CHIPS			6

#define LKETC_IO_SPEED			115200

#define LKETC_READ_FAULT_DECISECONDS	2

#define LKETC_COMMAND_PKT_LEN		84
#define LKETC_EVENT_PKT_LEN		4
#define LKETC_READ_BUFFER		LKETC_EVENT_PKT_LEN + 2	// 2 = max value of read_data_offset; allows 2 extra FTDI status bytes

#define LKETC_CLK_MAX			320	// 0xff * 3/2
#define LKETC_CLK_MIN			200

#define LKETC_USB_ID_MODEL_STR1		"CP2103_USB_to_UART_Bridge_Controller"

#define PIPE_R 0
#define PIPE_W 1

struct LKETC_INFO {
	char		device_name[24];
	int		device_fd;
	int		using_libusb;
	bool		serial_reopen;

	unsigned int	nonce_count[LKETC_MAX_CHIPS][LKETC_CHIP_CORES];
	unsigned int	error_count[LKETC_MAX_CHIPS][LKETC_CHIP_CORES];
	unsigned int	workdone;

	struct timeval	workstart;
	struct timeval	workend;
	struct timeval	scanwork_time;
	struct timeval	work_timeout;
	double		hashes_per_s;
	uint64_t	golden_speed_per_core;	// speed per core per sec
	uint32_t	read_count;
	uint32_t	last_nonce;
	int		next_chip_clk;

	unsigned char	freqcode;

	struct thr_info	*thr;
	pthread_t	sworkpth;
	pthread_mutex_t	lock;
	cgsem_t		wusem;

	struct work	*current_work;

	int		baud;
	int		cores_per_chip;
	int		chips_count_max;
	int		chips_count;
	int		chip_clk;
	int		chips_bit_num;		// log2(chips_count_max)
	int		read_data_offset;
};

extern struct device_drv lketc_drv;

#endif /* USE_LKETC */
#endif /* INCLUDE_DRIVER_LKETC_H */
