#ifndef INCLUDE_DRIVER_ZEUS_H
#define INCLUDE_DRIVER_ZEUS_H

#ifdef USE_ZEUS

#define ZEUS_PROTOCOL_DEBUG 1

#define ZEUS_CHIP_GEN			1
#define ZEUS_CHIP_GEN1_CORES		8
#define ZEUS_CHIP_CORES			ZEUS_CHIP_GEN1_CORES
#define ZEUS_MIN_CHIPS			6
#define ZEUS_MAX_CHIPS			1024

#define ZEUS_IO_SPEED			115200

#define ZEUS_READ_FAULT_DECISECONDS	2

#define ZEUS_COMMAND_PKT_LEN		84
#define ZEUS_EVENT_PKT_LEN		4

#define ZEUS_CLK_MAX			382	// 0xff * 3/2
#define ZEUS_CLK_MIN			2

#define ZEUS_USB_ID_MODEL_STR1		"CP2102_USB_to_UART_Bridge_Controller"
#define ZEUS_USB_ID_MODEL_STR2		"FT232R_USB_UART"

#define PIPE_R 0
#define PIPE_W 1

struct ZEUS_INFO {
	char		device_name[24];
	int		device_fd;
	int		using_libusb;
	bool		serial_reopen;

	unsigned int	nonce_count[ZEUS_MAX_CHIPS][ZEUS_CHIP_CORES];
	unsigned int	error_count[ZEUS_MAX_CHIPS][ZEUS_CHIP_CORES];
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
};

extern struct device_drv zeus_drv;

#endif /* USE_ZEUS */
#endif /* INCLUDE_DRIVER_ZEUS_H */
