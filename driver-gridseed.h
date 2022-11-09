#ifndef INCLUDE_DRIVER_GRIDSEED_H
#define INCLUDE_DRIVER_GRIDSEED_H

#ifdef USE_GRIDSEED

#include "util.h"

#define GRIDSEED_MINER_THREADS		1
#define GRIDSEED_LATENCY		4

#define GRIDSEED_DEFAULT_BAUD		115200
#define GRIDSEED_DEFAULT_FREQUENCY	600
#define GRIDSEED_DEFAULT_CHIPS		5
#define GRIDSEED_MAX_CHIPS		256
#define GRIDSEED_DEFAULT_MODULES	1
#define GRIDSEED_DEFAULT_USEFIFO	0
#define GRIDSEED_DEFAULT_BTCORE		16

#define GRIDSEED_COMMAND_DELAY		20
#define GRIDSEED_READ_SIZE		12
#define GRIDSEED_MCU_QUEUE_LEN		8
#define GRIDSEED_SOFT_QUEUE_LEN		(GRIDSEED_MCU_QUEUE_LEN+2)
#define GRIDSEED_READBUF_SIZE		8192
#define GRIDSEED_HASH_SPEED		((double)0.0851128926)  // in ms
#define GRIDSEED_F_IN			25  // input frequency

#define GRIDSEED_MIN_FREQUENCY		13
#define GRIDSEED_MAX_FREQUENCY		1600

#define GRIDSEED_PROXY_PORT		3350

#define GRIDSEED_PERIPH_BASE		((uint32_t)0x40000000)
#define GRIDSEED_APB2PERIPH_BASE	(GRIDSEED_PERIPH_BASE + 0x10000)
#define GRIDSEED_GPIOA_BASE		(GRIDSEED_APB2PERIPH_BASE + 0x0800)
#define GRIDSEED_GPIOB_BASE		(GRIDSEED_APB2PERIPH_BASE + 0x0c00)
#define GRIDSEED_CRL_OFFSET		0x00
#define GRIDSEED_ODR_OFFSET		0x0c

#define GRIDSEED_USB_ID_MODEL_STR	"STM32_Virtual_COM_Port"

#define transfer(gridseed, request_type, bRequest, wValue, wIndex, cmd) \
		_transfer(gridseed, request_type, bRequest, wValue, wIndex, NULL, 0, cmd)

enum gsd_mode {
	MODE_UNK = 0,
	MODE_SHA256,		// Solo mining in sha256 mode, no proxy requests (yet)
	MODE_SHA256_DUAL,	// Mining sha256 directly, providing proxy for scrypt mining
	MODE_SCRYPT,		// Solo mining in scrypt mode
	MODE_SCRYPT_DUAL	// Mining scrypt via proxy through a sha256 dual miner
};

#define MODE_UNK_STR		"Unknown"
#define MODE_SHA256_STR		"sha256"
#define MODE_SHA256_DUAL_STR	"sha256 / scrypt"
#define MODE_SCRYPT_STR		"scrypt"
#define MODE_SCRYPT_DUAL_STR	"scrypt via proxy"

#define SHA256_MODE(mode) ((mode) == MODE_SHA256 || (mode) == MODE_SHA256_DUAL)
#define SCRYPT_MODE(mode) ((mode) == MODE_SCRYPT || (mode) == MODE_SCRYPT_DUAL)

typedef struct s_gridseed_info {
	// device
	enum sub_ident		ident;
	uint32_t		fw_version;
	char			id[24];
	int			device_fd;
	int			using_libusb;
	bool			serial_reopen;
	// statistics
	int			nonce_count[GRIDSEED_MAX_CHIPS];  // per chip
	int			error_count[GRIDSEED_MAX_CHIPS];  // per chip
	struct timeval		scanhash_time;
	// options
	int			baud;
	int			freq;
	unsigned char		cmd_freq[8];
	unsigned char		cmd_btc_baud[8];
	int			chips; //chips per module
	int			modules;
	int			usefifo;
	int			btcore;
	int			voltage;
	int			led;
	int			per_chip_stats;
	// runtime
	struct thr_info		*thr;
	pthread_t		th_read;
	pthread_t		th_send;
	pthread_t		th_packet;
	pthread_mutex_t		lock;
	pthread_mutex_t		qlock;
	enum gsd_mode		mode;
	// state
	//   sha
	int			queued;
	int			dev_queue_len;
	int			soft_queue_len;
	struct work		*workqueue[GRIDSEED_SOFT_QUEUE_LEN];
	int			needworks;  /* how many works need to be queue for device */
	bool			query_qlen; /* true when query device queue length and waiting response */
	cgtimer_t		query_ts;
	//   sha & scrypt
	int			workdone;
	//   scrypt
	struct work		*ltc_work;
	struct timeval		ltc_workstart;
	int			hashes_per_ms;
	// proxy
	int			sockltc;
	short			ltc_port;
	struct sockaddr_in	toaddr; /* remote address to send response */
	cgsem_t			psem;
} GRIDSEED_INFO;

enum packet_type {
	PACKET_PING,
	PACKET_INFO,
	PACKET_WORK,
	PACKET_NONCE
};

typedef struct s_gridseed_packet {
	enum packet_type type;
	union {
		struct {
			char id[24];
			int freq;
			int chips;
			int modules;
		} info;
		struct {
			unsigned char target[32];
			unsigned char midstate[32];
			unsigned char data[128];
			int id;
		} work;
		struct {
			uint32_t nonce;
			int workid;
		} nonce;
	};
} GRIDSEED_PACKET;

extern struct device_drv gridseed_drv;

#endif /* USE_GRIDSEED */
#endif /* INCLUDE_DRIVER_GRIDSEED_H */
