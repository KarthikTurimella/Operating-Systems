////////////////////////////////////////////////////////
// Everything about reading/writing to the disk
// We are implementing the very basic PIO method
// as explained in http://wiki.osdev.org/ATA_PIO_Mode
// On the real world, DMA is the preferred method
//
// We will use the LBA28 addressing mode 

#include "kernel_only.h"

uint32_t total_sectors;	// total number of LBA28 addressable sectors

/*** Initialize the disk (get total_sectors) ***/
// Disk I/O port address on primary ATA bus
// 0x1F0: Data port
// 0x1F1: Not used (NULL)
// 0x1F2: Sector count = number of sectors to read/write (0 is a special value)
// 0x1F3: LBA lower 8 bits
// 0x1F4: LBA next 8 bits
// 0x1F5: LBA next 8 bits
// 0x1F6: Set LBA mode and LBA28 higher 4 bits
// 0x1F7: Command port/Regular status port
void init_disk(void) {
	uint8_t status;
	uint16_t data[256];

	int i;
	
	total_sectors = 0;

	// run the IDENTIFY DEVICE command
	// special data is written to the ports
	port_write_byte(0x1F6, 0xA0);	// select master on primary bus
	port_write_byte(0x1F2, 0);	// sectorcount = 0, means 256
	port_write_byte(0x1F3, 0);	// LBAlo set as 0
	port_write_byte(0x1F4, 0);	// LBAmid set as 0
	port_write_byte(0x1F5, 0);	// LBAhi set as 0
	port_write_byte(0x1F7, 0xEC);	// send IDENTIFY command to command-IO port

	do {
		status = port_read_byte(0x1F7);	// read status byte
		if (status == 0) {	// no disk
			total_sectors = 0;
			return;
		}
	} while (status & 0x80); // until BSY (busy) bit is cleared

	do {
		status = port_read_byte(0x1F7);	// read status byte
		// loop until DRQ or ERR bit is set
		if (status & 0x08 || status & 0x01) break; 
	} while (1);

	if (!(status & 0x01)) { // not an error
		for(i=0; i<256; i++) { // read 256 words (2-byte per word)
			data[i] = port_read_word(0x1F0);
		}
		// no. of LBA 28-bit addressable sectors
		total_sectors = ((uint32_t)data[60] | ((uint32_t)data[61]<<16)); 
	}
	else {
		total_sectors = 0;
	}
	
}

/*** Read up to 256 sectors starting from given 28-bit LBA ***/
// n_sectors = 0 means 256
// buffer must be able to hold the data; otherwise overflow (DANGER!)
// return codes: DISK_ERROR_ERR, DISK_ERROR_DF and NO_ERROR,
//		 DISK_ERROR_LBA_OUTSIDE_RANGE, DISK_ERROR_SECTORCOUNT_TOO_BIG
//
// Meaning of bit used in status code
// 	0:	ERR (indicates an error occurred. Send a new 
//		command to clear it)
//	3: 	DRQ (will be set when the drive has PIO data to transfer,
//		or is ready to accept PIO data)
//	5: 	DF (Drive Fault error (does not set ERR))
//	6: 	RDY (bit is clear when drive is spun down, or after an
//		error; set otherwise)
//	7: 	BSY (indicates the drive is preparing to send/receive data
//		(wait for it to clear);in case of 'hang' (it never clears),
//		do a software reset) 
uint8_t read_disk(uint32_t LBA, uint8_t n_sectors, uint8_t *buffer) {
	uint8_t status;
	int i;
	uint16_t sectors_to_read;
	uint16_t *data = (uint16_t *)buffer;

	if (LBA >= total_sectors) return DISK_ERROR_LBA_OUTSIDE_RANGE;
	if (LBA + n_sectors > total_sectors) return DISK_ERROR_SECTORCOUNT_TOO_BIG;

	// LBA mode (bit 6) and highest four bits of LBA (bit 7 and 5 are always set)
	port_write_byte(0x1F6, 0xE0 | ((LBA >> 24) & 0x0F)); 

	port_write_byte(0x1F1,0x00);			// NULL byte
	port_write_byte(0x1F2,n_sectors); 		// sector count
	port_write_byte(0x1F3,(uint8_t)LBA);		// low 8 bits of LBA
	port_write_byte(0x1F4,(uint8_t)(LBA>>8));	// next 8 bits of LBA
	port_write_byte(0x1F5,(uint8_t)(LBA>>16));	// next 8 bits of LBA
	port_write_byte(0x1F7,0x20);			// send READ SECTORS command

	sectors_to_read = (n_sectors==0)?256:n_sectors;

	for (; sectors_to_read>0; sectors_to_read--) {
		// poll for readiness
		do {
			status = port_read_byte(0x1F7);
		} while (status & 0x80); // until BSY (busy) bit is cleared
		while(1) {
			if (status & 0x01) return DISK_ERROR_ERR; // ERR bit set
			if (status & 0x02) return DISK_ERROR_DF;  // DF bit set
			if (status & 0x08) break;		  // DRQ bit set
		}

		// read one sector
		for(i=0; i<256; i++) {
			data[i] = port_read_word(0x1F0); // read one word (2 bytes)
		}
		data += 256;

		// 400ns delay
		port_read_byte(0x1F7); port_read_byte(0x1F7); port_read_byte(0x1F7); port_read_byte(0x1F7);
	}
	return NO_ERROR;
}
