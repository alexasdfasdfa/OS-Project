// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2012 SAMSUNG Electronics
 * Jaehoon Chung <jh80.chung@samsung.com>
 * Rajeshawari Shinde <rajeshwari.s@samsung.com>
 */

#include "dwmmc.h"
#include "../debug.h"
#include "mmc.h"
// #include <errno.h>

#ifdef DRIVER_DWMMC

#define PAGE_SIZE 4096

static inline int __test_and_clear_bit_1(int nr, void *addr)
{
	int mask, retval;
	unsigned int *a = (unsigned int *)addr;

	a += nr >> 5;
	mask = 1 << (nr & 0x1f);
	retval = (mask & *a) != 0;
	*a &= ~mask;

	return retval;
}

static int dwmci_wait_reset(struct dwmci_host *host, u32 value)
{
	unsigned long timeout = 1000;
	u32 ctrl;

	dwmci_writel(host, DWMCI_CTRL, value);

	while (timeout--) {
		ctrl = dwmci_readl(host, DWMCI_CTRL);
		if (!(ctrl & DWMCI_RESET_ALL))
			return 1;
	}
	return 0;
}

static void dwmci_set_idma_desc(struct dwmci_idmac *idmac,
		u32 desc0, u32 desc1, u32 desc2)
{
	struct dwmci_idmac *desc = idmac;

	desc->flags = desc0;
	desc->cnt = desc1;
	desc->addr = desc2;
	desc->next_addr = (ulong)desc + sizeof(struct dwmci_idmac);
}

static void dwmci_prepare_data(struct dwmci_host *host,
			       struct mmc_data *data,
			       struct dwmci_idmac *cur_idmac,
			       void *bounce_buffer)
{
	unsigned long ctrl;
	unsigned int i = 0, flags, cnt, blk_cnt;
	ulong data_start, data_end;


	blk_cnt = data->blocks;

	dwmci_wait_reset(host, DWMCI_CTRL_FIFO_RESET);

	/* Clear IDMAC interrupt */
	dwmci_writel(host, DWMCI_IDSTS, 0xFFFFFFFF);

	data_start = (ulong)cur_idmac;
	dwmci_writel(host, DWMCI_DBADDR, (ulong)cur_idmac);

	do {
		flags = DWMCI_IDMAC_OWN | DWMCI_IDMAC_CH ;
		flags |= (i == 0) ? DWMCI_IDMAC_FS : 0;
		if (blk_cnt <= 8) {
			flags |= DWMCI_IDMAC_LD;
			cnt = data->blocksize * blk_cnt;
		} else
			cnt = data->blocksize * 8;

		dwmci_set_idma_desc(cur_idmac, flags, cnt,
				    (ulong)bounce_buffer + (i * PAGE_SIZE));

		cur_idmac++;
		if (blk_cnt <= 8)
			break;
		blk_cnt -= 8;
		i++;
	} while(1);

	data_end = (ulong)cur_idmac;
	flush_dcache_range(data_start, roundup(data_end, ARCH_DMA_MINALIGN));

	ctrl = dwmci_readl(host, DWMCI_CTRL);
	ctrl |= DWMCI_IDMAC_EN | DWMCI_DMA_EN;
	dwmci_writel(host, DWMCI_CTRL, ctrl);

	ctrl = dwmci_readl(host, DWMCI_BMOD);
	ctrl |= DWMCI_BMOD_IDMAC_FB | DWMCI_BMOD_IDMAC_EN;
	dwmci_writel(host, DWMCI_BMOD, ctrl);

	dwmci_writel(host, DWMCI_BLKSIZ, data->blocksize);
	dwmci_writel(host, DWMCI_BYTCNT, data->blocksize * data->blocks);
}

static int dwmci_fifo_ready(struct dwmci_host *host, u32 bit, u32 *len)
{
	u32 timeout = 20000;

	*len = dwmci_readl(host, DWMCI_STATUS);
	while (--timeout && (*len & bit)) {
		udelay(200);
		*len = dwmci_readl(host, DWMCI_STATUS);
	}

	if (!timeout) {
		debug("%s: FIFO underflow timeout\n", __func__);
		return -ETIMEDOUT;
	}

	return 0;
}

static unsigned int dwmci_get_timeout(struct mmc *mmc, const unsigned int size)
{
	// unsigned int timeout;

	// timeout = size * 8;	/* counting in bits */
	// timeout *= 10;		/* wait 10 times as long */
	// // timeout /= mmc->clock;
	// // timeout /= mmc->bus_width;
	// // timeout /= mmc->ddr_mode ? 2 : 1;
	// timeout *= 1000;	/* counting in msec */
	// timeout = (timeout < 1000) ? 1000 : timeout;

	return 1000;
}

static int dwmci_data_transfer(struct dwmci_host *host, struct mmc_data *data)
{
	// struct mmc *mmc = host->mmc;
	int ret = 0;
	u32 timeout, mask, size, i, len = 0;
	u32 *buf = NULL;
	ulong start = get_timer(0);
	u32 fifo_depth = (((host->fifoth_val & RX_WMARK_MASK) >>
			    RX_WMARK_SHIFT) + 1) * 2;

	size = data->blocksize * data->blocks;
	if (data->flags == MMC_DATA_READ)
		buf = (unsigned int *)data->dest;
	else
		buf = (unsigned int *)data->src;

	timeout = dwmci_get_timeout(NULL, size);

	size /= 4;

	for (;;) {
		mask = dwmci_readl(host, DWMCI_RINTSTS);
		/* Error during data transfer. */
		if (mask & (DWMCI_DATA_ERR | DWMCI_DATA_TOUT)) {
			debug("%s: DATA ERROR!\n", __func__);
			ret = -EINVAL;
			break;
		}

		if (host->fifo_mode && size) {
			len = 0;
			if (data->flags == MMC_DATA_READ &&
			    (mask & (DWMCI_INTMSK_RXDR | DWMCI_INTMSK_DTO))) {
				dwmci_writel(host, DWMCI_RINTSTS,
					     DWMCI_INTMSK_RXDR | DWMCI_INTMSK_DTO);
				while (size) {
					ret = dwmci_fifo_ready(host,
							DWMCI_FIFO_EMPTY,
							&len);
					if (ret < 0)
						break;

					len = (len >> DWMCI_FIFO_SHIFT) &
						    DWMCI_FIFO_MASK;
					len = min(size, len);
					for (i = 0; i < len; i++)
						*buf++ =
						dwmci_readl(host, DWMCI_DATA);
					size = size > len ? (size - len) : 0;
				}
			} else if (data->flags == MMC_DATA_WRITE &&
				   (mask & DWMCI_INTMSK_TXDR)) {
				while (size) {
					ret = dwmci_fifo_ready(host,
							DWMCI_FIFO_FULL,
							&len);
					if (ret < 0)
						break;

					len = fifo_depth - ((len >>
						   DWMCI_FIFO_SHIFT) &
						   DWMCI_FIFO_MASK);
					len = min(size, len);
					for (i = 0; i < len; i++)
						dwmci_writel(host, DWMCI_DATA,
							     *buf++);
					size = size > len ? (size - len) : 0;
				}
				dwmci_writel(host, DWMCI_RINTSTS,
					     DWMCI_INTMSK_TXDR);
			}
		}

		/* Data arrived correctly. */
		if (mask & DWMCI_INTMSK_DTO) {
			ret = 0;
			break;
		}

		/* Check for timeout. */
		if (get_timer(start) > timeout) {
			debug("%s: Timeout waiting for data!\n",
			      __func__);
			ret = -ETIMEDOUT;
			break;
		}
	}

	dwmci_writel(host, DWMCI_RINTSTS, mask);

	return ret;
}

static int dwmci_set_transfer_mode(struct dwmci_host *host,
		struct mmc_data *data)
{
	unsigned long mode;

	mode = DWMCI_CMD_DATA_EXP;
	if (data->flags & MMC_DATA_WRITE)
		mode |= DWMCI_CMD_RW;

	return mode;
}


static int dwmci_send_cmd(struct mmc *mmc, struct mmc_cmd *cmd,
		struct mmc_data *data)
{
	struct dwmci_host *host = mmc->priv;
	int ret = 0, flags = 0, i;
	unsigned int timeout = 500;
	u32 retry = 100000;
	u32 mask, ctrl;
	ulong start = get_timer(0);

	while (dwmci_readl(host, DWMCI_STATUS) & DWMCI_BUSY) {
		if (get_timer(start) > timeout) {
			debug("%s: Timeout on data busy\n", __func__);
			return -ETIMEDOUT;
		}
	}

	dwmci_writel(host, DWMCI_RINTSTS, DWMCI_INTMSK_ALL);

	if (data) {
		if (host->fifo_mode) {
			dwmci_writel(host, DWMCI_BLKSIZ, data->blocksize);
			dwmci_writel(host, DWMCI_BYTCNT,
				     data->blocksize * data->blocks);
			dwmci_wait_reset(host, DWMCI_CTRL_FIFO_RESET);
		} else {
			// TODO: assert
			assert(0);
		}
	}

	dwmci_writel(host, DWMCI_CMDARG, cmd->cmdarg);

	if (data)
		flags = dwmci_set_transfer_mode(host, data);

	if ((cmd->resp_type & MMC_RSP_136) && (cmd->resp_type & MMC_RSP_BUSY))
		return -1;

	if (cmd->cmdidx == MMC_CMD_STOP_TRANSMISSION)
		flags |= DWMCI_CMD_ABORT_STOP;
	else
		flags |= DWMCI_CMD_PRV_DAT_WAIT;

	if (cmd->resp_type & MMC_RSP_PRESENT) {
		flags |= DWMCI_CMD_RESP_EXP;
		if (cmd->resp_type & MMC_RSP_136)
			flags |= DWMCI_CMD_RESP_LENGTH;
	}

	if (cmd->resp_type & MMC_RSP_CRC)
		flags |= DWMCI_CMD_CHECK_CRC;

	if (__test_and_clear_bit_1(DW_MMC_CARD_NEED_INIT, &host->flags))
		flags |= DWMCI_CMD_SEND_INIT;

	flags |= (cmd->cmdidx | DWMCI_CMD_START | DWMCI_CMD_USE_HOLD_REG);

	debug("Sending CMD%d\n",cmd->cmdidx);

	dwmci_writel(host, DWMCI_CMD, flags);

	for (i = 0; i < retry; i++) {
		mask = dwmci_readl(host, DWMCI_RINTSTS);
		if (mask & DWMCI_INTMSK_CDONE) {
			if (!data)
				dwmci_writel(host, DWMCI_RINTSTS, mask);
			break;
		}
	}

	if (i == retry) {
		debug("%s: Timeout.\n", __func__);
		return -ETIMEDOUT;
	}

	if (mask & DWMCI_INTMSK_RTO) {
		/*
		 * Timeout here is not necessarily fatal. (e)MMC cards
		 * will splat here when they receive CMD55 as they do
		 * not support this command and that is exactly the way
		 * to tell them apart from SD cards. Thus, this output
		 * below shall be debug(). eMMC cards also do not favor
		 * CMD8, please keep that in mind.
		 */
		debug("%s: Response Timeout.\n", __func__);
		return -ETIMEDOUT;
	} else if (mask & DWMCI_INTMSK_RE) {
		debug("%s: Response Error.\n", __func__);
		return -EIO;
	} else if ((cmd->resp_type & MMC_RSP_CRC) &&
		   (mask & DWMCI_INTMSK_RCRC)) {
		debug("%s: Response CRC Error.\n", __func__);
		return -EIO;
	}


	if (cmd->resp_type & MMC_RSP_PRESENT) {
		if (cmd->resp_type & MMC_RSP_136) {
			cmd->response[0] = dwmci_readl(host, DWMCI_RESP3);
			cmd->response[1] = dwmci_readl(host, DWMCI_RESP2);
			cmd->response[2] = dwmci_readl(host, DWMCI_RESP1);
			cmd->response[3] = dwmci_readl(host, DWMCI_RESP0);
		} else {
			cmd->response[0] = dwmci_readl(host, DWMCI_RESP0);
		}
	}

	if (data) {
		ret = dwmci_data_transfer(host, data);

		/* only dma mode need it */
		if (!host->fifo_mode) {
			if (data->flags == MMC_DATA_READ)
				mask = DWMCI_IDINTEN_RI;
			else
				mask = DWMCI_IDINTEN_TI;
			ret = wait_for_bit_le32(host->ioaddr + DWMCI_IDSTS,
						mask, true, 1000, false);
			if (ret)
				debug("%s: DWMCI_IDINTEN mask 0x%x timeout.\n",
				      __func__, mask);
			/* clear interrupts */
			dwmci_writel(host, DWMCI_IDSTS, DWMCI_IDINTEN_MASK);

			ctrl = dwmci_readl(host, DWMCI_CTRL);
			ctrl &= ~(DWMCI_DMA_EN);
			dwmci_writel(host, DWMCI_CTRL, ctrl);
			bounce_buffer_stop(&bbstate);
		}
	}

	udelay(100);

	return ret;
}

static int dwmci_setup_bus(struct dwmci_host *host, u32 freq)
{
	u32 div, status;
	int timeout = 10000;
	unsigned long sclk;

	if ((freq == host->clock) || (freq == 0))
		return 0;
	/*
	 * If host->get_mmc_clk isn't defined,
	 * then assume that host->bus_hz is source clock value.
	 * host->bus_hz should be set by user.
	 */
	// if (host->get_mmc_clk)
	// 	sclk = host->get_mmc_clk(host, freq);
	else if (host->bus_hz)
		sclk = host->bus_hz;
	else {
		debug("%s: Didn't get source clock value.\n", __func__);
		return -EINVAL;
	}

	if (sclk == freq)
		div = 0;	/* bypass mode */
	else
		div = DIV_ROUND_UP(sclk, 2 * freq);

	dwmci_writel(host, DWMCI_CLKENA, 0);
	dwmci_writel(host, DWMCI_CLKSRC, 0);

	dwmci_writel(host, DWMCI_CLKDIV, div);
	dwmci_writel(host, DWMCI_CMD, DWMCI_CMD_PRV_DAT_WAIT |
			DWMCI_CMD_UPD_CLK | DWMCI_CMD_START);

	do {
		status = dwmci_readl(host, DWMCI_CMD);
		if (timeout-- < 0) {
			debug("%s: Timeout!\n", __func__);
			return -ETIMEDOUT;
		}
	} while (status & DWMCI_CMD_START);

	dwmci_writel(host, DWMCI_CLKENA, DWMCI_CLKEN_ENABLE |
			DWMCI_CLKEN_LOW_PWR);

	dwmci_writel(host, DWMCI_CMD, DWMCI_CMD_PRV_DAT_WAIT |
			DWMCI_CMD_UPD_CLK | DWMCI_CMD_START);

	timeout = 10000;
	do {
		status = dwmci_readl(host, DWMCI_CMD);
		if (timeout-- < 0) {
			debug("%s: Timeout!\n", __func__);
			return -ETIMEDOUT;
		}
	} while (status & DWMCI_CMD_START);

	host->clock = freq;

	return 0;
}


static int dwmci_set_ios(struct mmc *mmc)
{
	struct dwmci_host *host = (struct dwmci_host *)mmc->priv;
	u32 ctype, regs;

	debug("Buswidth = %d, clock: %d\n", mmc->bus_width, mmc->clock);

	dwmci_setup_bus(host, mmc->clock);
	ctype = DWMCI_CTYPE_8BIT;

	dwmci_writel(host, DWMCI_CTYPE, ctype);

	regs = dwmci_readl(host, DWMCI_UHS_REG);
	if (mmc->ddr_mode)
		regs |= DWMCI_DDR_MODE;
	else
		regs &= ~DWMCI_DDR_MODE;

	dwmci_writel(host, DWMCI_UHS_REG, regs);

	if (host->clksel) {
		int ret;

		ret = host->clksel(host);
		if (ret)
			return ret;
	}

	return 0;
}

static void dw_mci_hs_set_bits(struct dwmci_host *host, u32 smpl_phase)
{
	/* change driver phase and sample phase */
	u32 mask = 0x1f;
	u32 reg_value;

	reg_value = dwmci_readl(host, DWMCI_UHS_REG_EXT);

	/* In UHS_REG_EXT, only 5 bits valid in DRV_PHASE and SMPL_PHASE */
	reg_value &= ~(mask << 16);
	reg_value |= (smpl_phase << 16);
	dwmci_writel(host, DWMCI_UHS_REG_EXT, reg_value);

	/* We should delay 1ms wait for timing setting finished. */
	udelay(1000);
}

static int dwmci_execute_tuning(struct udevice *dev, uint opcode)
{
	struct mmc *mmc = mmc_get_mmc_dev(dev);
	struct dwmci_host *host = mmc->priv;
	int err = -1;
	int smpl_phase, smpl_raise = -1, smpl_fall = -1;
	int i;

	for (i = 0; i < 32; ++i) {
		smpl_phase = i;
		dw_mci_hs_set_bits(host, smpl_phase);
		dwmci_writel(host, DWMCI_RINTSTS, DWMCI_INTMSK_ALL);

		err = mmc_send_tuning(mmc, opcode, NULL);

		if (!err && smpl_raise < 0) {
			smpl_raise = i;
		} else if (err && smpl_raise >= 0) {
			smpl_fall = i - 1;
			break;
		}
	}

	if (i >= 32 && smpl_raise >= 0)
		smpl_fall = 31;

	if (smpl_raise < 0) {
		pr_err("No valid delay chain! use default\n");
		dw_mci_hs_set_bits(host, 0);
		err = -EINVAL;
	} else {
		smpl_phase = (smpl_raise + smpl_fall) / 2;
		dw_mci_hs_set_bits(host, smpl_phase);
		pr_debug("Found valid delay chain! use it [delay=%d]\n", smpl_phase);
		err = 0;
	}

	dwmci_writel(host, DWMCI_RINTSTS, DWMCI_INTMSK_ALL);
	return err;
}

static int dwmci_init(struct mmc *mmc)
{
	struct dwmci_host *host = mmc->priv;

	if (host->board_init)
		host->board_init(host);

	dwmci_writel(host, DWMCI_PWREN, 1);

	if (!dwmci_wait_reset(host, DWMCI_RESET_ALL)) {
		debug("%s[%d] Fail-reset!!\n", __func__, __LINE__);
		return -EIO;
	}

	host->flags = 1 << DW_MMC_CARD_NEED_INIT;

	/* Enumerate at 400KHz */
	dwmci_setup_bus(host, mmc->cfg->f_min);

	dwmci_writel(host, DWMCI_RINTSTS, 0xFFFFFFFF);
	dwmci_writel(host, DWMCI_INTMASK, 0);

	dwmci_writel(host, DWMCI_TMOUT, 0xFFFFFFFF);

	dwmci_writel(host, DWMCI_IDINTEN, 0);
	dwmci_writel(host, DWMCI_BMOD, 1);

	if (!host->fifoth_val) {
		uint32 fifo_size;

		fifo_size = dwmci_readl(host, DWMCI_FIFOTH);
		fifo_size = ((fifo_size & RX_WMARK_MASK) >> RX_WMARK_SHIFT) + 1;
		host->fifoth_val = MSIZE(0x2) | RX_WMARK(fifo_size / 2 - 1) |
				TX_WMARK(fifo_size / 2);
	}
	dwmci_writel(host, DWMCI_FIFOTH, host->fifoth_val);

	dwmci_writel(host, DWMCI_CLKENA, 0);
	dwmci_writel(host, DWMCI_CLKSRC, 0);

	if (!host->fifo_mode)
		dwmci_writel(host, DWMCI_IDINTEN, DWMCI_IDINTEN_MASK);

	return 0;
}

void dwmci_setup_cfg(struct mmc_config *cfg, struct dwmci_host *host,
		u32 max_clk, u32 min_clk)
{
	cfg->name = host->name;
#ifndef CONFIG_DM_MMC
	cfg->ops = &dwmci_ops;
#endif
	cfg->f_min = min_clk;
	cfg->f_max = max_clk;

	cfg->voltages = MMC_VDD_32_33 | MMC_VDD_33_34 | MMC_VDD_165_195;

	cfg->host_caps = host->caps;

	if (host->buswidth == 8) {
		cfg->host_caps |= MMC_MODE_8BIT;
		cfg->host_caps &= ~MMC_MODE_4BIT;
	} else {
		cfg->host_caps |= MMC_MODE_4BIT;
		cfg->host_caps &= ~MMC_MODE_8BIT;
	}
// #if CONFIG_IS_ENABLED(TARGET_STARFIVE_VISIONFIVE2)
	cfg->host_caps |= MMC_MODE_HS | MMC_MODE_HS_52MHz | MMC_MODE_HS200;
// #else
// 	cfg->host_caps |= MMC_MODE_HS_52MHz | MMC_MODE_HS200;
// #endif

	cfg->b_max = CONFIG_SYS_MMC_MAX_BLK_COUNT;
}
#endif