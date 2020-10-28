#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>


#define ZTTY_MINORS     2   /* only have 4 devices */

struct ztty_serial {
    struct tty_struct   *tty;       /* pointer to the tty for this device */
    int                 open_count; /* number of times this port has been opened */
    struct mutex        mutex;      /* locks this structure */

    /* for tiocmget and tiocmset functions */
    int         msr;        /* MSR shadow */
    int         mcr;        /* MCR shadow */

    /* for ioctl fun */
    struct serial_struct    serial;
    wait_queue_head_t   wait;
    struct async_icount icount;
};

static struct ztty_serial *tiny_table[ZTTY_MINORS]; /* initially all NULL */
static struct tty_port tiny_tty_port[ZTTY_MINORS];

#define ZTTY_MAX_ROOM (1024)

static int ttyzCount;
static char ttyzBuff[ZTTY_MAX_ROOM + 4];
static unsigned char sha256Buff[256];

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int do_sha256(const unsigned char *data, int len, unsigned char *out_digest)
{
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";
    unsigned int datalen = len; // remove the null byte

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if(IS_ERR(alg)){
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, datalen, out_digest);
    crypto_free_shash(alg);

    return 0;
}


static void ztty_flush(struct tty_port *port)
{
    int i;
    char buffStr[512] = "";
    char *p = buffStr;

    if (ttyzCount > 0)
    {
        ttyzBuff[ttyzCount] = '\0';

        do_sha256(ttyzBuff, ttyzCount, sha256Buff);

        *p = '\n'; p++; *p = '\r'; p++; //new line,
        for (i = 0; i < 32; ++i)
        {
            if (((i%8) == 0) && i) {*p = '\n'; p++; *p = '\r'; p++;} //new line,
            sprintf(p, "0x%02x|", sha256Buff[i]);
            p += 5;
        }
        *p = '\n'; p++; *p = '\r'; //new line,

        if (!tty_buffer_request_room(port, 1))
            tty_flip_buffer_push(port);

        tty_insert_flip_string(port, buffStr, strlen(buffStr));
        tty_flip_buffer_push(port);

        ttyzCount = 0;
    }
}

static int _print(const unsigned char *buf, int count, struct tty_port *port)
{
    int i = ttyzCount;

    if (buf == NULL)
    {
        ztty_flush(port);
        return i;
    }

    for (i = 0; i < count; i++)
    {
        if (ttyzCount >= ZTTY_MAX_ROOM)
        {
            /* end of tmp buffer reached: cut the message in two */
            ttyzBuff[ttyzCount++] = '\\';
            ztty_flush(port);
        }

        switch (buf[i]) {
            case '\r':
                ztty_flush(port);
                if ((i + 1) < count && buf[i + 1] == '\n')
                    i++;
                break;

            case '\n':
                ztty_flush(port);
                break;

            default:
                ttyzBuff[ttyzCount++] = buf[i];
                break;
        }
    }

    return count;
}

static int ztty_open(struct tty_struct *tty, struct file *file)
{
    struct ztty_serial *tiny;
    int index;

    /* initialize the pointer in case something fails */
    tty->driver_data = NULL;

    /* get the serial object associated with this tty pointer */
    index = tty->index;
    tiny = tiny_table[index];
    if (tiny == NULL)
    {
        /* first time accessing this device, let's create it */
        tiny = kmalloc(sizeof(*tiny), GFP_KERNEL);
        if (!tiny)
            return -ENOMEM;

        mutex_init(&tiny->mutex);
        tiny->open_count = 0;

        tiny_table[index] = tiny;
    }

    mutex_lock(&tiny->mutex);

    /* save our structure within the tty structure */
    tty->driver_data = tiny;
    tiny->tty = tty;

    ++tiny->open_count;
    if (tiny->open_count == 1)
    {
        /* this is the first time this port is opened */
        /* do any hardware initialization needed here */
    }

    mutex_unlock(&tiny->mutex);
    return 0;
}

static void do_close(struct ztty_serial *tiny)
{
    mutex_lock(&tiny->mutex);
    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);
    if (!tiny->open_count) {
        /* port was never opened */
        goto exit;
    }

    --tiny->open_count;
    if (tiny->open_count <= 0) {
        /* The port is being closed by the last user. */
        /* Do any hardware specific stuff here */
    }
exit:
    mutex_unlock(&tiny->mutex);
}

static void ztty_close(struct tty_struct *tty, struct file *file)
{
    struct ztty_serial *ztty = tty->driver_data;

    if (ztty)
        do_close(ztty);
}

static int ztty_write(struct tty_struct *tty, const unsigned char *buffer, int count)
{
    struct ztty_serial *tiny = tty->driver_data;
    int retval = -EINVAL;

    if (!tiny)
        return -ENODEV;

    mutex_lock(&tiny->mutex);

    if (!tiny->open_count)
        goto exit;

    /* fake sending the data out a hardware port by
     * writing it to the kernel debug log.
     */

    if (!tty_buffer_request_room(tiny->tty->port, 1))
        tty_flip_buffer_push(tiny->tty->port);

    tty_insert_flip_char(tiny->tty->port, buffer[0], TTY_NORMAL);
    tty_flip_buffer_push(tiny->tty->port);

    _print(buffer, count, tiny->tty->port);

exit:
    mutex_unlock(&tiny->mutex);
    return retval;
}

static int ztty_write_room(struct tty_struct *tty)
{
    struct ztty_serial *tiny = tty->driver_data;
    int room = -EINVAL;

    if (!tiny)
        return -ENODEV;

    mutex_lock(&tiny->mutex);

    if (!tiny->open_count) {
        goto exit;
    }

    /* calculate how much room is left in the device */
    room = 255;

exit:
    mutex_unlock(&tiny->mutex);
    return room;
}

#define RELEVANT_IFLAG(iflag) ((iflag) & (IGNBRK|BRKINT|IGNPAR|PARMRK|INPCK))

static void ztty_set_termios(struct tty_struct *tty, struct ktermios *old_termios)
{
    unsigned int cflag;

    cflag = tty->termios.c_cflag;

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    /* check that they really want us to change something */
    if (old_termios)
    {
        if ((cflag == old_termios->c_cflag) &&
            (RELEVANT_IFLAG(tty->termios.c_iflag) == RELEVANT_IFLAG(old_termios->c_iflag)))
        {
            pr_debug(" - nothing to change...\n");
            return;
        }
    }

    /* get the byte size */
    switch (cflag & CSIZE)
    {
        case CS5:
            pr_debug(" - data bits = 5\n");
            break;
        case CS6:
            pr_debug(" - data bits = 6\n");
            break;
        case CS7:
            pr_debug(" - data bits = 7\n");
            break;
        default:
        case CS8:
            pr_debug(" - data bits = 8\n");
            break;
    }

    /* determine the parity */
    if (cflag & PARENB)
    {
        if (cflag & PARODD)
            pr_debug(" - parity = odd\n");
        else
            pr_debug(" - parity = even\n");
    }
    else
    {
        pr_debug(" - parity = none\n");
    }

    /* figure out the stop bits requested */
    if (cflag & CSTOPB)
        pr_debug(" - stop bits = 2\n");
    else
        pr_debug(" - stop bits = 1\n");

    /* figure out the hardware flow control settings */
    if (cflag & CRTSCTS)
        pr_debug(" - RTS/CTS is enabled\n");
    else
        pr_debug(" - RTS/CTS is disabled\n");

    /* determine software flow control */
    /* if we are implementing XON/XOFF, set the start and
     * stop character in the device */
    if (I_IXOFF(tty) || I_IXON(tty))
    {
        unsigned char stop_char  = STOP_CHAR(tty);
        unsigned char start_char = START_CHAR(tty);

        /* if we are implementing INBOUND XON/XOFF */
        if (I_IXOFF(tty))
            pr_debug(" - INBOUND XON/XOFF is enabled, "
                "XON = %2x, XOFF = %2x", start_char, stop_char);
        else
            pr_debug(" - INBOUND XON/XOFF is disabled");

        /* if we are implementing OUTBOUND XON/XOFF */
        if (I_IXON(tty))
            pr_debug(" - OUTBOUND XON/XOFF is enabled, "
                "XON = %2x, XOFF = %2x", start_char, stop_char);
        else
            pr_debug(" - OUTBOUND XON/XOFF is disabled");
    }

    /* get the baud rate wanted */
    pr_debug(" - baud rate = %d", tty_get_baud_rate(tty));
}

/* Our fake UART values */
#define MCR_DTR     0x01
#define MCR_RTS     0x02
#define MCR_LOOP    0x04
#define MSR_CTS     0x08
#define MSR_CD      0x10
#define MSR_RI      0x20
#define MSR_DSR     0x40

static int ztty_tiocmget(struct tty_struct *tty)
{
    struct ztty_serial *ztty = tty->driver_data;

    unsigned int result = 0;
    unsigned int msr = ztty->msr;
    unsigned int mcr = ztty->mcr;

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    result = ((mcr & MCR_DTR) ? TIOCM_DTR  : 0) |   /* DTR is set */
            ((mcr & MCR_RTS)  ? TIOCM_RTS  : 0) |   /* RTS is set */
            ((mcr & MCR_LOOP) ? TIOCM_LOOP : 0) |   /* LOOP is set */
            ((msr & MSR_CTS)  ? TIOCM_CTS  : 0) |   /* CTS is set */
            ((msr & MSR_CD)   ? TIOCM_CAR  : 0) |   /* Carrier detect is set*/
            ((msr & MSR_RI)   ? TIOCM_RI   : 0) |   /* Ring Indicator is set */
            ((msr & MSR_DSR)  ? TIOCM_DSR  : 0);    /* DSR is set */

    return result;
}

static int tiny_tiocmset(struct tty_struct *tty, unsigned int set,
             unsigned int clear)
{
    struct ztty_serial *ztty = tty->driver_data;
    unsigned int mcr = ztty->mcr;

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    if (set & TIOCM_RTS)
        mcr |= MCR_RTS;
    if (set & TIOCM_DTR)
        mcr |= MCR_RTS;

    if (clear & TIOCM_RTS)
        mcr &= ~MCR_RTS;
    if (clear & TIOCM_DTR)
        mcr &= ~MCR_RTS;

    /* set the new MCR value in the device */
    ztty->mcr = mcr;
    return 0;
}

#define ztty_ioctl ztty_ioctl_tiocgserial
static int ztty_ioctl(struct tty_struct *tty, unsigned int cmd,
              unsigned long arg)
{
    struct ztty_serial *ztty = tty->driver_data;

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    if (cmd == TIOCGSERIAL) {
        struct serial_struct tmp;

        if (!arg)
            return -EFAULT;

        memset(&tmp, 0, sizeof(tmp));

        tmp.type        = ztty->serial.type;
        tmp.line        = ztty->serial.line;
        tmp.port        = ztty->serial.port;
        tmp.irq         = ztty->serial.irq;
        tmp.flags       = ASYNC_SKIP_TEST | ASYNC_AUTO_IRQ;
        tmp.xmit_fifo_size  = ztty->serial.xmit_fifo_size;
        tmp.baud_base       = ztty->serial.baud_base;
        tmp.close_delay     = 5*HZ;
        tmp.closing_wait    = 30*HZ;
        tmp.custom_divisor  = ztty->serial.custom_divisor;
        tmp.hub6        = ztty->serial.hub6;
        tmp.io_type     = ztty->serial.io_type;

        if (copy_to_user((void __user *)arg, &tmp, sizeof(struct serial_struct)))
            return -EFAULT;

        return 0;
    }
    return -ENOIOCTLCMD;
}
#undef ztty_ioctl

#define ztty_ioctl ztty_ioctl_tiocmiwait
static int ztty_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
    struct ztty_serial *ztty = tty->driver_data;

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    if (cmd == TIOCMIWAIT) {
        DECLARE_WAITQUEUE(wait, current);
        struct async_icount cnow;
        struct async_icount cprev;

        cprev = ztty->icount;
        while (1)
        {
            add_wait_queue(&ztty->wait, &wait);
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            remove_wait_queue(&ztty->wait, &wait);

            /* see if a signal woke us up */
            if (signal_pending(current))
                return -ERESTARTSYS;

            cnow = ztty->icount;
            if (cnow.rng == cprev.rng && cnow.dsr == cprev.dsr &&
                cnow.dcd == cprev.dcd && cnow.cts == cprev.cts)
                return -EIO; /* no change => error */
            if (((arg & TIOCM_RNG) && (cnow.rng != cprev.rng)) ||
                ((arg & TIOCM_DSR) && (cnow.dsr != cprev.dsr)) ||
                ((arg & TIOCM_CD)  && (cnow.dcd != cprev.dcd)) ||
                ((arg & TIOCM_CTS) && (cnow.cts != cprev.cts))) {
                return 0;
            }
            cprev = cnow;
        }

    }
    return -ENOIOCTLCMD;
}
#undef ztty_ioctl

#define ztty_ioctl ztty_ioctl_tiocgicount
static int ztty_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
    struct ztty_serial *ztty = tty->driver_data;

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    if (cmd == TIOCGICOUNT) {
        struct async_icount cnow = ztty->icount;
        struct serial_icounter_struct icount;

        icount.cts  = cnow.cts;
        icount.dsr  = cnow.dsr;
        icount.rng  = cnow.rng;
        icount.dcd  = cnow.dcd;
        icount.rx   = cnow.rx;
        icount.tx   = cnow.tx;
        icount.frame    = cnow.frame;
        icount.overrun  = cnow.overrun;
        icount.parity   = cnow.parity;
        icount.brk  = cnow.brk;
        icount.buf_overrun = cnow.buf_overrun;

        if (copy_to_user((void __user *)arg, &icount, sizeof(icount)))
            return -EFAULT;
        return 0;
    }
    return -ENOIOCTLCMD;
}
#undef ztty_ioctl

/* the real ztty_ioctl function.  The above is done to get the small functions in the book */
static int ztty_ioctl(struct tty_struct *tty, unsigned int cmd,
              unsigned long arg)
{
    switch (cmd) {
    case TIOCGSERIAL:
        return ztty_ioctl_tiocgserial(tty, cmd, arg);
    case TIOCMIWAIT:
        return ztty_ioctl_tiocmiwait(tty, cmd, arg);
    case TIOCGICOUNT:
        return ztty_ioctl_tiocgicount(tty, cmd, arg);
    }

    return -ENOIOCTLCMD;
}

static const struct tty_operations serial_ops = {
    .open           = ztty_open,
    .close          = ztty_close,
    .write          = ztty_write,
    .write_room     = ztty_write_room,
    .set_termios    = ztty_set_termios,
    .tiocmget       = ztty_tiocmget,
    .tiocmset       = tiny_tiocmset,
    .ioctl          = ztty_ioctl,
};

static struct tty_driver *ztty_driver;

static int __init tiny_init(void)
{
    int retval;
    int i;

    /* allocate the tty driver */
    ztty_driver = tty_alloc_driver(ZTTY_MINORS, \
                                        TTY_DRIVER_RESET_TERMIOS | \
                                        TTY_DRIVER_REAL_RAW | \
                                        TTY_DRIVER_DYNAMIC_DEV | \
                                        TTY_DRIVER_HARDWARE_BREAK);
    if (!ztty_driver)
        return -ENOMEM;

    /* initialize the tty driver */
    ztty_driver->owner = THIS_MODULE;
    ztty_driver->driver_name = "zboard_tty";
    ztty_driver->name = "ttyZ";
    ztty_driver->type = TTY_DRIVER_TYPE_SERIAL,
    ztty_driver->subtype = SERIAL_TYPE_NORMAL,
    ztty_driver->flags = TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV,
    ztty_driver->init_termios = tty_std_termios;
    ztty_driver->init_termios.c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL;

    tty_set_operations(ztty_driver, &serial_ops);

    for (i = 0; i < ZTTY_MINORS; i++)
    {
        tty_port_init(tiny_tty_port + i);
        tty_port_link_device(tiny_tty_port + i, ztty_driver, i);
    }

    /* register the tty driver */
    retval = tty_register_driver(ztty_driver);
    if (retval)
    {
        pr_debug("failed to register tiny tty driver");
        put_tty_driver(ztty_driver);
        return retval;
    }

    for (i = 0; i < ZTTY_MINORS; ++i)
        tty_register_device(ztty_driver, i, NULL);

    pr_debug("DEBUG:: %s - L: %d\n",__FUNCTION__, __LINE__);

    return retval;
}

static void __exit tiny_exit(void)
{
    struct ztty_serial *tiny;
    int i;

    for (i = 0; i < ZTTY_MINORS; ++i)
        tty_unregister_device(ztty_driver, i);
    tty_unregister_driver(ztty_driver);

    /* shut down all of the timers and free the memory */
    for (i = 0; i < ZTTY_MINORS; ++i)
    {
        tiny = tiny_table[i];
        if (tiny)
        {
            /* close the port */
            while (tiny->open_count)
                do_close(tiny);

            kfree(tiny);
            tiny_table[i] = NULL;
        }
    }
}

module_init(tiny_init);
module_exit(tiny_exit);
MODULE_LICENSE("GPL");

