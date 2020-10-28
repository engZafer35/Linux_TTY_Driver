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

#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>

#define ZTTY_MINORS (2) /* only 2 devices */

struct ztty_serial
{
	struct tty_struct   *tty;		/* pointer to the tty for this device */
	int                 open_count;	        /* number of times this port has been opened */
	struct mutex	    mutex;		/* locks this structure */
};

static struct ztty_serial *ztty_table[ZTTY_MINORS];	/* initially all NULL */
static struct tty_port    ztty_port[ZTTY_MINORS];

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

        do_sha256(ttyzBuff, ttyzCount, sha256Buff); //calculate sha256

        *p = '\n'; p++; *p = '\r'; p++; //new line,
        for (i = 0; i < 32; ++i)
        {
            if (((i%8) == 0) && i) {*p = '\n'; p++; *p = '\r'; p++;} //new line,
            sprintf(p, "0x%02x-", sha256Buff[i]);
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
	struct ztty_serial *ztty;
	int index;

	/* initialize the pointer in case something fails */
	tty->driver_data = NULL;

	/* get the serial object associated with this tty pointer */
	index = tty->index;
	ztty = ztty_table[index];
	if (ztty == NULL)
	{
		/* first time accessing this device, let's create it */
	    ztty = kmalloc(sizeof(*ztty), GFP_KERNEL);
		if (!ztty)
			return -ENOMEM;

		mutex_init(&ztty->mutex);
		ztty->open_count = 0;

		ztty_table[index] = ztty;
	}

	mutex_lock(&ztty->mutex);

	/* save our structure within the tty structure */
	tty->driver_data = ztty;
	ztty->tty = tty;

	pr_debug("DEBUG: ttyZ%d-%d  Opened \n", index, ztty->open_count);

	++ztty->open_count;
	if (ztty->open_count == 1)
	{
		/* this is the first time this port is opened */
		/* do any hardware initialization needed here */
	}

	mutex_unlock(&ztty->mutex);
	return 0;
}

static void do_close(struct ztty_serial *ztty)
{
	mutex_lock(&ztty->mutex);

	if (!ztty->open_count)
		goto exit;

	--ztty->open_count;
	if (ztty->open_count <= 0) {
		/* The port is being closed by the last user. */
		/* Do any hardware specific stuff here */
	}

	pr_debug("DEBUG: ttyZ%d-%d Closed\n", ztty->tty->index, ztty->open_count);
exit:
	mutex_unlock(&ztty->mutex);
}

static void ztty_close(struct tty_struct *tty, struct file *file)
{
	struct ztty_serial *ztty = tty->driver_data;

	if (ztty)
		do_close(ztty);
}

static int ztty_write(struct tty_struct *tty, const unsigned char *buffer, int count)
{
	struct ztty_serial *ztty = tty->driver_data;
	int retval = -EINVAL;

	if (!ztty)
		return -ENODEV;

	mutex_lock(&ztty->mutex);

	if (!ztty->open_count)
		goto exit;

    if (!tty_buffer_request_room(ztty->tty->port, 1))
        tty_flip_buffer_push(ztty->tty->port);

    tty_insert_flip_char(ztty->tty->port, buffer[0], TTY_NORMAL);
    tty_flip_buffer_push(ztty->tty->port);

	_print(buffer, count, ztty->tty->port);

exit:
	mutex_unlock(&ztty->mutex);
	return retval;
}

static int ztty_write_room(struct tty_struct *tty)
{
	struct ztty_serial *ztty = tty->driver_data;
	int room = -EINVAL;

	if (!ztty)
		return -ENODEV;

	mutex_lock(&ztty->mutex);

	if (!ztty->open_count) {
		/* port was not opened */
		goto exit;
	}

	/* calculate how much room is left in the device */
	room = 255;

exit:
	mutex_unlock(&ztty->mutex);
	return room;
}

static const struct tty_operations serial_ops = {
	.open  = ztty_open,
	.close = ztty_close,
	.write = ztty_write,
	.write_room = ztty_write_room,
};

static struct tty_driver *ztty_driver;

static int __init ztty_init(void)
{
	int retval;
	int i;

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
	ztty_driver->init_termios = tty_std_termios;
	ztty_driver->init_termios.c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL;

	tty_set_operations(ztty_driver, &serial_ops);

	for (i = 0; i < ZTTY_MINORS; i++)
	{
		tty_port_init(ztty_port + i);
		tty_port_link_device(ztty_port + i, ztty_driver, i);
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

    pr_debug("DEBUG:: ttyZ init Success \n");

	return retval;
}

static void __exit ztty_exit(void)
{
	struct ztty_serial *ztty;
	int i;

	for (i = 0; i < ZTTY_MINORS; ++i)
		tty_unregister_device(ztty_driver, i);
	tty_unregister_driver(ztty_driver);

	for (i = 0; i < ZTTY_MINORS; ++i)
	{
	    ztty = ztty_table[i];
		if (ztty) {
			while (ztty->open_count)
				do_close(ztty);

			kfree(ztty);
			ztty_table[i] = NULL;
		}
	}
}

module_init(ztty_init);
module_exit(ztty_exit);
MODULE_LICENSE("GPL");

