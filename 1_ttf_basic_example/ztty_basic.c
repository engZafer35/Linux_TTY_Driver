#include <linux/device.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/module.h>
#include <linux/tty_flip.h>

#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>

struct ztty_port {
    struct tty_port port;
};

static struct ztty_port tpk_port;

/*
 * Our simple preformatting supports transparent output of (time-stamped)
 * printk messages (also suitable for logging service):
 * - any cr is replaced by nl
 * - adds a ttyprintk source tag in front of each line
 * - too long message is fragmented, with '\'nl between fragments
 * - TPK_STR_SIZE isn't really the write_room limiting factor, because
 *   it is emptied on the fly during preformatting.
 */
#define ZTYY_STR_SIZE 508 /* should be bigger then max expected line length */
#define ZTTY_MAX_ROOM 1024

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

static void ztty_flush(void)
{
    if (ttyzCount > 0)
    {
        ttyzBuff[ttyzCount] = '\0';

        do_sha256(ttyzBuff, ttyzCount, sha256Buff);

            printk(KERN_INFO "SHA256(%s, %i)", ttyzBuff, ttyzCount);

            printk(KERN_INFO "%02x%02x%02x%02x%02x%02x%02x%02x",
                  sha256Buff[0], sha256Buff[1], sha256Buff[2], sha256Buff[3], sha256Buff[4],
                  sha256Buff[5], sha256Buff[6], sha256Buff[7]);

            printk(KERN_INFO "%02x%02x%02x%02x%02x%02x%02x%02x",
                  sha256Buff[8], sha256Buff[9], sha256Buff[10], sha256Buff[11], sha256Buff[12],
                  sha256Buff[13], sha256Buff[14], sha256Buff[15]);

            printk(KERN_INFO "%02x%02x%02x%02x%02x%02x%02x%02x",
                  sha256Buff[16], sha256Buff[17], sha256Buff[18], sha256Buff[19], sha256Buff[20],
                  sha256Buff[21], sha256Buff[22], sha256Buff[23]);

            printk(KERN_INFO "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                  sha256Buff[24], sha256Buff[25], sha256Buff[26], sha256Buff[27], sha256Buff[28],
                  sha256Buff[29], sha256Buff[30], sha256Buff[31]);

        ttyzCount = 0;
    }
}

static int _print(const unsigned char *buf, int count)
{
    int i = ttyzCount;

    if (buf == NULL) {
        ztty_flush();
        return i;
    }

    //pr_debug("Z-TTY: _print: %c %d \n", buf[0], count);

    for (i = 0; i < count; i++) {
        if (ttyzCount >= ZTTY_MAX_ROOM) {
            /* end of tmp buffer reached: cut the message in two */
            ttyzBuff[ttyzCount++] = '\\';
            ztty_flush();
        }

        switch (buf[i]) {
            case '\r':
                ztty_flush();
                if ((i + 1) < count && buf[i + 1] == '\n')
                    i++;
                break;
            case '\n':
                ztty_flush();
                break;
            default:
                ttyzBuff[ttyzCount++] = buf[i];
                break;
        }
    }

    return count;
}

/** TTY operations open function.*/
static int ztty_open(struct tty_struct *tty, struct file *filp)
{
    int ret;
    tty->driver_data = &tpk_port;

    ret = tty_port_open(&tpk_port.port, tty, filp);
    pr_debug("Z-TTY: Open ret %d !!\n", ret);

    return ret;
}

/** TTY operations close function.*/
static void ztty_close(struct tty_struct *tty, struct file *filp)
{
    struct ztty_port *tpkp = tty->driver_data;

    _print(NULL, 0);
    tty_port_close(&tpkp->port, tty, filp);
    pr_debug("Z-TTY: CLOSED \n");
}

/** TTY operations write function.*/
static int ztty_write(struct tty_struct *tty,
        const unsigned char *buf, int count)
{
    return _print(buf, count);
}
/** TTY operations write_room function. */
static int ztty_write_room(struct tty_struct *tty)
{
    return ZTTY_MAX_ROOM;
}

/** TTY operations ioctl function. */
static int ztty_ioctl(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg)
{
    //pr_debug("Z-TTY: IOCTL cmd %d !!\n", cmd);
    return 0;
}

static const struct tty_operations ztty_ops = {
    .open       = ztty_open,
    .close      = ztty_close,
    .write      = ztty_write,
    .write_room = ztty_write_room,
    .ioctl      = ztty_ioctl,
};

static const struct tty_port_operations null_ops = { };
static struct tty_driver *driver;

static int __init ztty_init(void)
{
    int ret;

    driver = tty_alloc_driver(1,
            TTY_DRIVER_RESET_TERMIOS |
            TTY_DRIVER_REAL_RAW |
            TTY_DRIVER_UNNUMBERED_NODE);
    if (IS_ERR(driver))
        return PTR_ERR(driver);

    tty_port_init(&tpk_port.port);
    tpk_port.port.ops = &null_ops;

    driver->driver_name = "zboard_ttyy";
    driver->name = "ttyz";
    driver->type = TTY_DRIVER_TYPE_SERIAL;
    driver->init_termios = tty_std_termios;
    driver->init_termios.c_oflag = OPOST | OCRNL | ONOCR | ONLRET;

    tty_set_operations(driver, &ztty_ops);
    tty_port_link_device(&tpk_port.port, driver, 0);

    ret = tty_register_driver(driver);
    if (ret < 0) {
        printk(KERN_ERR "Couldn't register ttyz driver %d \n", ret);
        goto error;
    }

    pr_debug("Z-TTY: init SUCCESS \n");
    return 0;

error:
    put_tty_driver(driver);
    tty_port_destroy(&tpk_port.port);
    return ret;
}

static void __exit ztty_exit(void)
{
    tty_unregister_driver(driver);
    put_tty_driver(driver);
    tty_port_destroy(&tpk_port.port);
}

module_init(ztty_init);
module_exit(ztty_exit);

MODULE_LICENSE("GPL");
