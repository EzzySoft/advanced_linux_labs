#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/usb.h>
#include "int_stack.h"

#define DEV_NAME "int_stack"

#ifndef DEFAULT_USB_VID
#define DEFAULT_USB_VID  0x31B2
#endif
#ifndef DEFAULT_USB_PID
#define DEFAULT_USB_PID  0x5075
#endif

struct int_stack {
        int    *data;
        size_t  top;
        size_t  max;
        struct  mutex mtx;
};

static struct int_stack stack = { .data = NULL, .top = 0, .max = 0 };

static dev_t           dev_id;
static struct cdev     cdev_;
static struct class   *cls;
static bool            dev_visible;

static int stack_open(struct inode *inode, struct file *filp)
{
        try_module_get(THIS_MODULE);
        return 0;
}

static int stack_release(struct inode *inode, struct file *filp)
{
        module_put(THIS_MODULE);
        return 0;
}

static ssize_t stack_write(struct file *filp,
                           const char __user *buf, size_t len, loff_t *off)
{
        int value;
        if (len < sizeof(int))
                return -EINVAL;

        if (copy_from_user(&value, buf, sizeof(int)))
                return -EFAULT;

        mutex_lock(&stack.mtx);
        if (stack.top >= stack.max) {
                mutex_unlock(&stack.mtx);
                return -ERANGE;
        }
        stack.data[stack.top++] = value;
        mutex_unlock(&stack.mtx);
        return sizeof(int);
}

static ssize_t stack_read(struct file *filp,
                          char __user *buf, size_t len, loff_t *off)
{
        int value;
        if (len < sizeof(int))
                return -EINVAL;

        mutex_lock(&stack.mtx);
        if (stack.top == 0) {
                mutex_unlock(&stack.mtx);
                return 0;
        }
        value = stack.data[--stack.top];
        mutex_unlock(&stack.mtx);

        if (copy_to_user(buf, &value, sizeof(int)))
                return -EFAULT;
        return sizeof(int);
}

static long stack_ioctl(struct file *filp,
                        unsigned int cmd, unsigned long arg)
{
        int new_size;
        int *new_buf;

        if (cmd != INT_STACK_SET_SIZE)
                return -ENOTTY;

        if (copy_from_user(&new_size, (int __user *)arg, sizeof(int)))
                return -EFAULT;

        if (new_size <= 0)
                return -EINVAL;

        mutex_lock(&stack.mtx);

        new_buf = krealloc(stack.data, new_size * sizeof(int), GFP_KERNEL);
        if (!new_buf) {
                mutex_unlock(&stack.mtx);
                return -ENOMEM;
        }
        stack.data = new_buf;
        stack.max  = new_size;
        stack.top  = 0;

        mutex_unlock(&stack.mtx);
        return 0;
}

static const struct file_operations fops = {
        .owner          = THIS_MODULE,
        .open           = stack_open,
        .release        = stack_release,
        .read           = stack_read,
        .write          = stack_write,
        .unlocked_ioctl = stack_ioctl,
};

static int stack_dev_create(void)
{
        int ret;

        if (dev_visible)
                return 0;

        ret = alloc_chrdev_region(&dev_id, 0, 1, DEV_NAME);
        if (ret)
                return ret;

        cdev_init(&cdev_, &fops);
        cdev_.owner = THIS_MODULE;
        ret = cdev_add(&cdev_, dev_id, 1);
        if (ret)
                goto err_cdev;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
        cls = class_create(THIS_MODULE, DEV_NAME);
#else
        cls = class_create(DEV_NAME);
#endif
        if (IS_ERR(cls)) {
                ret = PTR_ERR(cls);
                goto err_class;
        }

        device_create(cls, NULL, dev_id, NULL, DEV_NAME);
        dev_visible = true;
        pr_info("int_stack: /dev/%s created\n", DEV_NAME);
        return 0;

err_class:
        cdev_del(&cdev_);
err_cdev:
        unregister_chrdev_region(dev_id, 1);
        return ret;
}

static void stack_dev_destroy(void)
{
        if (!dev_visible)
                return;

        device_destroy(cls, dev_id);
        class_destroy(cls);
        cdev_del(&cdev_);
        unregister_chrdev_region(dev_id, 1);
        dev_visible = false;
        pr_info("int_stack: /dev/%s removed (stack data preserved)\n", DEV_NAME);
}

static const struct usb_device_id key_table[] = {
        { USB_DEVICE(DEFAULT_USB_VID, DEFAULT_USB_PID) },
        { }
};
MODULE_DEVICE_TABLE(usb, key_table);

static int key_probe(struct usb_interface *intf,
                     const struct usb_device_id *id)
{
        pr_info("int_stack: USB key %04X:%04X inserted\n",
                id->idVendor, id->idProduct);
        return stack_dev_create();
}

static void key_disconnect(struct usb_interface *intf)
{
        pr_info("int_stack: USB key removed\n");
        stack_dev_destroy();
}

static struct usb_driver key_driver = {
        .name       = "int_stack_usb_key",
        .probe      = key_probe,
        .disconnect = key_disconnect,
        .id_table   = key_table,
};

static int __init mod_init(void)
{
        mutex_init(&stack.mtx);
        return usb_register(&key_driver);
}

static void __exit mod_exit(void)
{
        usb_deregister(&key_driver);
        stack_dev_destroy();
        kfree(stack.data);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lab5");
MODULE_DESCRIPTION("integer stack chardev protected by USB key");
