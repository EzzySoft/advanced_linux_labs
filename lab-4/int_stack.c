#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include "int_stack.h"

#define DEV_NAME "int_stack"

struct int_stack {
	int    *data;
	size_t  top;
	size_t  max;
	struct  mutex mtx;
};

static dev_t dev;
static struct cdev cdev_;
static struct class *cls;

static struct int_stack stack = {
	.data = NULL,
	.top  = 0,
	.max  = 0
};

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
                           const char __user *buf,
                           size_t len, loff_t *off)
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
                          char __user *buf,
                          size_t len, loff_t *off)
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


static struct file_operations fops = {
	.owner          = THIS_MODULE,
	.open           = stack_open,
	.release        = stack_release,
	.read           = stack_read,
	.write          = stack_write,
	.unlocked_ioctl = stack_ioctl,
};

static int __init stack_init(void)
{
	int ret;

	mutex_init(&stack.mtx);

	ret = alloc_chrdev_region(&dev, 0, 1, DEV_NAME);
	if (ret) return ret;

	cdev_init(&cdev_, &fops);
	cdev_.owner = THIS_MODULE;
	ret = cdev_add(&cdev_, dev, 1);
	if (ret) goto err_cdev;

	cls = class_create(DEV_NAME); 
	if (IS_ERR(cls)) { ret = PTR_ERR(cls); goto err_class; }

	device_create(cls, NULL, dev, NULL, DEV_NAME);
	pr_info("%s: major=%d minor=%d\n", DEV_NAME, MAJOR(dev), MINOR(dev));
	return 0;

err_class:
	cdev_del(&cdev_);
err_cdev:
	unregister_chrdev_region(dev, 1);
	return ret;
}

static void __exit stack_exit(void)
{
	device_destroy(cls, dev);
	class_destroy(cls);
	cdev_del(&cdev_);
	unregister_chrdev_region(dev, 1);
	kfree(stack.data);
}

module_init(stack_init);
module_exit(stack_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lab4");
MODULE_DESCRIPTION("integer stack chardev");
