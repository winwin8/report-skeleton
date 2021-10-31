#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("WTFPL");
MODULE_AUTHOR("Dmitrii Medvedev");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.1");

ssize_t input_char_len = 0;
char *input_buff;

static struct proc_dir_entry* entry;

static ssize_t proc_write(struct file *file, const char __user * ubuf, size_t count, loff_t* ppos) 
{
	//printk(KERN_DEBUG "Attempt to write proc file");

        int len;
        len = count;
 
        copy_from_user(input_buff, ubuf, len);
        input_char_len += count - 1;
        printk(KERN_DEBUG "var1- all input count:%ld \n", input_char_len);        

        return len;
}

static ssize_t proc_read(struct file *file, char __user * ubuf, size_t count, loff_t* ppos) 
{
    int len = strlen(input_buff);
	if (*ppos > 0 || count < len)
	{
		return 0;
	}
	if (copy_to_user(ubuf, input_buff, input_char_len) != 0)
	{
		return -EFAULT;
	}
    printk(KERN_DEBUG "varN- read info:%s \n", input_buff); 
	*ppos = len;
	return len;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write,
};


static int __init proc_example_init(void)
{
    input_buff = (char*)kmalloc(1024, GFP_KERNEL);
    input_char_len = 0;
    memset(input_buff, 0, 1024);

	entry = proc_create("var1", 0666, NULL, &fops);
	printk(KERN_INFO "%s: proc file is created\n", THIS_MODULE->name);
	return 0;
}

static void __exit proc_example_exit(void)
{
    kfree(input_buff);
	proc_remove(entry);
	printk(KERN_INFO "%s: proc file is deleted\n", THIS_MODULE->name);
}

module_init(proc_example_init);
module_exit(proc_example_exit);


