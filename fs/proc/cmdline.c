#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/setup.h>

static char new_command_line[COMMAND_LINE_SIZE];

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", new_command_line);
	return 0;
}

static int cmdline_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
	.open		= cmdline_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_cmdline_init(void)
{
	char *offset_addr, *cmd = new_command_line;

	strcpy(cmd, saved_command_line);

	offset_addr = strstr(cmd, "androidboot.mode=usb_chg");
	if (offset_addr) {
		size_t i, len, offset;
		len = strlen(cmd);
		offset = offset_addr - cmd;
		for (i = 1; i < (len - offset); i++) {
			if (cmd[offset + i] == ' ')
				break;
		}
		memmove(offset_addr, &cmd[offset + i + 1], len - i - offset);

		strcat(cmd, " androidboot.mode=charger");
	} else {
		if (strstr(cmd, "androidboot.bootreason=usb_chg")) {
			strcat(cmd, " androidboot.mode=charger");
		}
	}

	proc_create("cmdline", 0, NULL, &cmdline_proc_fops);
	return 0;
}
fs_initcall(proc_cmdline_init);
