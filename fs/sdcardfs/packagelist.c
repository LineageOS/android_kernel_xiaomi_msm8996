/*
 * fs/sdcardfs/packagelist.c
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd
 *   Authors: Daeho Jeong, Woojoong Lee, Seunghwan Hyun,
 *               Sunghwan Yun, Sungjong Seo
 *
 * This program has been developed as a stackable file system based on
 * the WrapFS which written by
 *
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009     Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This file is dual licensed.  It may be redistributed and/or modified
 * under the terms of the Apache 2.0 License OR version 2 of the GNU
 * General Public License.
 */

#include "sdcardfs.h"
#include <linux/hashtable.h>
#include <linux/delay.h>


#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/configfs.h>

struct hashtable_entry {
	struct hlist_node hlist;
	const char *key;
	atomic_t value;
};

static DEFINE_HASHTABLE(package_to_appid, 8);

static struct kmem_cache *hashtable_entry_cachep;

static unsigned int str_hash(const char *key) {
	int i;
	unsigned int h = strlen(key);
	char *data = (char *)key;

	for (i = 0; i < strlen(key); i++) {
		h = h * 31 + *data;
		data++;
	}
	return h;
}

appid_t get_appid(const char *app_name)
{
	struct hashtable_entry *hash_cur;
	unsigned int hash = str_hash(app_name);
	appid_t ret_id;

	rcu_read_lock();
	hash_for_each_possible_rcu(package_to_appid, hash_cur, hlist, hash) {
		if (!strcasecmp(app_name, hash_cur->key)) {
			ret_id = atomic_read(&hash_cur->value);
			rcu_read_unlock();
			return ret_id;
		}
	}
	rcu_read_unlock();
	return 0;
}

/* Kernel has already enforced everything we returned through
 * derive_permissions_locked(), so this is used to lock down access
 * even further, such as enforcing that apps hold sdcard_rw. */
int check_caller_access_to_name(struct inode *parent_node, const char* name) {

	/* Always block security-sensitive files at root */
	if (parent_node && SDCARDFS_I(parent_node)->perm == PERM_ROOT) {
		if (!strcasecmp(name, "autorun.inf")
			|| !strcasecmp(name, ".android_secure")
			|| !strcasecmp(name, "android_secure")) {
			return 0;
		}
	}

	/* Root always has access; access for any other UIDs should always
	 * be controlled through packages.list. */
	if (from_kuid(&init_user_ns, current_fsuid()) == 0) {
		return 1;
	}

	/* No extra permissions to enforce */
	return 1;
}

/* This function is used when file opening. The open flags must be
 * checked before calling check_caller_access_to_name() */
int open_flags_to_access_mode(int open_flags) {
	if((open_flags & O_ACCMODE) == O_RDONLY) {
		return 0; /* R_OK */
	} else if ((open_flags & O_ACCMODE) == O_WRONLY) {
		return 1; /* W_OK */
	} else {
		/* Probably O_RDRW, but treat as default to be safe */
		return 1; /* R_OK | W_OK */
	}
}

static struct hashtable_entry *alloc_packagelist_entry(const char *key,
		appid_t value)
{
	struct hashtable_entry *ret = kmem_cache_alloc(hashtable_entry_cachep,
			GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->key = kstrdup(key, GFP_KERNEL);
	if (!ret->key) {
		kmem_cache_free(hashtable_entry_cachep, ret);
		return NULL;
	}

	atomic_set(&ret->value, value);
	return ret;
}

static int insert_packagelist_entry_locked(const char *key, appid_t value)
{
	struct hashtable_entry *hash_cur;
	struct hashtable_entry *new_entry;
	unsigned int hash = str_hash(key);

	hash_for_each_possible_rcu(package_to_appid, hash_cur, hlist, hash) {
		if (!strcasecmp(key, hash_cur->key)) {
			atomic_set(&hash_cur->value, value);
			return 0;
		}
	}
	new_entry = alloc_packagelist_entry(key, value);
	if (!new_entry)
		return -ENOMEM;
	hash_add_rcu(package_to_appid, &new_entry->hlist, hash);
	return 0;
}

static void fixup_perms(struct super_block *sb, const char *key) {
	if (sb && sb->s_magic == SDCARDFS_SUPER_MAGIC) {
		fixup_perms_recursive(sb->s_root, key, strlen(key));
	}
}

static void fixup_all_perms(const char *key)
{
	struct sdcardfs_sb_info *sbinfo;
	list_for_each_entry(sbinfo, &sdcardfs_super_list, list)
		if (sbinfo)
			fixup_perms(sbinfo->sb, key);
}

static int insert_packagelist_entry(const char *key, appid_t value)
{
	int err;

	mutex_lock(&sdcardfs_super_list_lock);
	err = insert_packagelist_entry_locked(key, value);
	if (!err)
		fixup_all_perms(key);
	mutex_unlock(&sdcardfs_super_list_lock);

	return err;
}

static void free_packagelist_entry(struct hashtable_entry *entry)
{
	kfree(entry->key);
	hash_del_rcu(&entry->hlist);
	kmem_cache_free(hashtable_entry_cachep, entry);
}

static void remove_packagelist_entry_locked(const char *key)
{
	struct hashtable_entry *hash_cur;
	unsigned int hash = str_hash(key);

	hash_for_each_possible_rcu(package_to_appid, hash_cur, hlist, hash) {
		if (!strcasecmp(key, hash_cur->key)) {
			hash_del_rcu(&hash_cur->hlist);
			synchronize_rcu();
			free_packagelist_entry(hash_cur);
			return;
		}
	}
}

static void remove_packagelist_entry(const char *key)
{
	mutex_lock(&sdcardfs_super_list_lock);
	remove_packagelist_entry_locked(key);
	fixup_all_perms(key);
	mutex_unlock(&sdcardfs_super_list_lock);
	return;
}

static void packagelist_destroy(void)
{
	struct hashtable_entry *hash_cur;
	struct hlist_node *h_t;
	HLIST_HEAD(free_list);
	int i;
	mutex_lock(&sdcardfs_super_list_lock);
	hash_for_each_rcu(package_to_appid, i, hash_cur, hlist) {
		hash_del_rcu(&hash_cur->hlist);
		hlist_add_head(&hash_cur->hlist, &free_list);

	}
	synchronize_rcu();
	hlist_for_each_entry_safe(hash_cur, h_t, &free_list, hlist)
		free_packagelist_entry(hash_cur);
	mutex_unlock(&sdcardfs_super_list_lock);
	printk(KERN_INFO "sdcardfs: destroyed packagelist pkgld\n");
}

struct package_details {
	struct config_item item;
	const char* name;
};

static inline struct package_details *to_package_details(struct config_item *item)
{
	return item ? container_of(item, struct package_details, item) : NULL;
}

CONFIGFS_ATTR_STRUCT(package_details);
#define PACKAGE_DETAILS_ATTR(_name, _mode, _show, _store)	\
struct package_details_attribute package_details_attr_##_name = __CONFIGFS_ATTR(_name, _mode, _show, _store)

static ssize_t package_details_appid_show(struct package_details *package_details,
				      char *page)
{
	return scnprintf(page, PAGE_SIZE, "%u\n", get_appid(package_details->name));
}

static ssize_t package_details_appid_store(struct package_details *package_details,
				       const char *page, size_t count)
{
	unsigned int tmp;
	int ret;

	ret = kstrtouint(page, 10, &tmp);
	if (ret)
		return ret;

	ret = insert_packagelist_entry(package_details->name, tmp);

	if (ret)
		return ret;

	return count;
}

static void package_details_release(struct config_item *item)
{
	struct package_details *package_details = to_package_details(item);
	printk(KERN_INFO "sdcardfs: removing %s\n", package_details->name);
	remove_packagelist_entry(package_details->name);
	kfree(package_details->name);
	kfree(package_details);
}

PACKAGE_DETAILS_ATTR(appid, S_IRUGO | S_IWUGO, package_details_appid_show, package_details_appid_store);

static struct configfs_attribute *package_details_attrs[] = {
	&package_details_attr_appid.attr,
	NULL,
};

CONFIGFS_ATTR_OPS(package_details);
static struct configfs_item_operations package_details_item_ops = {
	.release = package_details_release,
	.show_attribute = package_details_attr_show,
	.store_attribute = package_details_attr_store,
};

static struct config_item_type package_appid_type = {
	.ct_item_ops	= &package_details_item_ops,
	.ct_attrs	= package_details_attrs,
	.ct_owner	= THIS_MODULE,
};

struct packages {
	struct configfs_subsystem subsystem;
};

static inline struct packages *to_packages(struct config_item *item)
{
	return item ? container_of(to_configfs_subsystem(to_config_group(item)), struct packages, subsystem) : NULL;
}

CONFIGFS_ATTR_STRUCT(packages);
#define PACKAGES_ATTR(_name, _mode, _show, _store)	\
struct packages_attribute packages_attr_##_name = __CONFIGFS_ATTR(_name, _mode, _show, _store)
#define PACKAGES_ATTR_RO(_name, _show)	\
struct packages_attribute packages_attr_##_name = __CONFIGFS_ATTR_RO(_name, _show);

static struct config_item *packages_make_item(struct config_group *group, const char *name)
{
	struct package_details *package_details;

	package_details = kzalloc(sizeof(struct package_details), GFP_KERNEL);
	if (!package_details)
		return ERR_PTR(-ENOMEM);
	package_details->name = kstrdup(name, GFP_KERNEL);
	if (!package_details->name)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&package_details->item, name,
				   &package_appid_type);

	return &package_details->item;
}

static ssize_t packages_list_show(struct packages *packages,
					 char *page)
{
	struct hashtable_entry *hash_cur;
	int i;
	int count = 0, written = 0;
	const char errormsg[] = "<truncated>\n";

	rcu_read_lock();
	hash_for_each_rcu(package_to_appid, i, hash_cur, hlist) {
		written = scnprintf(page + count, PAGE_SIZE - sizeof(errormsg) - count, "%s %d\n",
					(const char *)hash_cur->key, atomic_read(&hash_cur->value));
		if (count + written == PAGE_SIZE - sizeof(errormsg)) {
			count += scnprintf(page + count, PAGE_SIZE - count, errormsg);
			break;
		}
		count += written;
	}
	rcu_read_unlock();

	return count;
}

struct packages_attribute packages_attr_packages_gid_list = __CONFIGFS_ATTR_RO(packages_gid.list, packages_list_show);

static struct configfs_attribute *packages_attrs[] = {
	&packages_attr_packages_gid_list.attr,
	NULL,
};

CONFIGFS_ATTR_OPS(packages)
static struct configfs_item_operations packages_item_ops = {
	.show_attribute = packages_attr_show,
	.store_attribute = packages_attr_store,
};

/*
 * Note that, since no extra work is required on ->drop_item(),
 * no ->drop_item() is provided.
 */
static struct configfs_group_operations packages_group_ops = {
	.make_item	= packages_make_item,
};

static struct config_item_type packages_type = {
	.ct_item_ops	= &packages_item_ops,
	.ct_group_ops	= &packages_group_ops,
	.ct_attrs	= packages_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct packages sdcardfs_packages = {
	.subsystem = {
		.su_group = {
			.cg_item = {
				.ci_namebuf = "sdcardfs",
				.ci_type = &packages_type,
			},
		},
	},
};

static int configfs_sdcardfs_init(void)
{
	int ret;
	struct configfs_subsystem *subsys = &sdcardfs_packages.subsystem;

	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);
	ret = configfs_register_subsystem(subsys);
	if (ret) {
		printk(KERN_ERR "Error %d while registering subsystem %s\n",
		       ret,
		       subsys->su_group.cg_item.ci_namebuf);
	}
	return ret;
}

static void configfs_sdcardfs_exit(void)
{
	configfs_unregister_subsystem(&sdcardfs_packages.subsystem);
}

int packagelist_init(void)
{
	hashtable_entry_cachep =
		kmem_cache_create("packagelist_hashtable_entry",
					sizeof(struct hashtable_entry), 0, 0, NULL);
	if (!hashtable_entry_cachep) {
		printk(KERN_ERR "sdcardfs: failed creating pkgl_hashtable entry slab cache\n");
		return -ENOMEM;
	}

	configfs_sdcardfs_init();
        return 0;
}

void packagelist_exit(void)
{
	configfs_sdcardfs_exit();
	packagelist_destroy();
	if (hashtable_entry_cachep)
		kmem_cache_destroy(hashtable_entry_cachep);
}
