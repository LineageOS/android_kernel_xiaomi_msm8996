/*
 * zsmalloc memory allocator
 *
 * Copyright (C) 2011  Nitin Gupta
 * Copyright (C) 2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the license that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 */

/*
 * Following is how we use various fields and flags of underlying
 * struct page(s) to form a zspage.
 *
 * Usage of struct page fields:
 *	page->first_page: points to the first component (0-order) page
 *	page->index (union with page->freelist): offset of the first object
 *		starting in this page.
 *	page->lru: links together all component pages (except the first page)
 *		of a zspage
 *
 *	For _first_ page only:
 *
 *	page->private (union with page->first_page): refers to the
 *		component page after the first page
 *		If the page is first_page for huge object, it stores handle.
 *		Look at size_class->huge.
 *	page->lru: links together first pages of various zspages.
 *		Basically forming list of zspages in a fullness group.
 *	page->freelist: override by struct zs_meta
 *	page->mapping: address space operations for page migration
 *
 * Usage of struct page flags:
 *	PG_private: identifies the first component page
 *	PG_private2: identifies the last component page
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/vmalloc.h>
#include <linux/hardirq.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/migrate.h>
#include <linux/compaction.h>
#include <linux/zsmalloc.h>
#include <linux/zpool.h>

/*
 * This must be power of 2 and greater than of equal to sizeof(link_free).
 * These two conditions ensure that any 'struct link_free' itself doesn't
 * span more than 1 page which avoids complex case of mapping 2 pages simply
 * to restore link_free pointer values.
 */
#define ZS_ALIGN		8

/*
 * A single 'zspage' is composed of up to 2^N discontiguous 0-order (single)
 * pages. ZS_MAX_ZSPAGE_ORDER defines upper limit on N.
 */
#define ZS_MAX_ZSPAGE_ORDER 2
#define ZS_MAX_PAGES_PER_ZSPAGE (_AC(1, UL) << ZS_MAX_ZSPAGE_ORDER)

#define ZS_HANDLE_SIZE (sizeof(unsigned long))

/*
 * Object location (<PFN>, <obj_idx>) is encoded as
 * as single (unsigned long) handle value.
 *
 * Note that object index <obj_idx> is relative to system
 * page <PFN> it is stored in, so for each sub-page belonging
 * to a zspage, obj_idx starts with 0.
 *
 * This is made more complicated by various memory models and PAE.
 */

#ifndef MAX_PHYSMEM_BITS
#ifdef CONFIG_HIGHMEM64G
#define MAX_PHYSMEM_BITS 36
#else /* !CONFIG_HIGHMEM64G */
/*
 * If this definition of MAX_PHYSMEM_BITS is used, OBJ_INDEX_BITS will just
 * be PAGE_SHIFT
 */
#define MAX_PHYSMEM_BITS BITS_PER_LONG
#endif
#endif
#define _PFN_BITS		(MAX_PHYSMEM_BITS - PAGE_SHIFT)

/*
 * Memory for allocating for handle keeps object position by
 * encoding <page, obj_idx> and the encoded value has a room
 * in least bit(ie, look at obj_to_location).
 * We use the bit to synchronize between object access by
 * user and migration.
 */
#define HANDLE_PIN_BIT	0

/*
 * Head in allocated object should have OBJ_ALLOCATED_TAG
 * to identify the object was allocated or not.
 * It's okay to add the status bit in the least bit because
 * header keeps handle which is 4byte-aligned address so we
 * have room for two bit at least.
 */
#define OBJ_ALLOCATED_TAG 1
#define OBJ_TAG_BITS 1
#define OBJ_INDEX_BITS	(BITS_PER_LONG - _PFN_BITS - OBJ_TAG_BITS)
#define OBJ_INDEX_MASK	((_AC(1, UL) << OBJ_INDEX_BITS) - 1)

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
/* ZS_MIN_ALLOC_SIZE must be multiple of ZS_ALIGN */
#define ZS_MIN_ALLOC_SIZE \
	MAX(32, (ZS_MAX_PAGES_PER_ZSPAGE << PAGE_SHIFT >> OBJ_INDEX_BITS))
/* each chunk includes extra space to keep handle */
#define ZS_MAX_ALLOC_SIZE	PAGE_SIZE

#define FREE_OBJ_IDX_BITS 11
#define FREE_OBJ_IDX_MASK ((1 << FREE_OBJ_IDX_BITS) - 1)
#define CLASS_IDX_BITS	8
#define CLASS_IDX_MASK	((1 << CLASS_IDX_BITS) - 1)
#define FULLNESS_BITS	2
#define FULLNESS_MASK	((1 << FULLNESS_BITS) - 1)
#define INUSE_BITS	11
#define INUSE_MASK	((1 << INUSE_BITS) - 1)
#define ETC_BITS	(BITS_PER_LONG - FREE_OBJ_IDX_BITS - \
			CLASS_IDX_BITS - FULLNESS_BITS - INUSE_BITS)
/*
 * On systems with 4K page size, this gives 255 size classes! There is a
 * trader-off here:
 *  - Large number of size classes is potentially wasteful as free page are
 *    spread across these classes
 *  - Small number of size classes causes large internal fragmentation
 *  - Probably its better to use specific size classes (empirically
 *    determined). NOTE: all those class sizes must be set as multiple of
 *    ZS_ALIGN to make sure link_free itself never has to span 2 pages.
 *
 *  ZS_MIN_ALLOC_SIZE and ZS_SIZE_CLASS_DELTA must be multiple of ZS_ALIGN
 *  (reason above)
 */
#define ZS_SIZE_CLASS_DELTA	(PAGE_SIZE >> CLASS_IDX_BITS)

#define PAGE_ISOLATED_BIT	0


/*
 * We do not maintain any list for completely empty or full pages
 * Don't reorder.
 */
enum fullness_group {
	ZS_ALMOST_FULL = 0,
	ZS_ALMOST_EMPTY,
	ZS_EMPTY,
	ZS_FULL
};

enum zs_stat_type {
	OBJ_ALLOCATED,
	OBJ_USED,
	CLASS_ALMOST_FULL,
	CLASS_ALMOST_EMPTY,
	PAGES_MOVED,
	ABORTED_ISOLATES,
	NR_ZS_STAT_TYPE,
};

struct zs_size_stat {
	unsigned long objs[NR_ZS_STAT_TYPE];
};

#ifdef CONFIG_ZSMALLOC_STAT
static struct dentry *zs_stat_root;
#endif

/*
 * number of size_classes
 */
static int zs_size_classes;

/*
 * We assign a page to ZS_ALMOST_EMPTY fullness group when:
 *	n <= N / f, where
 * n = number of allocated objects
 * N = total number of objects zspage can store
 * f = fullness_threshold_frac
 *
 * Similarly, we assign zspage to:
 *	ZS_ALMOST_FULL	when n > N / f
 *	ZS_EMPTY	when n == 0
 *	ZS_FULL		when n == N
 *
 * (see: fix_fullness_group())
 */
static const int fullness_threshold_frac = 4;

struct zs_pool;
struct size_class {
	spinlock_t lock;
	struct zs_pool *pool;
	struct page *fullness_list[ZS_EMPTY];
	/*
	 * Size of objects stored in this class. Must be multiple
	 * of ZS_ALIGN.
	 */
	int size;
	int max_objects;
	unsigned int index;

	/* Number of PAGE_SIZE sized pages to combine to form a 'zspage' */
	int pages_per_zspage;
	struct zs_size_stat stats;

	/* huge object: pages_per_zspage == 1 && maxobj_per_zspage == 1 */
	bool huge;
};

/*
 * Placed within free objects to form a singly linked list.
 * For every zspage, first_page->free_obj_idx gives head of this list.
 *
 * This must be power of 2 and less than or equal to ZS_ALIGN
 */
struct link_free {
	union {
		/* Next free object index from first page */
		unsigned long next;
		/*
		 * Handle of allocated object.
		 */
		unsigned long handle;
	};
};

struct zs_pool {
	char *name;

	struct size_class **size_class;
	struct kmem_cache *handle_cachep;

	gfp_t flags;	/* allocation flags used when growing pool */
	atomic_long_t pages_allocated;

	struct zs_pool_stats stats;

	/* Compact classes */
	struct shrinker shrinker;
	/*
	 * To signify that register_shrinker() was successful
	 * and unregister_shrinker() will not Oops.
	 */
	bool shrinker_enabled;

	/* Anonymous inode to populate page migration mapping hooks into. */
	struct inode *inode;
#ifdef CONFIG_ZSMALLOC_STAT
	struct dentry *stat_dentry;
#endif
};

/*
 * In this implementation, a free_idx, zspage's class index, fullness group,
 * inuse object count are encoded in its (first)page->freelist
 * sizeof(struct zs_meta) should be equal to sizeof(unsigned long).
 */
struct zs_meta {
	unsigned long free_idx:FREE_OBJ_IDX_BITS;
	unsigned long class_idx:CLASS_IDX_BITS;
	unsigned long fullness:FULLNESS_BITS;
	unsigned long inuse:INUSE_BITS;
#if ETC_BITS > 0
	unsigned long etc:ETC_BITS;
#endif
};

struct mapping_area {
#ifdef CONFIG_PGTABLE_MAPPING
	struct vm_struct *vm; /* vm area for mapping object that span pages */
#else
	char *vm_buf; /* copy buffer for objects that span pages */
#endif
	char *vm_addr; /* address of kmap_atomic()'ed pages */
	enum zs_mapmode vm_mm; /* mapping mode */
	bool huge;
};

static int create_handle_cache(struct zs_pool *pool)
{
	pool->handle_cachep = kmem_cache_create("zs_handle", ZS_HANDLE_SIZE,
					0, 0, NULL);
	return pool->handle_cachep ? 0 : 1;
}

static void destroy_handle_cache(struct zs_pool *pool)
{
	kmem_cache_destroy(pool->handle_cachep);
}

static unsigned long alloc_handle(struct zs_pool *pool)
{
	return (unsigned long)kmem_cache_alloc(pool->handle_cachep,
		pool->flags & ~__GFP_HIGHMEM);
}

static void free_handle(struct zs_pool *pool, unsigned long handle)
{
	kmem_cache_free(pool->handle_cachep, (void *)handle);
}

static void record_obj(unsigned long handle, unsigned long obj)
{
	/*
	 * lsb of @obj represents handle lock while other bits
	 * represent object value the handle is pointing so
	 * updating shouldn't do store tearing.
	 */
	WRITE_ONCE(*(unsigned long *)handle, obj);
}

/* zpool driver */

#ifdef CONFIG_ZPOOL

static void *zs_zpool_create(char *name, gfp_t gfp,
			     const struct zpool_ops *zpool_ops,
			     struct zpool *zpool)
{
	return zs_create_pool(name, gfp);
}

static void zs_zpool_destroy(void *pool)
{
	zs_destroy_pool(pool);
}

static int zs_zpool_malloc(void *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	*handle = zs_malloc(pool, size);
	return *handle ? 0 : -1;
}
static void zs_zpool_free(void *pool, unsigned long handle)
{
	zs_free(pool, handle);
}

static int zs_zpool_shrink(void *pool, unsigned int pages,
			unsigned int *reclaimed)
{
	return -EINVAL;
}

static void *zs_zpool_map(void *pool, unsigned long handle,
			enum zpool_mapmode mm)
{
	enum zs_mapmode zs_mm;

	switch (mm) {
	case ZPOOL_MM_RO:
		zs_mm = ZS_MM_RO;
		break;
	case ZPOOL_MM_WO:
		zs_mm = ZS_MM_WO;
		break;
	case ZPOOL_MM_RW: /* fallthru */
	default:
		zs_mm = ZS_MM_RW;
		break;
	}

	return zs_map_object(pool, handle, zs_mm);
}
static void zs_zpool_unmap(void *pool, unsigned long handle)
{
	zs_unmap_object(pool, handle);
}

static u64 zs_zpool_total_size(void *pool)
{
	return zs_get_total_pages(pool) << PAGE_SHIFT;
}

static struct zpool_driver zs_zpool_driver = {
	.type =		"zsmalloc",
	.owner =	THIS_MODULE,
	.create =	zs_zpool_create,
	.destroy =	zs_zpool_destroy,
	.malloc =	zs_zpool_malloc,
	.free =		zs_zpool_free,
	.shrink =	zs_zpool_shrink,
	.map =		zs_zpool_map,
	.unmap =	zs_zpool_unmap,
	.total_size =	zs_zpool_total_size,
};

MODULE_ALIAS("zpool-zsmalloc");
#endif /* CONFIG_ZPOOL */

static unsigned int get_maxobj_per_zspage(int size, int pages_per_zspage)
{
	return pages_per_zspage * PAGE_SIZE / size;
}

/* per-cpu VM mapping areas for zspage accesses that cross page boundaries */
static DEFINE_PER_CPU(struct mapping_area, zs_map_area);

static int is_first_page(struct page *page)
{
	return PagePrivate(page);
}

static int is_last_page(struct page *page)
{
	return PagePrivate2(page);
}

static int get_inuse_obj(struct page *page)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(page));

	m = (struct zs_meta *)&page->freelist;

	return m->inuse;
}

static void set_inuse_obj(struct page *page, int inc)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(page));

	m = (struct zs_meta *)&page->freelist;
	m->inuse += inc;
}

static void set_free_obj_idx(struct page *first_page, int idx)
{
	struct zs_meta *m = (struct zs_meta *)&first_page->freelist;

	m->free_idx = idx;
}

static unsigned long get_free_obj_idx(struct page *first_page)
{
	struct zs_meta *m = (struct zs_meta *)&first_page->freelist;

	return m->free_idx;
}

static void get_zspage_meta(struct page *page, unsigned int *class_idx,
				enum fullness_group *fullness)
{
	struct zs_meta *m;
	BUG_ON(!is_first_page(page));

	m = (struct zs_meta *)&page->freelist;
	*fullness = m->fullness;
	*class_idx = m->class_idx;
}

static void set_zspage_meta(struct page *page, unsigned int class_idx,
				enum fullness_group fullness)
{
	struct zs_meta *m;

	BUG_ON(!is_first_page(page));

	BUG_ON(class_idx >= (1 << CLASS_IDX_BITS));
	BUG_ON(fullness >= (1 << FULLNESS_BITS));

	m = (struct zs_meta *)&page->freelist;
	m->fullness = fullness;
	m->class_idx = class_idx;
}

/*
 * zsmalloc divides the pool into various size classes where each
 * class maintains a list of zspages where each zspage is divided
 * into equal sized chunks. Each allocation falls into one of these
 * classes depending on its size. This function returns index of the
 * size class which has chunk size big enough to hold the give size.
 */
static int get_size_class_index(int size)
{
	int idx = 0;

	if (likely(size > ZS_MIN_ALLOC_SIZE))
		idx = DIV_ROUND_UP(size - ZS_MIN_ALLOC_SIZE,
				ZS_SIZE_CLASS_DELTA);

	return min(zs_size_classes - 1, idx);
}

static inline void zs_stat_inc(struct size_class *class,
				enum zs_stat_type type, unsigned long cnt)
{
	class->stats.objs[type] += cnt;
}

static inline void zs_stat_dec(struct size_class *class,
				enum zs_stat_type type, unsigned long cnt)
{
	class->stats.objs[type] -= cnt;
}

static inline unsigned long zs_stat_get(struct size_class *class,
				enum zs_stat_type type)
{
	return class->stats.objs[type];
}

#ifdef CONFIG_ZSMALLOC_STAT

static int __init zs_stat_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zs_stat_root = debugfs_create_dir("zsmalloc", NULL);
	if (!zs_stat_root)
		return -ENOMEM;

	return 0;
}

static void __exit zs_stat_exit(void)
{
	debugfs_remove_recursive(zs_stat_root);
}

static int zs_stats_size_show(struct seq_file *s, void *v)
{
	int i;
	struct zs_pool *pool = s->private;
	struct size_class *class;
	int objs_per_zspage;
	unsigned long class_almost_full, class_almost_empty;
	unsigned long obj_allocated, obj_used, pages_used, pages_moved, aborts;
	unsigned long total_class_almost_full = 0, total_class_almost_empty = 0;
	unsigned long total_objs = 0, total_used_objs = 0, total_pages = 0;
	unsigned long total_moved = 0, total_aborts = 0;

	seq_printf(s, " %5s %5s %11s %12s %13s %10s %10s %10s %10s %16s\n",
			"class", "size", "almost_full", "almost_empty",
			"obj_allocated", "obj_used", "pages_used",
			"pg_moved", "aborts", "pages_per_zspage");

	for (i = 0; i < zs_size_classes; i++) {
		class = pool->size_class[i];

		if (class->index != i)
			continue;

		spin_lock(&class->lock);
		class_almost_full = zs_stat_get(class, CLASS_ALMOST_FULL);
		class_almost_empty = zs_stat_get(class, CLASS_ALMOST_EMPTY);
		obj_allocated = zs_stat_get(class, OBJ_ALLOCATED);
		obj_used = zs_stat_get(class, OBJ_USED);
		pages_moved = zs_stat_get(class, PAGES_MOVED);
		aborts = zs_stat_get(class, ABORTED_ISOLATES);
		spin_unlock(&class->lock);

		objs_per_zspage = get_maxobj_per_zspage(class->size,
				class->pages_per_zspage);
		pages_used = obj_allocated / objs_per_zspage *
				class->pages_per_zspage;

		seq_printf(s, " %5u %5u %11lu %12lu %13lu %10lu %10lu %10lu %10lu %16d\n",
			i, class->size, class_almost_full, class_almost_empty,
			obj_allocated, obj_used, pages_used,
			pages_moved, aborts, class->pages_per_zspage);

		total_class_almost_full += class_almost_full;
		total_class_almost_empty += class_almost_empty;
		total_objs += obj_allocated;
		total_used_objs += obj_used;
		total_pages += pages_used;
		total_moved += pages_moved;
		total_aborts += aborts;
	}

	seq_puts(s, "\n");
	seq_printf(s, " %5s %5s %11lu %12lu %13lu %10lu %10lu %10lu %10lu\n",
			"Total", "", total_class_almost_full,
			total_class_almost_empty, total_objs,
			total_used_objs, total_pages, total_moved,
			total_aborts);

	return 0;
}

static int zs_stats_size_open(struct inode *inode, struct file *file)
{
	return single_open(file, zs_stats_size_show, inode->i_private);
}

static const struct file_operations zs_stat_size_ops = {
	.open           = zs_stats_size_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int zs_pool_stat_create(char *name, struct zs_pool *pool)
{
	struct dentry *entry;

	if (!zs_stat_root)
		return -ENODEV;

	entry = debugfs_create_dir(name, zs_stat_root);
	if (!entry) {
		pr_warn("debugfs dir <%s> creation failed\n", name);
		return -ENOMEM;
	}
	pool->stat_dentry = entry;

	entry = debugfs_create_file("classes", S_IFREG | S_IRUGO,
			pool->stat_dentry, pool, &zs_stat_size_ops);
	if (!entry) {
		pr_warn("%s: debugfs file entry <%s> creation failed\n",
				name, "classes");
		return -ENOMEM;
	}

	return 0;
}

static void zs_pool_stat_destroy(struct zs_pool *pool)
{
	debugfs_remove_recursive(pool->stat_dentry);
}

#else /* CONFIG_ZSMALLOC_STAT */
static int __init zs_stat_init(void)
{
	return 0;
}

static void __exit zs_stat_exit(void)
{
}

static inline int zs_pool_stat_create(char *name, struct zs_pool *pool)
{
	return 0;
}

static inline void zs_pool_stat_destroy(struct zs_pool *pool)
{
}
#endif


/*
 * For each size class, zspages are divided into different groups
 * depending on how "full" they are. This was done so that we could
 * easily find empty or nearly empty zspages when we try to shrink
 * the pool (not yet implemented). This function returns fullness
 * status of the given page.
 */
static enum fullness_group get_fullness_group(struct size_class *class,
						struct page *page)
{
	int inuse, max_objects;
	enum fullness_group fg;
	BUG_ON(!is_first_page(page));

	inuse = get_inuse_obj(page);
	max_objects = class->max_objects;

	if (inuse == 0)
		fg = ZS_EMPTY;
	else if (inuse == max_objects)
		fg = ZS_FULL;
	else if (inuse <= 3 * max_objects / fullness_threshold_frac)
		fg = ZS_ALMOST_EMPTY;
	else
		fg = ZS_ALMOST_FULL;

	return fg;
}

/*
 * Each size class maintains various freelists and zspages are assigned
 * to one of these freelists based on the number of live objects they
 * have. This functions inserts the given zspage into the freelist
 * identified by <class, fullness_group>.
 */
static void insert_zspage(struct page *page, struct size_class *class,
				enum fullness_group fullness)
{
	struct page **head;

	BUG_ON(!is_first_page(page));

	if (fullness >= ZS_EMPTY)
		return;

	zs_stat_inc(class, fullness == ZS_ALMOST_EMPTY ?
			CLASS_ALMOST_EMPTY : CLASS_ALMOST_FULL, 1);

	head = &class->fullness_list[fullness];
	if (!*head) {
		*head = page;
		return;
	}

	/*
	 * We want to see more ZS_FULL pages and less almost
	 * empty/full. Put pages with higher inuse first.
	 */
	list_add_tail(&page->lru, &(*head)->lru);
	if (get_inuse_obj(page) >= get_inuse_obj(*head))
		*head = page;
}

/*
 * This function removes the given zspage from the freelist identified
 * by <class, fullness_group>.
 */
static void remove_zspage(struct page *page, struct size_class *class,
				enum fullness_group fullness)
{
	struct page **head;

	BUG_ON(!is_first_page(page));

	if (fullness >= ZS_EMPTY)
		return;

	head = &class->fullness_list[fullness];
	BUG_ON(!*head);
	if (list_empty(&(*head)->lru))
		*head = NULL;
	else if (*head == page)
		*head = (struct page *)list_entry((*head)->lru.next,
					struct page, lru);

	list_del_init(&page->lru);
	zs_stat_dec(class, fullness == ZS_ALMOST_EMPTY ?
			CLASS_ALMOST_EMPTY : CLASS_ALMOST_FULL, 1);
}

/*
 * Each size class maintains zspages in different fullness groups depending
 * on the number of live objects they contain. When allocating or freeing
 * objects, the fullness status of the page can change, say, from ALMOST_FULL
 * to ALMOST_EMPTY when freeing an object. This function checks if such
 * a status change has occurred for the given page and accordingly moves the
 * page from the freelist of the old fullness group to that of the new
 * fullness group.
 */
static enum fullness_group fix_fullness_group(struct size_class *class,
						struct page *page)
{
	int class_idx;
	enum fullness_group currfg, newfg;

	BUG_ON(!is_first_page(page));

	get_zspage_meta(page, &class_idx, &currfg);
	newfg = get_fullness_group(class, page);
	if (newfg == currfg)
		goto out;

	remove_zspage(page, class, currfg);
	insert_zspage(page, class, newfg);
	set_zspage_meta(page, class_idx, newfg);

out:
	return newfg;
}

/*
 * We have to decide on how many pages to link together
 * to form a zspage for each size class. This is important
 * to reduce wastage due to unusable space left at end of
 * each zspage which is given as:
 *     wastage = Zp % class_size
 *     usage = Zp - wastage
 * where Zp = zspage size = k * PAGE_SIZE where k = 1, 2, ...
 *
 * For example, for size class of 3/8 * PAGE_SIZE, we should
 * link together 3 PAGE_SIZE sized pages to form a zspage
 * since then we can perfectly fit in 8 such objects.
 */
static int get_pages_per_zspage(int class_size)
{
	int i, max_usedpc = 0;
	/* zspage order which gives maximum used size per KB */
	int max_usedpc_order = 1;

	for (i = 1; i <= ZS_MAX_PAGES_PER_ZSPAGE; i++) {
		int zspage_size;
		int waste, usedpc;

		zspage_size = i * PAGE_SIZE;
		waste = zspage_size % class_size;
		usedpc = (zspage_size - waste) * 100 / zspage_size;

		if (usedpc > max_usedpc) {
			max_usedpc = usedpc;
			max_usedpc_order = i;
		}
	}

	return max_usedpc_order;
}

/*
 * A single 'zspage' is composed of many system pages which are
 * linked together using fields in struct page. This function finds
 * the first/head page, given any component page of a zspage.
 */
static struct page *get_first_page(struct page *page)
{
	if (is_first_page(page))
		return page;
	else
		return page->first_page;
}

static struct page *get_next_page(struct page *page)
{
	struct page *next;

	if (is_last_page(page))
		next = NULL;
	else if (is_first_page(page))
		next = (struct page *)page_private(page);
	else
		next = list_entry(page->lru.next, struct page, lru);

	return next;
}

static void obj_idx_to_location(struct size_class *class,
				struct page *first_page, unsigned long obj_idx,
				struct page **obj_page,
				unsigned long *ofs_in_page)
{
	int i;
	unsigned long ofs;
	struct page *cursor;
	int nr_page;

	BUG_ON(!is_first_page(first_page));

	ofs = obj_idx * class->size;
	cursor = first_page;
	nr_page = ofs / PAGE_SIZE;

	*ofs_in_page = ofs % PAGE_SIZE;

	for (i = 0; i < nr_page; i++)
		cursor = get_next_page(cursor);

	*obj_page = cursor;
}

static unsigned long obj_new_page(unsigned long obj, struct page *new_page)
{
	unsigned long new_obj;

	new_obj = page_to_pfn(new_page) << (OBJ_INDEX_BITS + OBJ_TAG_BITS);
	new_obj |= (obj & ((OBJ_INDEX_MASK << OBJ_TAG_BITS) | OBJ_TAG_BITS));

	return new_obj;
}

static void obj_to_obj_idx(unsigned long obj, struct page **obj_page,
				unsigned long *obj_idx)
{
	obj >>= OBJ_TAG_BITS;
	*obj_idx = obj & OBJ_INDEX_MASK;

	obj >>= OBJ_INDEX_BITS;
	*obj_page = pfn_to_page(obj);
}

static unsigned long obj_idx_to_obj(struct page *obj_page,
				unsigned long obj_idx)
{
	unsigned long obj;

	obj = page_to_pfn(obj_page) << OBJ_INDEX_BITS;
	obj |= ((obj_idx) & OBJ_INDEX_MASK);
	obj <<= OBJ_TAG_BITS;

	return obj;
}

static unsigned long handle_to_obj(unsigned long handle)
{
	return *(unsigned long *)handle;
}

static unsigned long obj_to_head(struct size_class *class, struct page *page,
			void *obj)
{
	if (class->huge) {
		VM_BUG_ON(!is_first_page(page));
		return *(unsigned long *)page_private(page);
	} else
		return *(unsigned long *)obj;
}

static inline int trypin_tag(unsigned long handle)
{
	unsigned long *ptr = (unsigned long *)handle;

	return !test_and_set_bit_lock(HANDLE_PIN_BIT, ptr);
}

static void pin_tag(unsigned long handle)
{
	while (!trypin_tag(handle));
}

static void unpin_tag(unsigned long handle)
{
	unsigned long *ptr = (unsigned long *)handle;

	clear_bit_unlock(HANDLE_PIN_BIT, ptr);
}

/*
 * We overload _mapcount in various ways during page migration.  The lower 2
 * bits are used as flags.  Since the reset state is -1, we set a "flag" by
 * clearing its respective bit.  The rest of _mapcount is used to store the
 * sub-page index.
 */
static int is_page_isolated(struct page *page)
{
	BUG_ON(!is_first_page(page));

	/* Make sure a parallel compaction/migration sees the isolation flag. */
	smp_rmb();
	return !(atomic_read(&page->_mapcount) & (1 << PAGE_ISOLATED_BIT));
}

static void set_page_isolated(struct page *page)
{
	int mapcount;

	BUG_ON(!is_first_page(page));

	mapcount = atomic_read(&page->_mapcount);
	/* Make sure a parallel compaction/migration sees the isolation flag. */
	smp_wmb();
	atomic_set(&page->_mapcount, mapcount & ~(1 << PAGE_ISOLATED_BIT));
}

static void clear_page_isolated(struct page *page)
{
	/* Make sure a parallel compaction/migration sees the isolation flag. */
	smp_wmb();
	atomic_set(&page->_mapcount, -1);
}

static int get_subpage_index(struct page *page)
{
	BUG_ON(is_first_page(page));

	return atomic_read(&page->_mapcount);
}

static void set_subpage_index(struct page *page, int index)
{
	BUG_ON(is_first_page(page));

	atomic_set(&page->_mapcount, index);
}

static void clear_subpage_index(struct page *page)
{
	set_subpage_index(page, -1);
}

static void reset_page(struct page *page)
{
	clear_bit(PG_private, &page->flags);
	clear_bit(PG_private_2, &page->flags);
	set_page_private(page, 0);
	ClearPageMobile(page);
	page->freelist = NULL;
	page->mapping = NULL;
	page_mapcount_reset(page);
}

static void free_zspage(struct page *first_page)
{
	struct page *nextp, *tmp, *head_extra;

	BUG_ON(!is_first_page(first_page));
	BUG_ON(get_inuse_obj(first_page));

	head_extra = (struct page *)page_private(first_page);

	reset_page(first_page);
	__free_page(first_page);

	/* zspage with only 1 system page */
	if (!head_extra)
		return;

	list_for_each_entry_safe(nextp, tmp, &head_extra->lru, lru) {
		list_del(&nextp->lru);
		reset_page(nextp);
		__free_page(nextp);
	}
	reset_page(head_extra);
	__free_page(head_extra);
}

/* Initialize a newly allocated zspage */
static void init_zspage(struct page *first_page, struct size_class *class)
{
	int obj_idx = 1;
	unsigned long off = 0;
	struct page *page = first_page;

	BUG_ON(!is_first_page(first_page));
	while (page) {
		struct page *next_page;
		struct link_free *link;
		void *vaddr;

		/*
		 * page->index stores offset of first object starting
		 * in the page.
		 */
		if (page != first_page)
			page->index = off;

		vaddr = kmap_atomic(page);
		link = (struct link_free *)vaddr + off / sizeof(*link);

		while ((off += class->size) < PAGE_SIZE) {
			link->next = (obj_idx++ << OBJ_ALLOCATED_TAG);
			link += class->size / sizeof(*link);
		}

		/*
		 * We now come to the last (full or partial) object on this
		 * page, which must point to the first object on the next
		 * page (if present)
		 */
		next_page = get_next_page(page);
		if (next_page)
			link->next = (obj_idx++ << OBJ_ALLOCATED_TAG);
		else
			link->next = (-1 << OBJ_ALLOCATED_TAG);
		kunmap_atomic(vaddr);
		page = next_page;
		off %= PAGE_SIZE;
	}

	set_free_obj_idx(first_page, 0);
}

/*
 * Allocate a zspage for the given size class
 */
static struct page *alloc_zspage(struct size_class *class, gfp_t flags)
{
	int i, error;
	struct page *first_page = NULL, *uninitialized_var(prev_page);

	/*
	 * Allocate individual pages and link them together as:
	 * 1. first page->private = first sub-page
	 * 2. all sub-pages are linked together using page->lru
	 * 3. each sub-page is linked to the first page using page->first_page
	 *
	 * For each size class, First/Head pages are linked together using
	 * page->lru. Also, we set PG_private to identify the first page
	 * (i.e. no other sub-page has this flag set) and PG_private_2 to
	 * identify the last page.
	 */
	error = -ENOMEM;
	for (i = 0; i < class->pages_per_zspage; i++) {
		struct page *page;

		page = alloc_page(flags);
		if (!page)
			goto cleanup;

		INIT_LIST_HEAD(&page->lru);
		if (i == 0) {	/* first page */
			SetPagePrivate(page);
			set_page_private(page, 0);
			first_page = page;
			set_inuse_obj(page, 0);
		}
		if (i == 1)
			set_page_private(first_page, (unsigned long)page);
		if (i >= 1)
			page->first_page = first_page;
		if (i >= 2)
			list_add(&page->lru, &prev_page->lru);
		if (i == class->pages_per_zspage - 1)	/* last page */
			SetPagePrivate2(page);
		page->mapping = class->pool->inode->i_mapping;
		prev_page = page;
	}

	init_zspage(first_page, class);

	error = 0; /* Success */

cleanup:
	if (unlikely(error) && first_page) {
		free_zspage(first_page);
		first_page = NULL;
	}

	return first_page;
}

static struct page *find_get_zspage(struct size_class *class)
{
	int i;
	struct page *page;

	for (i = 0; i < ZS_EMPTY; i++) {
		page = class->fullness_list[i];
		if (page)
			break;
	}

	BUG_ON(page && is_page_isolated(page));
	return page;
}

#ifdef CONFIG_PGTABLE_MAPPING
static inline int __zs_cpu_up(struct mapping_area *area)
{
	/*
	 * Make sure we don't leak memory if a cpu UP notification
	 * and zs_init() race and both call zs_cpu_up() on the same cpu
	 */
	if (area->vm)
		return 0;
	area->vm = alloc_vm_area(PAGE_SIZE * 2, NULL);
	if (!area->vm)
		return -ENOMEM;
	return 0;
}

static inline void __zs_cpu_down(struct mapping_area *area)
{
	if (area->vm)
		free_vm_area(area->vm);
	area->vm = NULL;
}

static inline void *__zs_map_object(struct mapping_area *area,
				struct page *pages[2], int off, int size)
{
	BUG_ON(map_vm_area(area->vm, PAGE_KERNEL, pages));
	area->vm_addr = area->vm->addr;
	return area->vm_addr + off;
}

static inline void __zs_unmap_object(struct mapping_area *area,
				struct page *pages[2], int off, int size)
{
	unsigned long addr = (unsigned long)area->vm_addr;

	unmap_kernel_range(addr, PAGE_SIZE * 2);
}

#else /* CONFIG_PGTABLE_MAPPING */

static inline int __zs_cpu_up(struct mapping_area *area)
{
	/*
	 * Make sure we don't leak memory if a cpu UP notification
	 * and zs_init() race and both call zs_cpu_up() on the same cpu
	 */
	if (area->vm_buf)
		return 0;
	area->vm_buf = kmalloc(ZS_MAX_ALLOC_SIZE, GFP_KERNEL);
	if (!area->vm_buf)
		return -ENOMEM;
	return 0;
}

static inline void __zs_cpu_down(struct mapping_area *area)
{
	kfree(area->vm_buf);
	area->vm_buf = NULL;
}

static void *__zs_map_object(struct mapping_area *area,
			struct page *pages[2], int off, int size)
{
	int sizes[2];
	void *addr;
	char *buf = area->vm_buf;

	/* disable page faults to match kmap_atomic() return conditions */
	pagefault_disable();

	/* no read fastpath */
	if (area->vm_mm == ZS_MM_WO)
		goto out;

	sizes[0] = PAGE_SIZE - off;
	sizes[1] = size - sizes[0];

	/* copy object to per-cpu buffer */
	addr = kmap_atomic(pages[0]);
	memcpy(buf, addr + off, sizes[0]);
	kunmap_atomic(addr);
	addr = kmap_atomic(pages[1]);
	memcpy(buf + sizes[0], addr, sizes[1]);
	kunmap_atomic(addr);
out:
	return area->vm_buf;
}

static void __zs_unmap_object(struct mapping_area *area,
			struct page *pages[2], int off, int size)
{
	int sizes[2];
	void *addr;
	char *buf;

	/* no write fastpath */
	if (area->vm_mm == ZS_MM_RO)
		goto out;

	buf = area->vm_buf;
	if (!area->huge) {
		buf = buf + ZS_HANDLE_SIZE;
		size -= ZS_HANDLE_SIZE;
		off += ZS_HANDLE_SIZE;
	}

	sizes[0] = PAGE_SIZE - off;
	sizes[1] = size - sizes[0];

	/* copy per-cpu buffer to object */
	addr = kmap_atomic(pages[0]);
	memcpy(addr + off, buf, sizes[0]);
	kunmap_atomic(addr);
	addr = kmap_atomic(pages[1]);
	memcpy(addr, buf + sizes[0], sizes[1]);
	kunmap_atomic(addr);

out:
	/* enable page faults to match kunmap_atomic() return conditions */
	pagefault_enable();
}

#endif /* CONFIG_PGTABLE_MAPPING */

static int zs_cpu_notifier(struct notifier_block *nb, unsigned long action,
				void *pcpu)
{
	int ret, cpu = (long)pcpu;
	struct mapping_area *area;

	switch (action) {
	case CPU_UP_PREPARE:
		area = &per_cpu(zs_map_area, cpu);
		ret = __zs_cpu_up(area);
		if (ret)
			return notifier_from_errno(ret);
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		area = &per_cpu(zs_map_area, cpu);
		__zs_cpu_down(area);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block zs_cpu_nb = {
	.notifier_call = zs_cpu_notifier
};

static int zs_register_cpu_notifier(void)
{
	int cpu, uninitialized_var(ret);

	cpu_notifier_register_begin();

	__register_cpu_notifier(&zs_cpu_nb);
	for_each_online_cpu(cpu) {
		ret = zs_cpu_notifier(NULL, CPU_UP_PREPARE, (void *)(long)cpu);
		if (notifier_to_errno(ret))
			break;
	}

	cpu_notifier_register_done();
	return notifier_to_errno(ret);
}

static void zs_unregister_cpu_notifier(void)
{
	int cpu;

	cpu_notifier_register_begin();

	for_each_online_cpu(cpu)
		zs_cpu_notifier(NULL, CPU_DEAD, (void *)(long)cpu);
	__unregister_cpu_notifier(&zs_cpu_nb);

	cpu_notifier_register_done();
}

static void init_zs_size_classes(void)
{
	int nr;

	nr = (ZS_MAX_ALLOC_SIZE - ZS_MIN_ALLOC_SIZE) / ZS_SIZE_CLASS_DELTA + 1;
	if ((ZS_MAX_ALLOC_SIZE - ZS_MIN_ALLOC_SIZE) % ZS_SIZE_CLASS_DELTA)
		nr += 1;

	zs_size_classes = nr;
}

static bool can_merge(struct size_class *prev, int size, int pages_per_zspage)
{
	if (prev->pages_per_zspage != pages_per_zspage)
		return false;

	if (get_maxobj_per_zspage(prev->size, prev->pages_per_zspage)
		!= get_maxobj_per_zspage(size, pages_per_zspage))
		return false;

	return true;
}

static bool zspage_full(struct size_class *class, struct page *page)
{
	BUG_ON(!is_first_page(page));

	return get_inuse_obj(page) == class->max_objects;
}

unsigned long zs_get_total_pages(struct zs_pool *pool)
{
	return atomic_long_read(&pool->pages_allocated);
}
EXPORT_SYMBOL_GPL(zs_get_total_pages);

/**
 * zs_map_object - get address of allocated object from handle.
 * @pool: pool from which the object was allocated
 * @handle: handle returned from zs_malloc
 *
 * Before using an object allocated from zs_malloc, it must be mapped using
 * this function. When done with the object, it must be unmapped using
 * zs_unmap_object.
 *
 * Only one object can be mapped per cpu at a time. There is no protection
 * against nested mappings.
 *
 * This function returns with preemption and page faults disabled.
 */
void *zs_map_object(struct zs_pool *pool, unsigned long handle,
			enum zs_mapmode mm)
{
	struct page *obj_page, *first_page;
	unsigned long obj, obj_idx, obj_ofs;

	unsigned int class_idx;
	enum fullness_group fg;
	struct size_class *class;
	struct mapping_area *area;
	struct page *pages[2];
	void *ret;

	BUG_ON(!handle);

	/*
	 * Because we use per-cpu mapping areas shared among the
	 * pools/users, we can't allow mapping in interrupt context
	 * because it can corrupt another users mappings.
	 */
	BUG_ON(in_interrupt());

	/* From now on, migration cannot move the object */
	pin_tag(handle);

	obj = handle_to_obj(handle);
	obj_to_obj_idx(obj, &obj_page, &obj_idx);

	first_page = get_first_page(obj_page);
	get_zspage_meta(first_page, &class_idx, &fg);

	class = pool->size_class[class_idx];
	obj_ofs = (class->size * obj_idx) % PAGE_SIZE;

	area = &get_cpu_var(zs_map_area);
	area->vm_mm = mm;
	if (obj_ofs + class->size <= PAGE_SIZE) {
		/* this object is contained entirely within a page */
		area->vm_addr = kmap_atomic(obj_page);
		ret = area->vm_addr + obj_ofs;
		goto out;
	}

	/* this object spans two pages */
	pages[0] = obj_page;
	pages[1] = get_next_page(obj_page);
	BUG_ON(!pages[1]);

	ret = __zs_map_object(area, pages, obj_ofs, class->size);
out:
	if (!class->huge)
		ret += ZS_HANDLE_SIZE;

	return ret;
}
EXPORT_SYMBOL_GPL(zs_map_object);

void zs_unmap_object(struct zs_pool *pool, unsigned long handle)
{
	struct page *obj_page, *first_page;
	unsigned long obj, obj_idx, obj_ofs;

	unsigned int class_idx;
	enum fullness_group fg;
	struct size_class *class;
	struct mapping_area *area;

	BUG_ON(!handle);

	obj = handle_to_obj(handle);

	obj_to_obj_idx(obj, &obj_page, &obj_idx);
	first_page = get_first_page(obj_page);
	get_zspage_meta(first_page, &class_idx, &fg);
	class = pool->size_class[class_idx];
	obj_ofs = (class->size * obj_idx) % PAGE_SIZE;

	area = this_cpu_ptr(&zs_map_area);
	if (obj_ofs + class->size <= PAGE_SIZE)
		kunmap_atomic(area->vm_addr);
	else {
		struct page *pages[2];

		pages[0] = obj_page;
		pages[1] = get_next_page(obj_page);
		BUG_ON(!pages[1]);

		__zs_unmap_object(area, pages, obj_ofs, class->size);
	}
	put_cpu_var(zs_map_area);
	unpin_tag(handle);
}
EXPORT_SYMBOL_GPL(zs_unmap_object);

static unsigned long obj_malloc(struct page *first_page,
		struct size_class *class, unsigned long handle)
{
	unsigned long obj_idx, obj;
	struct link_free *link;

	struct page *obj_page;
	unsigned long obj_ofs;
	void *vaddr;

	handle |= OBJ_ALLOCATED_TAG;
	obj_idx = get_free_obj_idx(first_page);
	obj_idx_to_location(class, first_page, obj_idx, &obj_page, &obj_ofs);

	vaddr = kmap_atomic(obj_page);
	link = (struct link_free *)vaddr + obj_ofs / sizeof(*link);
	set_free_obj_idx(first_page, link->next >> OBJ_ALLOCATED_TAG);
	if (!class->huge)
		/* record handle in the header of allocated chunk */
		link->handle = handle;
	else
		/* record handle in first_page->private */
		set_page_private(first_page, handle);
	kunmap_atomic(vaddr);
	set_inuse_obj(first_page, 1);
	zs_stat_inc(class, OBJ_USED, 1);

	obj = obj_idx_to_obj(obj_page, obj_idx);

	return obj;
}


/**
 * zs_malloc - Allocate block of given size from pool.
 * @pool: pool to allocate from
 * @size: size of block to allocate
 *
 * On success, handle to the allocated object is returned,
 * otherwise 0.
 * Allocation requests with size > ZS_MAX_ALLOC_SIZE will fail.
 */
unsigned long zs_malloc(struct zs_pool *pool, size_t size)
{
	unsigned long handle, obj;
	struct size_class *class;
	struct page *first_page;

	if (unlikely(!size || size > ZS_MAX_ALLOC_SIZE))
		return 0;

	handle = alloc_handle(pool);
	if (!handle)
		return 0;

	/* extra space in chunk to keep the handle */
	size += ZS_HANDLE_SIZE;
	class = pool->size_class[get_size_class_index(size)];

	spin_lock(&class->lock);
	first_page = find_get_zspage(class);

	if (!first_page) {
		struct page *page;

		spin_unlock(&class->lock);
		first_page = alloc_zspage(class, pool->flags);
		if (unlikely(!first_page)) {
			free_handle(pool, handle);
			return 0;
		}

		set_zspage_meta(first_page, class->index, ZS_EMPTY);
		atomic_long_add(class->pages_per_zspage,
					&pool->pages_allocated);

		spin_lock(&class->lock);
		page = first_page;
		while (page) {
			SetPageMobile(page);
			page = get_next_page(page);
		}
		zs_stat_inc(class, OBJ_ALLOCATED, get_maxobj_per_zspage(
				class->size, class->pages_per_zspage));
	}

	obj = obj_malloc(first_page, class, handle);
	/* Now move the zspage to another fullness group, if required */
	fix_fullness_group(class, first_page);
	record_obj(handle, obj);
	spin_unlock(&class->lock);

	return handle;
}
EXPORT_SYMBOL_GPL(zs_malloc);

static void obj_free(struct zs_pool *pool, struct size_class *class,
			unsigned long obj)
{
	struct link_free *link;
	struct page *first_page, *obj_page;
	unsigned long obj_idx, obj_ofs;
	void *vaddr;

	BUG_ON(!obj);

	obj_to_obj_idx(obj, &obj_page, &obj_idx);
	obj_ofs = (class->size * obj_idx) % PAGE_SIZE;
	first_page = get_first_page(obj_page);

	vaddr = kmap_atomic(obj_page);

	/* Insert this object in containing zspage's freelist */
	link = (struct link_free *)(vaddr + obj_ofs);
	link->next = get_free_obj_idx(first_page) << OBJ_ALLOCATED_TAG;
	if (class->huge)
		set_page_private(first_page, 0);
	kunmap_atomic(vaddr);
	set_free_obj_idx(first_page, obj_idx);
	set_inuse_obj(first_page, -1);
	zs_stat_dec(class, OBJ_USED, 1);

}

static inline void zs_free_if_empty(struct zs_pool *pool,
				struct size_class *class,
				struct page *first_page,
				enum fullness_group fullness)
{
	if (fullness == ZS_EMPTY) {
		zs_stat_dec(class, OBJ_ALLOCATED, get_maxobj_per_zspage(
				class->size, class->pages_per_zspage));
		atomic_long_sub(class->pages_per_zspage,
				&pool->pages_allocated);
		free_zspage(first_page);
	}
}

void zs_free(struct zs_pool *pool, unsigned long handle)
{
	struct page *first_page, *obj_page;
	unsigned long obj, obj_idx;
	int class_idx;
	struct size_class *class;
	enum fullness_group fullness;

	if (unlikely(!handle))
		return;

	pin_tag(handle);
	obj = handle_to_obj(handle);

	obj_to_obj_idx(obj, &obj_page, &obj_idx);
	first_page = get_first_page(obj_page);
	get_zspage_meta(first_page, &class_idx, &fullness);
	class = pool->size_class[class_idx];

	spin_lock(&class->lock);
	obj_free(pool, class, obj);
	/* Don't touch the fullness group if the page is isolated. */
	if (!is_page_isolated(first_page)) {
		zs_free_if_empty(pool, class, first_page,
				 fix_fullness_group(class, first_page));
	}
	spin_unlock(&class->lock);
	unpin_tag(handle);

	free_handle(pool, handle);
}
EXPORT_SYMBOL_GPL(zs_free);

static void zs_object_copy(unsigned long dst_obj, unsigned long src_obj,
				struct size_class *class)
{
	struct page *s_page, *d_page;
	unsigned long s_objidx, d_objidx;
	unsigned long s_off, d_off;
	void *s_addr, *d_addr;
	int s_size, d_size, size;
	int written = 0;

	s_size = d_size = class->size;

	obj_to_obj_idx(src_obj, &s_page, &s_objidx);
	obj_to_obj_idx(dst_obj, &d_page, &d_objidx);

	s_off = (class->size * s_objidx) % PAGE_SIZE;
	d_off = (class->size * d_objidx) % PAGE_SIZE;

	if (s_off + class->size > PAGE_SIZE)
		s_size = PAGE_SIZE - s_off;

	if (d_off + class->size > PAGE_SIZE)
		d_size = PAGE_SIZE - d_off;

	s_addr = kmap_atomic(s_page);
	d_addr = kmap_atomic(d_page);

	while (1) {
		size = min(s_size, d_size);
		memcpy(d_addr + d_off, s_addr + s_off, size);
		written += size;

		if (written == class->size)
			break;

		s_off += size;
		s_size -= size;
		d_off += size;
		d_size -= size;

		if (s_off >= PAGE_SIZE) {
			kunmap_atomic(d_addr);
			kunmap_atomic(s_addr);
			s_page = get_next_page(s_page);
			BUG_ON(!s_page);
			s_addr = kmap_atomic(s_page);
			d_addr = kmap_atomic(d_page);
			s_size = class->size - written;
			s_off = 0;
		}

		if (d_off >= PAGE_SIZE) {
			kunmap_atomic(d_addr);
			d_page = get_next_page(d_page);
			BUG_ON(!d_page);
			d_addr = kmap_atomic(d_page);
			d_size = class->size - written;
			d_off = 0;
		}
	}

	kunmap_atomic(d_addr);
	kunmap_atomic(s_addr);
}

/*
 * Find alloced object in zspage from index object and
 * return handle.
 */
static unsigned long find_alloced_obj(struct page *page, int index,
					struct size_class *class)
{
	unsigned long head;
	int offset = 0;
	unsigned long handle = 0;
	void *addr = kmap_atomic(page);

	if (!is_first_page(page))
		offset = page->index;
	offset += class->size * index;

	while (offset < PAGE_SIZE) {
		head = obj_to_head(class, page, addr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			handle = head & ~OBJ_ALLOCATED_TAG;
			if (trypin_tag(handle))
				break;
			handle = 0;
		}

		offset += class->size;
		index++;
	}

	kunmap_atomic(addr);
	return handle;
}

struct zs_compact_control {
	/* Source page for migration which could be a subpage of zspage. */
	struct page *s_page;
	/* Destination page for migration which should be a first page
	 * of zspage. */
	struct page *d_page;
	 /* Starting object index within @s_page which used for live object
	  * in the subpage. */
	int index;
};

static int migrate_zspage(struct zs_pool *pool, struct size_class *class,
				struct zs_compact_control *cc)
{
	unsigned long used_obj, free_obj;
	unsigned long handle;
	struct page *s_page = cc->s_page;
	struct page *d_page = cc->d_page;
	unsigned long index = cc->index;
	int ret = 0;

	while (1) {
		handle = find_alloced_obj(s_page, index, class);
		if (!handle) {
			s_page = get_next_page(s_page);
			if (!s_page)
				break;
			index = 0;
			continue;
		}

		/* Stop if there is no more space */
		if (zspage_full(class, d_page)) {
			unpin_tag(handle);
			ret = -ENOMEM;
			break;
		}

		used_obj = handle_to_obj(handle);
		free_obj = obj_malloc(d_page, class, handle);
		zs_object_copy(free_obj, used_obj, class);
		free_obj |= (1 << HANDLE_PIN_BIT);
		index++;
		record_obj(handle, free_obj);
		unpin_tag(handle);
		obj_free(pool, class, used_obj);
	}

	/* Remember last position in this iteration */
	cc->s_page = s_page;
	cc->index = index;

	return ret;
}

static struct page *isolate_target_page(struct size_class *class)
{
	int i;
	struct page *page;

	for (i = 0; i < ZS_EMPTY; i++) {
		page = class->fullness_list[i];
		if (page && !is_page_isolated(page)) {
			set_page_isolated(page);
			remove_zspage(page, class, i);
			break;
		}
	}

	return page;
}

/*
 * putback_zspage - add @first_page into right class's fullness list
 * @pool: target pool
 * @class: destination class
 * @first_page: target page
 *
 * Return @fist_page's fullness_group
 */
static enum fullness_group putback_zspage(struct zs_pool *pool,
			struct size_class *class,
			struct page *first_page)
{
	enum fullness_group fullness;

	BUG_ON(!is_first_page(first_page));

	fullness = get_fullness_group(class, first_page);
	insert_zspage(first_page, class, fullness);
	set_zspage_meta(first_page, class->index, fullness);
	clear_page_isolated(first_page);

	zs_free_if_empty(pool, class, first_page, fullness);

	return fullness;
}

static struct page *isolate_source_page(struct size_class *class)
{
	int i;
	struct page *page = NULL;

	for (i = ZS_ALMOST_EMPTY; i >= ZS_ALMOST_FULL; i--) {
		page = class->fullness_list[i];
		if (!page || is_page_isolated(page))
			continue;

		set_page_isolated(page);
		remove_zspage(page, class, i);
		break;
	}

	return page;
}

/*
 *
 * Based on the number of unused allocated objects calculate
 * and return the number of pages that we can free.
 */
static unsigned long zs_can_compact(struct size_class *class)
{
	unsigned long obj_wasted;

	obj_wasted = zs_stat_get(class, OBJ_ALLOCATED) -
		zs_stat_get(class, OBJ_USED);

	obj_wasted /= get_maxobj_per_zspage(class->size,
			class->pages_per_zspage);

	return obj_wasted * class->pages_per_zspage;
}

static void __zs_compact(struct zs_pool *pool, struct size_class *class)
{
	struct zs_compact_control cc;
	struct page *src_page;
	struct page *dst_page = NULL;

	spin_lock(&class->lock);
	while ((src_page = isolate_source_page(class))) {

		BUG_ON(!is_first_page(src_page));

		if (!zs_can_compact(class))
			break;

		cc.index = 0;
		cc.s_page = src_page;

		while ((dst_page = isolate_target_page(class))) {
			cc.d_page = dst_page;
			/*
			 * If there is no more space in dst_page, resched
			 * and see if anyone had allocated another zspage.
			 */
			if (!migrate_zspage(pool, class, &cc))
				break;

			putback_zspage(pool, class, dst_page);
		}

		/* Stop if we couldn't find slot */
		if (dst_page == NULL)
			break;

		putback_zspage(pool, class, dst_page);
		if (putback_zspage(pool, class, src_page) == ZS_EMPTY)
			pool->stats.pages_compacted += class->pages_per_zspage;
		spin_unlock(&class->lock);
		cond_resched();
		spin_lock(&class->lock);
	}

	if (src_page)
		putback_zspage(pool, class, src_page);

	spin_unlock(&class->lock);
}

unsigned long zs_compact(struct zs_pool *pool)
{
	int i;
	struct size_class *class;

	for (i = zs_size_classes - 1; i >= 0; i--) {
		class = pool->size_class[i];
		if (!class)
			continue;
		if (class->index != i)
			continue;
		__zs_compact(pool, class);
	}

	return pool->stats.pages_compacted;
}
EXPORT_SYMBOL_GPL(zs_compact);

void zs_pool_stats(struct zs_pool *pool, struct zs_pool_stats *stats)
{
	memcpy(stats, &pool->stats, sizeof(struct zs_pool_stats));
}
EXPORT_SYMBOL_GPL(zs_pool_stats);

static unsigned long zs_shrinker_scan(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	unsigned long pages_freed;
	struct zs_pool *pool = container_of(shrinker, struct zs_pool,
			shrinker);

	pages_freed = pool->stats.pages_compacted;
	/*
	 * Compact classes and calculate compaction delta.
	 * Can run concurrently with a manually triggered
	 * (by user) compaction.
	 */
	pages_freed = zs_compact(pool) - pages_freed;

	return pages_freed ? pages_freed : SHRINK_STOP;
}

static unsigned long zs_shrinker_count(struct shrinker *shrinker,
		struct shrink_control *sc)
{
	int i;
	struct size_class *class;
	unsigned long pages_to_free = 0;
	struct zs_pool *pool = container_of(shrinker, struct zs_pool,
			shrinker);

	if (!pool->shrinker_enabled)
		return 0;

	for (i = zs_size_classes - 1; i >= 0; i--) {
		class = pool->size_class[i];
		if (!class)
			continue;
		if (class->index != i)
			continue;

		pages_to_free += zs_can_compact(class);
	}

	return pages_to_free;
}

static void zs_unregister_shrinker(struct zs_pool *pool)
{
	if (pool->shrinker_enabled) {
		unregister_shrinker(&pool->shrinker);
		pool->shrinker_enabled = false;
	}
}

static int zs_register_shrinker(struct zs_pool *pool)
{
	pool->shrinker.scan_objects = zs_shrinker_scan;
	pool->shrinker.count_objects = zs_shrinker_count;
	pool->shrinker.batch = 0;
	pool->shrinker.seeks = DEFAULT_SEEKS;

	return register_shrinker(&pool->shrinker);
}

/*
 * Pin all allocated objects in a page and return true if successful.  If any
 * objects are in use, unpin all that were pinned by us and return false.
 *
 * FIXME: this may not be good enough!  There is the potential for a race when
 * get_next_page() is walking the page list while a sub-page is isolated.  The
 * only API directly affected by this is obj_malloc(), though.  The other APIs
 * use the handle, which directly references the page PFN.  Another possible
 * case is the case where an object spans two pages and zs_map_object is called.
 * Maybe we just need to handle that case specially and try to pin the object
 * that starts on the previous page.
 */
#define PIN_LIST_MAX (PAGE_SIZE / ZS_MIN_ALLOC_SIZE / BITS_PER_LONG)
static bool pin_all_tags(struct page *page, struct size_class *class)
{
	int offset = 0, index = 0, pindex = 0;
	void *vaddr;
	unsigned long head;
	unsigned long pinlist[PIN_LIST_MAX] = {0};
	int pinned = 0;

	if (class->huge) {
		offset = PAGE_SIZE;
		head = page_private(page);
		if (head & OBJ_ALLOCATED_TAG) {
			if (trypin_tag(head & ~OBJ_ALLOCATED_TAG))
				pinned = 1;
			else
				offset = 0;
		}
	} else {
		if (!is_first_page(page))
			offset = page->index;

		vaddr = kmap_atomic(page);
		while (offset < PAGE_SIZE) {
			BUG_ON(pindex >= PIN_LIST_MAX);
			head = *(unsigned long *)(vaddr + offset);
			if (head & OBJ_ALLOCATED_TAG) {
				if (!trypin_tag(head & ~OBJ_ALLOCATED_TAG))
					break;

				pinlist[pindex] |= 1 << index;
				pinned++;
			}

			offset += class->size;
			index++;
			if (index % BITS_PER_LONG == 0)
				pindex++;
		}
		kunmap_atomic(vaddr);
	}

	/* We were able to pin all allocated objects. */
	if (offset >= PAGE_SIZE)
		return true;

	/* We failed to pin an object, but none had been pinned yet. */
	if (pinned == 0)
		return false;

	/* Unpin any that we had managed to pin. */
	if (class->huge) {
		head = page_private(page);
		unpin_tag(head & ~OBJ_ALLOCATED_TAG);
		return false;
	}

	offset = index = pindex = pinned = 0;
	if (!is_first_page(page))
		offset = page->index;

	vaddr = kmap_atomic(page);
	while (offset < PAGE_SIZE) {
		BUG_ON(pindex >= PIN_LIST_MAX);
		if (pinlist[pindex] & (1 << index)) {
			head = *(unsigned long *)(vaddr + offset);
			unpin_tag(head & ~OBJ_ALLOCATED_TAG);
			pinned++;
		}
		offset += class->size;
		index++;
		if (index % BITS_PER_LONG == 0)
			pindex++;
	}
	kunmap_atomic(vaddr);

	return false;
}

/*
 * Unpin all allocated objects in a page.  The assumption here is that all
 * objects were pinned by pin_all_tags() and so we can unpin them all.
 */
static void unpin_all_tags(struct page *page, struct size_class *class)
{
	int offset = 0;
	void *vaddr;
	unsigned long head;
	int unpinned = 0;

	if (class->huge) {
		head = page_private(page);
		if (head & OBJ_ALLOCATED_TAG) {
			unpin_tag(head & ~OBJ_ALLOCATED_TAG);
			unpinned = 1;
		}
		return;
	}

	if (!is_first_page(page))
		offset = page->index;

	vaddr = kmap_atomic(page);
	while (offset < PAGE_SIZE) {
		head = *(unsigned long *)(vaddr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			unpin_tag(head & ~OBJ_ALLOCATED_TAG);
			unpinned++;
		}
		offset += class->size;
	}
	kunmap_atomic(vaddr);
}

/*
 * Pin the object that spans these two pages.  Some zspage classes have objects
 * that cross a page boundary.  When we are isolating a page that starts with a
 * partial object, the object head actually lives in the previous page.
 */
static bool pin_spanned_tag(struct page *page, struct page *next_page,
			    struct size_class *class)
{
	void *vaddr;
	unsigned long head;
	int offset = PAGE_SIZE - (class->size - next_page->index);
	bool res = true;

	vaddr = kmap_atomic(page);

	head = *(unsigned long *)(vaddr + offset);
	if (head & OBJ_ALLOCATED_TAG) {
		if (!trypin_tag(head & ~OBJ_ALLOCATED_TAG))
			res = false;
	}

	kunmap_atomic(vaddr);
	return res;
}

/*
 * Unpin the object that spans these two pages.
 */
static void unpin_spanned_tag(struct page *page, struct page *next_page,
			      struct size_class *class)
{
	void *vaddr;
	unsigned long head;
	int offset = PAGE_SIZE - (class->size - next_page->index);

	vaddr = kmap_atomic(page);

	head = *(unsigned long *)(vaddr + offset);
	if (head & OBJ_ALLOCATED_TAG)
		unpin_tag(head & ~OBJ_ALLOCATED_TAG);

	kunmap_atomic(vaddr);
}

/*
 * We need to free-up page->lru so that compaction can use it.  We are
 * presumably tight on memory, so we have to make use of what we have in
 * struct page.
 *
 * FIXME: The current approach used here has several limiations that are
 * described in the code below.  Another idea could be to ditch this entire
 * approach and do something like steal a page from the system at startup and
 * use that to stash-away zspage metadata for isolated pages. That creates other
 * headaches, though.
 */
static int zs_migrate_isolate(struct page *page)
{
	struct zs_pool *pool = (struct zs_pool *)page->mapping->private_data;
	struct size_class *class;
	unsigned int index = 0;
	enum fullness_group fullness;
	struct page *prev_page, *next_page;
	struct page *first_page = get_first_page(page);

	get_zspage_meta(first_page, &index, &fullness);
	class = pool->size_class[index];

	/*
	 * This zspage has a page that is already isolated.
	 *
	 * FIXME: This can be improved a bit if we tag every subpage
	 * with its index and then try to sort it all out during
	 * migrate.  It's not clear if that will improve overall
	 * performance any, but it will allow more pages to migrate on
	 * a single pass.
	 */
	if (unlikely(is_page_isolated(first_page)))
		return -EAGAIN;

	/*
	 * Hold the the class lock during isolation process to avoid races with
	 * obj_malloc()/obj_free().
	 */
	spin_lock(&class->lock);

	/* Recheck. Other process could have just isolated this zspage. */
	if (unlikely(is_page_isolated(first_page))) {
		spin_unlock(&class->lock);
		return -EAGAIN;
	}

	if (is_first_page(page)) {
		/*
		 * Pin every allocated object in this page.  This needs to be
		 * the last possible point of failure during isolate.
		 */
		if (unlikely(!pin_all_tags(page, class)))
			goto fail_busy;

		set_page_isolated(page);
	} else {
		/*
		 * Since this isn't the first page in a zspage, we need to
		 * remember the page's position in the sub-page list so that we
		 * can clear out of page->lru.
		 */
		index = 0;
		prev_page = next_page = first_page;
		while (next_page && next_page != page) {
			prev_page = next_page;
			next_page = get_next_page(next_page);
			index++;
			BUG_ON(index > ZS_MAX_PAGES_PER_ZSPAGE);
		}
		BUG_ON(!next_page);

		/*
		 * If the first object in the sub-page is not at the start of
		 * the page, then we need to pin the last object in the previous
		 * page (which we had to walk the list in order to get).
		 */
		if (page->index > 0) {
			if (!pin_spanned_tag(prev_page, page, class))
				goto fail_busy;
		}

		/*
		 * Pin every allocated object in this page.  This needs to be
		 * the last possible point of failure during isolate.
		 */
		if (unlikely(!pin_all_tags(page, class))) {
			if (page->index > 0)
				unpin_spanned_tag(prev_page, page, class);
			goto fail_busy;
		}

		/*
		 * Mark the first page so that it knows that a sub page is
		 * isolated and doesn't have to search the entire list.  Then
		 * save the relative page position into this page's _mapcount.
		 *
		 * FIXME: do we need to try to take the page lock on the first
		 * page here?
		 */
		set_page_isolated(first_page);
		set_subpage_index(page, index);

		/*
		 * If this is the second page (first sub-page) update the first
		 * page's reference to point the next page (or nothing if last).
		 */
		if (index == 1) {
			next_page = get_next_page(page);
			if (next_page)
				set_page_private(first_page,
						 (unsigned long)next_page);
			else
				set_page_private(first_page, 0);
		}

		/* If this is the last page, mark the previous page as last. */
		if (is_last_page(page))
			SetPagePrivate2(prev_page);

		list_del_init(&page->lru);
	}

	/*
	 * Remove the zspage from its fullness list to prevent any other
	 * allocations from occurring during migration.  We need to reaquire
	 * the fullness group while holding the class lock to avoid a race.
	 */
	get_zspage_meta(first_page, &index, &fullness);
	remove_zspage(first_page, class, fullness);

	spin_unlock(&class->lock);
	return 0;

fail_busy:
	zs_stat_inc(class, ABORTED_ISOLATES, 1);
	spin_unlock(&class->lock);
	return -EBUSY;
}

/*
 * Restore a sub-page back into the sub-page list using the index that was
 * stashed into _mapcount as the relative list position.
 */
static void zs_migrate_putback_sub_page(struct size_class *class,
					struct page *first_page,
					struct page *page, unsigned index)
{
	struct page *prev_page, *next_page;
	unsigned i;

	BUG_ON(!is_first_page(first_page));
	BUG_ON(is_first_page(page));
	BUG_ON(index > ZS_MAX_PAGES_PER_ZSPAGE);

	INIT_LIST_HEAD(&page->lru);

	/*
	 * Walk the page list to find the page that came after this one
	 * before it got isolated.  If it's the last page, watch out for
	 * it being the only sub-page.
	 */
	prev_page = next_page = first_page;
	for (i = 0; next_page && i < index; i++) {
		prev_page = next_page;
		next_page = get_next_page(next_page);
	}
	if (next_page)
		/* It's not the last page, so insert it. */
		list_add_tail(&page->lru, &next_page->lru);
	else if (i == index) {
		/* If it's the last page but not the 2nd page, append it. */
		if (prev_page != first_page)
			list_add(&page->lru, &prev_page->lru);
		/* The previous page is no longer the last. */
		ClearPagePrivate2(prev_page);
	} else {
		/* We got confused.  :( */
		pr_crit("%s: can't find slot for index %d\n", __func__, index);
		BUG();
	}

	/*
	 * If this is the second page (first sub-page), update the first
	 * page's reference to it.
	 */
	if (index == 1)
		set_page_private(first_page, (unsigned long)page);

	/*
	 * If the page starts with a partial page, unpin the last object in the
	 * previous page.
	 */
	if (page->index > 0)
		unpin_spanned_tag(prev_page, page, class);
}

/*
 * Called only if the page has not been migrated (apparently), so undo isolate.
 */
static void zs_migrate_putback(struct page *page)
{
	struct zs_pool *pool = (struct zs_pool *)page->mapping->private_data;
	struct size_class *class;
	unsigned int index;
	enum fullness_group fullness;
	struct page *first_page = get_first_page(page);

	BUG_ON(!is_page_isolated(first_page));

	get_zspage_meta(first_page, &index, &fullness);
	class = pool->size_class[index];

	spin_lock(&class->lock);
	if (!is_first_page(page)) {
		zs_migrate_putback_sub_page(class, first_page, page,
					    get_subpage_index(page));
		clear_subpage_index(page);
	}
	clear_page_isolated(first_page);

	/* Put the zspage back into the appropriate fullness list. */
	INIT_LIST_HEAD(&first_page->lru);
	fullness = get_fullness_group(class, first_page);
	insert_zspage(first_page, class, fullness);
	set_zspage_meta(first_page, class->index, fullness);
	spin_unlock(&class->lock);

	unpin_all_tags(page, class);
}

/*
 * Order is important!
 */
static int zs_migrate_page(struct address_space *mapping,
			   struct page *newpage,
			   struct page *page, enum migrate_mode mode)
{
	struct zs_pool *pool = (struct zs_pool *)page->mapping->private_data;
	struct size_class *class;
	enum fullness_group fullness;
	unsigned int index = 0, offset = 0;
	unsigned long head, handle, obj;
	void *vaddr, *newvaddr;
	struct page *next_page;
	struct page *first_page = get_first_page(page);
	int unpinned = 0;

	BUG_ON(!is_page_isolated(first_page));

	get_zspage_meta(first_page, &index, &fullness);
	class = pool->size_class[index];

	/*
	 * Copy the page contents first to avoid a potential race when moving
	 * a first page.
	 */
	newvaddr = kmap_atomic(newpage);
	vaddr = kmap_atomic(page);
	copy_page(newvaddr, vaddr);
	kunmap_atomic(vaddr);
	kunmap_atomic(newvaddr);

	/*
	 * Take the old page out of migrate's list and insert the new one back
	 * into one of our's.  First pages go into a fullness list.  Sub-pages
	 * need to slip back into their sequence.
	 */
	list_del(&page->lru);
	if (is_first_page(page)) {
		/* Update any sub-pages' first_page. */
		next_page = get_next_page(page);
		while (next_page) {
			next_page->first_page = newpage;
			next_page = get_next_page(next_page);
		}

		/* Move the first page's private and meta. */
		SetPagePrivate(newpage);
		set_page_private(newpage, page_private(page));
		newpage->freelist = page->freelist;

		first_page = newpage;
	} else {
		/* Copy sub-page glue. */
		newpage->first_page = first_page;
		newpage->index = page->index;

		/*
		 * Put the new page back into the correct position of the
		 * sub-page list.
		 */
		zs_migrate_putback_sub_page(class, first_page, newpage,
					    get_subpage_index(page));
		clear_subpage_index(page);
	}

	/* Move special flags and mapping */
	if (is_last_page(page)) {
		SetPagePrivate2(newpage);
		ClearPagePrivate2(page);
	}
	SetPageMobile(newpage);
	ClearPageMobile(page);
	newpage->mapping = page->mapping;
	page->mapping = NULL;

	/*
	 * Now that the zspage is stitched back together, put it back into the
	 * appropriate fullness list.  We hold the class lock to prevent races
	 * with obj_malloc()/obj_free() between the fullness list and the
	 * object pins.
	 */
	INIT_LIST_HEAD(&first_page->lru);
	spin_lock(&class->lock);
	fullness = get_fullness_group(class, first_page);
	insert_zspage(first_page, class, fullness);
	set_zspage_meta(first_page, class->index, fullness);

	/*
	 * Unpin all of the allocated objects in the page, and point the
	 * relevant object handles to their new location.  The handles are
	 * abstract and so their values within the page can be left alone.  The
	 * embedded handles of "non-huge" zspages are found at the head of each
	 * allocated object within the page.
	 */
	if (!is_first_page(newpage))
		offset = newpage->index;

	if (!class->huge)
		newvaddr = kmap_atomic(newpage);

	while (offset < PAGE_SIZE) {
		if (class->huge) {
			head = page_private(newpage);
			offset = PAGE_SIZE;
		} else
			head = *(unsigned long *)(newvaddr + offset);
		if (head & OBJ_ALLOCATED_TAG) {
			handle = head & ~OBJ_ALLOCATED_TAG;
			obj = handle_to_obj(handle);

			/*
			 * Update the object with the new page PFN, preserving
			 * the index and tag bit.
			 */
			obj = obj_new_page(obj, newpage);
			record_obj(handle, obj);
			unpin_tag(handle);
			unpinned++;
		}

		offset += class->size;
		index++;
	}

	if (!class->huge)
		kunmap_atomic(newvaddr);

	/* Clear the isolation state of the zspage (and the old first page). */
	clear_page_isolated(first_page);
	if (is_first_page(page)) {
		clear_page_isolated(page);
		ClearPagePrivate(page);
	}

	/*
	 * If a free happened to an object on a different page in the zspage and
	 * the zspage was nearly empty, we completely wasted our time.  We need
	 * to free the zspage, since it was deferred from obj_free().
	 */
	zs_free_if_empty(pool, class, first_page, fullness);

	zs_stat_inc(class, PAGES_MOVED, 1);
	spin_unlock(&class->lock);

	pool->stats.pages_moved++;

	return MIGRATEPAGE_MOBILE_SUCCESS;	/* failure is not an option! */
}

const struct address_space_operations zspool_aops = {
	.isolatepage = zs_migrate_isolate,
	.putbackpage = zs_migrate_putback,
	.migratepage = zs_migrate_page,
};

/**
 * zs_create_pool - Creates an allocation pool to work from.
 * @flags: allocation flags used to allocate pool metadata
 *
 * This function must be called before anything when using
 * the zsmalloc allocator.
 *
 * On success, a pointer to the newly created pool is returned,
 * otherwise NULL.
 */
struct zs_pool *zs_create_pool(char *name, gfp_t flags)
{
	int i;
	struct zs_pool *pool;
	struct size_class *prev_class = NULL;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	pool->size_class = kcalloc(zs_size_classes, sizeof(struct size_class *),
			GFP_KERNEL);
	if (!pool->size_class) {
		kfree(pool);
		return NULL;
	}

	pool->name = kstrdup(name, GFP_KERNEL);
	if (!pool->name)
		goto err;

	if (create_handle_cache(pool))
		goto err;

	/*
	 * Construct an anonymous inode for this pool that provides page
	 * migration callbacks.
	 */
	pool->inode = anon_inode_new();
	pool->inode->i_mapping->a_ops = &zspool_aops;
	pool->inode->i_mapping->private_data = pool;

	/*
	 * Iterate reversly, because, size of size_class that we want to use
	 * for merging should be larger or equal to current size.
	 */
	for (i = zs_size_classes - 1; i >= 0; i--) {
		int size;
		int pages_per_zspage;
		struct size_class *class;

		size = ZS_MIN_ALLOC_SIZE + i * ZS_SIZE_CLASS_DELTA;
		if (size > ZS_MAX_ALLOC_SIZE)
			size = ZS_MAX_ALLOC_SIZE;
		pages_per_zspage = get_pages_per_zspage(size);

		/*
		 * size_class is used for normal zsmalloc operation such
		 * as alloc/free for that size. Although it is natural that we
		 * have one size_class for each size, there is a chance that we
		 * can get more memory utilization if we use one size_class for
		 * many different sizes whose size_class have same
		 * characteristics. So, we makes size_class point to
		 * previous size_class if possible.
		 */
		if (prev_class) {
			if (can_merge(prev_class, size, pages_per_zspage)) {
				pool->size_class[i] = prev_class;
				continue;
			}
		}

		class = kzalloc(sizeof(struct size_class), GFP_KERNEL);
		if (!class)
			goto err;

		class->pool = pool;
		class->size = size;
		class->index = i;
		class->pages_per_zspage = pages_per_zspage;
		class->max_objects = class->pages_per_zspage * PAGE_SIZE / class->size;
		if (pages_per_zspage == 1 &&
			get_maxobj_per_zspage(size, pages_per_zspage) == 1)
			class->huge = true;
		spin_lock_init(&class->lock);
		pool->size_class[i] = class;

		prev_class = class;
	}

	pool->flags = flags;

	/*
	 * Make sure that we mark pages movable when mobile page compaction is
	 * is enabled and that we don't mark them if it is not.
	 */
	if (sysctl_mobile_page_compaction)
		pool->flags |= __GFP_MOVABLE;
	else
		pool->flags &= ~__GFP_MOVABLE;

	if (zs_pool_stat_create(name, pool))
		goto err;

	/*
	 * Not critical, we still can use the pool
	 * and user can trigger compaction manually.
	 */
	if (zs_register_shrinker(pool) == 0)
		pool->shrinker_enabled = true;
	return pool;

err:
	zs_destroy_pool(pool);
	return NULL;
}
EXPORT_SYMBOL_GPL(zs_create_pool);

void zs_destroy_pool(struct zs_pool *pool)
{
	int i;

	zs_unregister_shrinker(pool);
	zs_pool_stat_destroy(pool);

	for (i = 0; i < zs_size_classes; i++) {
		int fg;
		struct size_class *class = pool->size_class[i];

		if (!class)
			continue;

		if (class->index != i)
			continue;

		for (fg = 0; fg < ZS_EMPTY; fg++) {
			if (class->fullness_list[fg]) {
				pr_info("Freeing non-empty class with size %db, fullness group %d\n",
					class->size, fg);
			}
		}
		kfree(class);
	}

	destroy_handle_cache(pool);
	kfree(pool->size_class);
	kfree(pool->name);
	kfree(pool);
}
EXPORT_SYMBOL_GPL(zs_destroy_pool);

static int __init zs_init(void)
{
	int ret = zs_register_cpu_notifier();

	if (ret)
		goto notifier_fail;

	BUILD_BUG_ON(sizeof(unsigned long) * 8 < (FREE_OBJ_IDX_BITS +
		CLASS_IDX_BITS + FULLNESS_BITS + INUSE_BITS + ETC_BITS));

	init_zs_size_classes();

#ifdef CONFIG_ZPOOL
	zpool_register_driver(&zs_zpool_driver);
#endif

	ret = zs_stat_init();
	if (ret) {
		pr_err("zs stat initialization failed\n");
		goto stat_fail;
	}
	return 0;

stat_fail:
#ifdef CONFIG_ZPOOL
	zpool_unregister_driver(&zs_zpool_driver);
#endif
notifier_fail:
	zs_unregister_cpu_notifier();

	return ret;
}

static void __exit zs_exit(void)
{
#ifdef CONFIG_ZPOOL
	zpool_unregister_driver(&zs_zpool_driver);
#endif
	zs_unregister_cpu_notifier();

	zs_stat_exit();
}

module_init(zs_init);
module_exit(zs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
