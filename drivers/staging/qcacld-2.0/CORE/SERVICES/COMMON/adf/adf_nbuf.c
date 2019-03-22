/*
 * Copyright (c) 2013-2018 The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */


#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <adf_os_types.h>
#include <adf_nbuf.h>
#include <adf_os_io.h>
#include <adf_os_lock.h>
#include <net/ieee80211_radiotap.h>
#include "adf_trace.h"
#include "vos_trace.h"
#include <vos_api.h>
#include <adf_os_atomic.h>
#include <adf_os_time.h>

#ifdef CONFIG_WCNSS_MEM_PRE_ALLOC
#include <net/cnss_prealloc.h>
#endif

/* Packet Counter */
static uint32_t nbuf_tx_mgmt[NBUF_TX_PKT_STATE_MAX];
static uint32_t nbuf_tx_data[NBUF_TX_PKT_STATE_MAX];

/**
 * adf_nbuf_tx_desc_count_display() - Displays the packet counter
 *
 * Return: none
 */
void adf_nbuf_tx_desc_count_display(void)
{
	adf_os_print("Current Snapshot of the Driver:\n");
	adf_os_print("Data Packets:\n");
	adf_os_print("HDD %d TXRX_Q %d TXRX %d HTT %d",
		     nbuf_tx_data[NBUF_TX_PKT_HDD] -
		     (nbuf_tx_data[NBUF_TX_PKT_TXRX] +
		     nbuf_tx_data[NBUF_TX_PKT_TXRX_ENQUEUE] -
		     nbuf_tx_data[NBUF_TX_PKT_TXRX_DEQUEUE]),
		     nbuf_tx_data[NBUF_TX_PKT_TXRX_ENQUEUE] -
		     nbuf_tx_data[NBUF_TX_PKT_TXRX_DEQUEUE],
		     (nbuf_tx_data[NBUF_TX_PKT_TXRX] -
		     nbuf_tx_data[NBUF_TX_PKT_HTT]),
		     (nbuf_tx_data[NBUF_TX_PKT_HTT]  -
		     nbuf_tx_data[NBUF_TX_PKT_HTC]));
	adf_os_print(" HTC %d  HIF %d CE %d TX_COMP %d\n",
		     (nbuf_tx_data[NBUF_TX_PKT_HTC]  -
		     nbuf_tx_data[NBUF_TX_PKT_HIF]),
		     (nbuf_tx_data[NBUF_TX_PKT_HIF]  -
		     nbuf_tx_data[NBUF_TX_PKT_CE]),
		     (nbuf_tx_data[NBUF_TX_PKT_CE]   -
		     nbuf_tx_data[NBUF_TX_PKT_FREE]),
		     nbuf_tx_data[NBUF_TX_PKT_FREE]);
	adf_os_print("Mgmt Packets:\n");
	adf_os_print("TXRX %d HTT %d HTC %d HIF %d CE %d TX_COMP %d\n",
		     (nbuf_tx_mgmt[NBUF_TX_PKT_TXRX] -
		     nbuf_tx_mgmt[NBUF_TX_PKT_HTT]),
		     (nbuf_tx_mgmt[NBUF_TX_PKT_HTT]  -
		     nbuf_tx_mgmt[NBUF_TX_PKT_HTC]),
		     (nbuf_tx_mgmt[NBUF_TX_PKT_HTC]  -
		     nbuf_tx_mgmt[NBUF_TX_PKT_HIF]),
		     (nbuf_tx_mgmt[NBUF_TX_PKT_HIF]  -
		     nbuf_tx_mgmt[NBUF_TX_PKT_CE]),
		     (nbuf_tx_mgmt[NBUF_TX_PKT_CE]   -
		     nbuf_tx_mgmt[NBUF_TX_PKT_FREE]),
		     nbuf_tx_mgmt[NBUF_TX_PKT_FREE]);
}

/**
 * adf_nbuf_tx_desc_count_update() - Updates the layer packet counter
 * @packet_type   : packet type either mgmt/data
 * @current_state : layer at which the packet currently present
 *
 * Return: none
 */
static inline void adf_nbuf_tx_desc_count_update(uint8_t packet_type,
							uint8_t current_state)
{
	switch (packet_type) {
	case NBUF_TX_PKT_MGMT_TRACK:
		nbuf_tx_mgmt[current_state]++;
		break;
	case NBUF_TX_PKT_DATA_TRACK:
		nbuf_tx_data[current_state]++;
		break;
	default:
		break;
	}
}

/**
 * adf_nbuf_tx_desc_count_clear() - Clears packet counter for both data, mgmt
 *
 * Return: none
 */
void adf_nbuf_tx_desc_count_clear(void)
{
	memset(nbuf_tx_mgmt, 0, sizeof(nbuf_tx_mgmt));
	memset(nbuf_tx_data, 0, sizeof(nbuf_tx_data));
}

/**
 * adf_nbuf_set_state() - Updates the packet state
 * @nbuf:            network buffer
 * @current_state :  layer at which the packet currently is
 *
 * This function updates the packet state to the layer at which the packet
 * currently is
 *
 * Return: none
 */
void adf_nbuf_set_state(adf_nbuf_t nbuf, uint8_t current_state)
{
	/*
	 * Only Mgmt, Data Packets are tracked. WMI messages
	 * such as scan commands are not tracked
	 */
	uint8_t packet_type;

	packet_type = NBUF_GET_PACKET_TRACK(nbuf);

	if ((packet_type != NBUF_TX_PKT_DATA_TRACK) &&
	    (packet_type != NBUF_TX_PKT_MGMT_TRACK)) {
		return;
	}
	NBUF_SET_PACKET_STATE(nbuf, current_state);
	adf_nbuf_tx_desc_count_update(packet_type,
				      current_state);
}

adf_nbuf_trace_update_t  trace_update_cb = NULL;

#if defined(CONFIG_WCNSS_MEM_PRE_ALLOC) && defined(FEATURE_SKB_PRE_ALLOC)
struct sk_buff *__adf_nbuf_pre_alloc(adf_os_device_t osdev, size_t size)
{
	struct sk_buff *skb = NULL;

	if (size >= WCNSS_PRE_SKB_ALLOC_GET_THRESHOLD)
		skb = wcnss_skb_prealloc_get(size);

	return skb;
}

int __adf_nbuf_pre_alloc_free(struct sk_buff *skb)
{
	return wcnss_skb_prealloc_put(skb);
}
#else
struct sk_buff *__adf_nbuf_pre_alloc(adf_os_device_t osdev, size_t size)
{
	return NULL;
}

int __adf_nbuf_pre_alloc_free(struct sk_buff *skb)
{
	return 0;
}
#endif

/*
 * @brief This allocates an nbuf aligns if needed and reserves
 *        some space in the front, since the reserve is done
 *        after alignment the reserve value if being unaligned
 *        will result in an unaligned address.
 *
 * @param hdl
 * @param size
 * @param reserve
 * @param align
 *
 * @return nbuf or NULL if no memory
 */
struct sk_buff *
__adf_nbuf_alloc(adf_os_device_t osdev, size_t size, int reserve, int align, int prio)
{
    struct sk_buff *skb;
    unsigned long offset;
    int flags = GFP_KERNEL;

    if(align)
        size += (align - 1);

    if (in_interrupt() || irqs_disabled() || in_atomic())
        flags = GFP_ATOMIC;

    skb = __netdev_alloc_skb(NULL, size, flags);

    if (skb)
       goto skb_cb;

    skb = __adf_nbuf_pre_alloc(osdev, size);

    if (!skb) {
        printk("ERROR:NBUF alloc failed\n");
        return NULL;
    }

skb_cb:
    memset(skb->cb, 0x0, sizeof(skb->cb));

    /*
     * The default is for netbuf fragments to be interpreted
     * as wordstreams rather than bytestreams.
     * Set the CVG_NBUF_MAX_EXTRA_FRAGS+1 wordstream_flags bits,
     * to provide this default.
     */
    NBUF_EXTRA_FRAG_WORDSTREAM_FLAGS(skb) =
        (1 << (CVG_NBUF_MAX_EXTRA_FRAGS + 1)) - 1;

    /**
     * XXX:how about we reserve first then align
     */

    /**
     * Align & make sure that the tail & data are adjusted properly
     */
    if(align){
        offset = ((unsigned long) skb->data) % align;
        if(offset)
            skb_reserve(skb, align - offset);
    }

    /**
     * NOTE:alloc doesn't take responsibility if reserve unaligns the data
     * pointer
     */
    skb_reserve(skb, reserve);

    return skb;
}

#ifdef QCA_ARP_SPOOFING_WAR
/*
 * __adf_rx_nbuf_alloc() Rx buffer allocation function *
 * @hdl:
 * @size:
 * @reserve:
 * @align:
 *
 * Use existing buffer allocation API and overwrite
 * priv_data field of skb->cb for registering callback
 * as it is not used for Rx case.
 *
 * Return: nbuf or NULL if no memory
 */
struct sk_buff *
__adf_rx_nbuf_alloc(adf_os_device_t osdev, size_t size, int reserve, int align, int prio)
{
    struct sk_buff *skb;

    skb = __adf_nbuf_alloc(osdev, size, reserve,align, prio);
    if (skb) {
        NBUF_CB_PTR(skb) = osdev->filter_cb;
    }
    return skb;
}
#endif
/*
 * @brief free the nbuf its interrupt safe
 * @param skb
 */
void
__adf_nbuf_free(struct sk_buff *skb)
{
#ifdef QCA_MDM_DEVICE
#if defined(IPA_OFFLOAD) && (!defined(IPA_UC_OFFLOAD) ||\
   (defined(IPA_UC_OFFLOAD) && defined(IPA_UC_STA_OFFLOAD)))
    if( (NBUF_OWNER_ID(skb) == IPA_NBUF_OWNER_ID) && NBUF_CALLBACK_FN(skb) )
        NBUF_CALLBACK_FN_EXEC(skb);
    else
#endif
#endif /* QCA_MDM_DEVICE */
    {
       if (__adf_nbuf_pre_alloc_free(skb))
           return;
       dev_kfree_skb_any(skb);
    }
}


/*
 * @brief Reference the nbuf so it can get held until the last free.
 * @param skb
 */

void
__adf_nbuf_ref(struct sk_buff *skb)
{
    skb_get(skb);
}

/**
 *  @brief Check whether the buffer is shared
 *  @param skb: buffer to check
 *
 *  Returns true if more than one person has a reference to this
 *  buffer.
 */
int
__adf_nbuf_shared(struct sk_buff *skb)
{
    return skb_shared(skb);
}
/**
 * @brief create a nbuf map
 * @param osdev
 * @param dmap
 *
 * @return a_status_t
 */
a_status_t
__adf_nbuf_dmamap_create(adf_os_device_t osdev, __adf_os_dma_map_t *dmap)
{
    a_status_t error = A_STATUS_OK;
    /**
     * XXX: driver can tell its SG capablity, it must be handled.
     * XXX: Bounce buffers if they are there
     */
    (*dmap) = kzalloc(sizeof(struct __adf_os_dma_map), GFP_KERNEL);
    if(!(*dmap))
        error = A_STATUS_ENOMEM;

    return error;
}

/**
 * @brief free the nbuf map
 *
 * @param osdev
 * @param dmap
 */
void
__adf_nbuf_dmamap_destroy(adf_os_device_t osdev, __adf_os_dma_map_t dmap)
{
    kfree(dmap);
}

#ifdef NBUF_MAP_UNMAP_DEBUG

/**
 * DEFINE_ADF_FLEX_MEM_POOL() - define a new flex mem pool with one segment
 * @name: the name of the pool variable
 * @size_of_item: size of the items the pool will allocate
 * @rm_limit: min number of segments to keep during reduction
 */
#define DEFINE_ADF_FLEX_MEM_POOL(name, size_of_item, rm_limit) \
	struct adf_flex_mem_pool name; \
	uint8_t __ ## name ## _head_bytes[ADF_FM_BITMAP_BITS * (size_of_item)];\
	struct adf_flex_mem_segment __ ## name ## _head = { \
		.node = VOS_LIST_NODE_INIT_SINGLE( \
			VOS_LIST_ANCHOR(name.seg_list)), \
		.bytes = __ ## name ## _head_bytes, \
	}; \
	struct adf_flex_mem_pool name = { \
		.reduction_limit = (rm_limit), \
		.item_size = (size_of_item), \
	}

/**
 * adf_flex_mem_pool - a pool of memory segments
 * @seg_list: the list containing the memory segments
 * @lock: spinlock for protecting internal data structures
 * @reduction_limit: the minimum number of segments to keep during reduction
 * @item_size: the size of the items the pool will allocate
 */
struct adf_flex_mem_pool {
	vos_list_t seg_list;
	adf_os_spinlock_t lock;
	uint16_t reduction_limit;
	uint16_t item_size;
};

/**
 * adf_flex_mem_segment - a memory pool segment
 * @node: the list node for membership in the memory pool
 * @dynamic: true if this segment was dynamically allocated
 * @used_bitmap: bitmap for tracking which items in the segment are in use
 * @bytes: raw memory for allocating items from
 */
struct adf_flex_mem_segment {
	vos_list_node_t node;
	bool dynamic;
	uint32_t used_bitmap;
	uint8_t *bytes;
};
#define ADF_NBUF_HISTORY_SIZE 4096

static adf_os_atomic_t adf_nbuf_history_index;
static struct adf_nbuf_event adf_nbuf_history[ADF_NBUF_HISTORY_SIZE];

static int32_t adf_nbuf_circular_index_next(adf_os_atomic_t *index, int size)
{
	int32_t next = adf_os_atomic_inc_return(index);

	if (next == size)
		adf_os_atomic_sub(size, index);

	return next % size;
}

void
adf_nbuf_history_add(adf_nbuf_t nbuf, const char *file, uint32_t line,
		     enum adf_nbuf_event_type type)
{
	int32_t idx = adf_nbuf_circular_index_next(&adf_nbuf_history_index,
						   ADF_NBUF_HISTORY_SIZE);
	struct adf_nbuf_event *event = &adf_nbuf_history[idx];

	event->nbuf = nbuf;
	strlcpy(event->file, kbasename(file), ADF_MEM_FILE_NAME_SIZE);
	event->line = line;
	event->type = type;
	event->timestamp = adf_os_ticks();
}

DEFINE_ADF_FLEX_MEM_POOL(adf_nbuf_map_pool,
			 sizeof(struct adf_nbuf_map_metadata), 0);
#define ADF_NBUF_MAP_HT_BITS 10 /* 1024 buckets */
static DECLARE_HASHTABLE(adf_nbuf_map_ht, ADF_NBUF_MAP_HT_BITS);
static adf_os_spinlock_t adf_nbuf_map_lock;

static void __adf_flex_mem_release(struct adf_flex_mem_pool *pool)
{
	struct adf_flex_mem_segment *seg;
	struct adf_flex_mem_segment *next;

	list_for_each_entry_safe(seg, next, &(pool->seg_list.anchor), node) {
		if (!seg->dynamic)
			continue;

		if (seg->used_bitmap != 0)
			continue;

		vos_list_remove_node_no_mutex(&pool->seg_list, &seg->node);
		vos_mem_free(seg);
	}
}

void adf_flex_mem_release(struct adf_flex_mem_pool *pool)
{
	VOS_BUG(pool);
	if (!pool)
		return;

	adf_os_spin_lock_bh(&pool->lock);
	__adf_flex_mem_release(pool);
	adf_os_spin_unlock_bh(&pool->lock);
}

void adf_flex_mem_deinit(struct adf_flex_mem_pool *pool)
{
	v_SIZE_t pSize = 0;
	adf_flex_mem_release(pool);
	if (vos_list_size_no_mutex(&pool->seg_list, &pSize) ==
	    VOS_STATUS_SUCCESS)
		VOS_BUG(!pSize);
	else
		adf_print("%s seg list get ailed",__func__);

	adf_os_spinlock_destroy(&pool->lock);
}

static struct adf_flex_mem_segment *
adf_flex_mem_seg_alloc(struct adf_flex_mem_pool *pool)
{
	struct adf_flex_mem_segment *seg;
	size_t total_size = sizeof(struct adf_flex_mem_segment) +
		pool->item_size * ADF_FM_BITMAP_BITS;

	seg = vos_mem_malloc(total_size);
	if (!seg)
		return NULL;

	seg->dynamic = true;
	seg->bytes = (uint8_t *)(seg + 1);
	seg->used_bitmap = 0;
	vos_list_insert_back_no_mutex(&pool->seg_list, &seg->node);

	return seg;
}

void adf_flex_mem_init(struct adf_flex_mem_pool *pool)
{
	int i;

	adf_os_spinlock_init(&pool->lock);
	vos_list_init(&pool->seg_list);
	for (i = 0; i < pool->reduction_limit; i++)
		adf_flex_mem_seg_alloc(pool);
}

static void *__adf_flex_mem_alloc(struct adf_flex_mem_pool *pool)
{
	struct adf_flex_mem_segment *seg;

	list_for_each_entry(seg, &(pool->seg_list.anchor), node) {
		int index;
		void *ptr;

		index = adf_ffz(seg->used_bitmap);
		if (index < 0)
			continue;

		VOS_BUG(index < ADF_FM_BITMAP_BITS);

		seg->used_bitmap ^= (ADF_FM_BITMAP)1 << index;
		ptr = &seg->bytes[index * pool->item_size];
		vos_mem_zero(ptr, pool->item_size);

		return ptr;
	}

	seg = adf_flex_mem_seg_alloc(pool);
	if (!seg)
		return NULL;

	seg->used_bitmap = 1;

	return seg->bytes;
}

void *adf_flex_mem_alloc(struct adf_flex_mem_pool *pool)
{
	void *ptr;

	VOS_BUG(pool);
	if (!pool)
		return NULL;

	adf_os_spin_lock_bh(&pool->lock);
	ptr = __adf_flex_mem_alloc(pool);
	adf_os_spin_unlock_bh(&pool->lock);

	return ptr;
}

static void adf_flex_mem_seg_free(struct adf_flex_mem_pool *pool,
				  struct adf_flex_mem_segment *seg)
{
	v_SIZE_t pSize = 0;
	if (!seg->dynamic)
		return;

	if (vos_list_size_no_mutex(&pool->seg_list, &pSize) ==
	    VOS_STATUS_SUCCESS) {
		if (pSize <= pool->reduction_limit)
			return;
	} else {
		adf_print("%s seg list size get failed", __func__);
	}

	vos_list_remove_node_no_mutex(&pool->seg_list, &seg->node);
	vos_mem_free(seg);
}

static void __adf_flex_mem_free(struct adf_flex_mem_pool *pool, void *ptr)
{
	struct adf_flex_mem_segment *seg;
	void *low_addr;
	void *high_addr;
	unsigned long index;

	list_for_each_entry(seg, &(pool->seg_list.anchor), node) {
		low_addr = seg->bytes;
		high_addr = low_addr + pool->item_size * ADF_FM_BITMAP_BITS;

		if (ptr < low_addr || ptr > high_addr)
			continue;

		index = (ptr - low_addr) / pool->item_size;
		VOS_BUG(index < ADF_FM_BITMAP_BITS);

		seg->used_bitmap ^= (ADF_FM_BITMAP)1 << index;
		if (!seg->used_bitmap)
			adf_flex_mem_seg_free(pool, seg);

		return;
	}

	adf_print("Failed to find pointer in segment pool");
}

void adf_flex_mem_free(struct adf_flex_mem_pool *pool, void *ptr)
{
	VOS_BUG(pool);
	if (!pool)
		return;

	VOS_BUG(ptr);
	if (!ptr)
		return;

	adf_os_spin_lock_bh(&pool->lock);
	__adf_flex_mem_free(pool, ptr);
	adf_os_spin_unlock_bh(&pool->lock);
}

static void adf_nbuf_map_tracking_init(void)
{
	adf_flex_mem_init(&adf_nbuf_map_pool);
	hash_init(adf_nbuf_map_ht);
	adf_os_spinlock_init(&adf_nbuf_map_lock);
}

void adf_nbuf_map_check_for_leaks(void)
{
	struct adf_nbuf_map_metadata *meta;
	int bucket;
	uint32_t count = 0;
	bool is_empty;

	adf_flex_mem_release(&adf_nbuf_map_pool);
	adf_os_spin_lock_irqsave(&adf_nbuf_map_lock);
	is_empty = hash_empty(adf_nbuf_map_ht);
	adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);

	if (is_empty)
		return;

	adf_print("Nbuf map without unmap events detected!");
	adf_print("------------------------------------------------------------");

	/* Hold the lock for the entire iteration for safe list/meta access. We
	 * are explicitly preferring the chance to watchdog on the print, over
	 * the posibility of invalid list/memory access. Since we are going to
	 * panic anyway, the worst case is loading up the crash dump to find out
	 * what was in the hash table.
	 */
	adf_os_spin_lock_irqsave(&adf_nbuf_map_lock);
	hash_for_each(adf_nbuf_map_ht, bucket, meta, node) {
		count++;
		adf_print("0x%pk @ %s:%u",
			meta->nbuf, meta->file, meta->line);
	}
	adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);

	adf_print("%u fatal nbuf map without unmap events detected!", count);
}

static void adf_nbuf_map_tracking_deinit(void)
{
	adf_nbuf_map_check_for_leaks();
	adf_os_spinlock_destroy(&adf_nbuf_map_lock);
	adf_flex_mem_deinit(&adf_nbuf_map_pool);
}

static struct adf_nbuf_map_metadata *adf_nbuf_meta_get(adf_nbuf_t nbuf)
{
	struct adf_nbuf_map_metadata *meta;

	hash_for_each_possible(adf_nbuf_map_ht, meta, node, (size_t)nbuf) {
		if (meta->nbuf == nbuf)
			return meta;
	}

	return NULL;
}

static a_status_t
adf_nbuf_track_map(adf_nbuf_t nbuf, const char *file, uint32_t line)
{
	struct adf_nbuf_map_metadata *meta;

	VOS_BUG(nbuf);
	if (!nbuf) {
		adf_print("Cannot map null nbuf");
		return A_STATUS_EINVAL;
	}

	adf_os_spin_lock_irqsave(&adf_nbuf_map_lock);
	meta = adf_nbuf_meta_get(nbuf);
	adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);
	if (meta) {
		adf_print(
			"Double nbuf map detected @ %s:%u; last map from %s:%u",
			kbasename(file), line, meta->file, meta->line);
		VOS_BUG(0);
		return A_STATUS_EINVAL;
	}

	meta = adf_flex_mem_alloc(&adf_nbuf_map_pool);
	if (!meta) {
		adf_print("Failed to allocate nbuf map tracking metadata");
		return A_STATUS_ENOMEM;
	}

	meta->nbuf = nbuf;
	strlcpy(meta->file, kbasename(file), ADF_MEM_FILE_NAME_SIZE);
	meta->line = line;

	adf_os_spin_lock_irqsave(&adf_nbuf_map_lock);
	hash_add(adf_nbuf_map_ht, &meta->node, (size_t)nbuf);
	adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);

	adf_nbuf_history_add(nbuf, file, line, ADF_NBUF_MAP);

	return A_STATUS_OK;
}

static void
adf_nbuf_untrack_map(adf_nbuf_t nbuf, const char *file, uint32_t line)
{
	struct adf_nbuf_map_metadata *meta;

	VOS_BUG(nbuf);
	if (!nbuf) {
		adf_print("Cannot unmap null nbuf");
		return;
	}

	adf_os_spin_lock_irqsave(&adf_nbuf_map_lock);
	meta = adf_nbuf_meta_get(nbuf);

	if (!meta) {
		adf_print(
		      "Double nbuf unmap or unmap without map detected @ %s:%u",
		      kbasename(file), line);
		adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);
		VOS_BUG(0);
		return;
	}

	hash_del(&meta->node);
	adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);

	adf_flex_mem_free(&adf_nbuf_map_pool, meta);

	adf_nbuf_history_add(nbuf, file, line, ADF_NBUF_UNMAP);
}

a_status_t adf_nbuf_map_debug(adf_os_device_t osdev,
			      adf_nbuf_t buf,
			      adf_os_dma_dir_t dir,
			      const char *file,
			      uint32_t line)
{
	a_status_t status;

	status = adf_nbuf_track_map(buf, file, line);
	if (status)
		return status;

	status = __adf_nbuf_map(osdev, buf, dir);
	if (status)
		adf_nbuf_untrack_map(buf, file, line);

	return status;
}

void adf_nbuf_unmap_debug(adf_os_device_t osdev,
			  adf_nbuf_t buf,
			  adf_os_dma_dir_t dir,
			  const char *file,
			  uint32_t line)
{
	adf_nbuf_untrack_map(buf, file, line);
	__adf_nbuf_unmap_single(osdev, buf, dir);
}

a_status_t adf_nbuf_map_single_debug(adf_os_device_t osdev,
				     adf_nbuf_t buf,
				     adf_os_dma_dir_t dir,
				     const char *file,
				     uint32_t line)
{
	a_status_t status;

	status = adf_nbuf_track_map(buf, file, line);
	if (status)
		return status;

	status = __adf_nbuf_map_single(osdev, buf, dir);
	if (status)
		adf_nbuf_untrack_map(buf, file, line);

	return status;
}

void adf_nbuf_unmap_single_debug(adf_os_device_t osdev,
				 adf_nbuf_t buf,
				 adf_os_dma_dir_t dir,
				 const char *file,
				 uint32_t line)
{
	adf_nbuf_untrack_map(buf, file, line);
	__adf_nbuf_unmap_single(osdev, buf, dir);
}

static void adf_nbuf_panic_on_free_if_mapped(adf_nbuf_t nbuf, uint8_t *file,
					     uint32_t line)
{
	struct adf_nbuf_map_metadata *meta;

	adf_os_spin_lock_irqsave(&adf_nbuf_map_lock);
	meta = adf_nbuf_meta_get(nbuf);
	if (meta)
		adf_print(
			"Nbuf freed @ %s:%u while mapped from %s:%u",
			kbasename(file), line, meta->file, meta->line);
	adf_os_spin_unlock_irqrestore(&adf_nbuf_map_lock);
}
#else
static inline void adf_nbuf_map_tracking_init(void)
{
}

static inline void adf_nbuf_map_tracking_deinit(void)
{
}

static inline void adf_nbuf_panic_on_free_if_mapped(adf_nbuf_t nbuf,
						    uint8_t *file,
						    uint32_t line)
{
}
#endif
/**
 * @brief get the dma map of the nbuf
 *
 * @param osdev
 * @param bmap
 * @param skb
 * @param dir
 *
 * @return a_status_t
 */
a_status_t
__adf_nbuf_map(
    adf_os_device_t osdev,
    struct sk_buff *skb,
    adf_os_dma_dir_t dir)
{
#ifdef ADF_OS_DEBUG
    struct skb_shared_info  *sh = skb_shinfo(skb);
#endif
    adf_os_assert(
        (dir == ADF_OS_DMA_TO_DEVICE) || (dir == ADF_OS_DMA_FROM_DEVICE));

    /*
     * Assume there's only a single fragment.
     * To support multiple fragments, it would be necessary to change
     * adf_nbuf_t to be a separate object that stores meta-info
     * (including the bus address for each fragment) and a pointer
     * to the underlying sk_buff.
     */
    adf_os_assert(sh->nr_frags == 0);

    return __adf_nbuf_map_single(osdev, skb, dir);

    return A_STATUS_OK;
}

/**
 * @brief adf_nbuf_unmap() - to unmap a previously mapped buf
 */
void
__adf_nbuf_unmap(
    adf_os_device_t osdev,
    struct sk_buff *skb,
    adf_os_dma_dir_t dir)
{
    adf_os_assert(
        (dir == ADF_OS_DMA_TO_DEVICE) || (dir == ADF_OS_DMA_FROM_DEVICE));

    adf_os_assert(((dir == ADF_OS_DMA_TO_DEVICE) || (dir == ADF_OS_DMA_FROM_DEVICE)));
    /*
     * Assume there's a single fragment.
     * If this is not true, the assertion in __adf_nbuf_map will catch it.
     */
    __adf_nbuf_unmap_single(osdev, skb, dir);
}

a_status_t
__adf_nbuf_map_single(
    adf_os_device_t osdev, adf_nbuf_t buf, adf_os_dma_dir_t dir)
{
    u_int32_t paddr_lo;

/* tempory hack for simulation */
#ifdef A_SIMOS_DEVHOST
    NBUF_MAPPED_PADDR_LO(buf) = paddr_lo = (u_int32_t) buf->data;
    return A_STATUS_OK;
#else
    /* assume that the OS only provides a single fragment */
    NBUF_MAPPED_PADDR_LO(buf) = paddr_lo =
        dma_map_single(osdev->dev, buf->data,
                       skb_end_pointer(buf) - buf->data, dir);
    return dma_mapping_error(osdev->dev, paddr_lo) ?
        A_STATUS_FAILED : A_STATUS_OK;
#endif	/* #ifdef A_SIMOS_DEVHOST */
}

void
__adf_nbuf_unmap_single(
    adf_os_device_t osdev, adf_nbuf_t buf, adf_os_dma_dir_t dir)
{
#if !defined(A_SIMOS_DEVHOST)
    dma_unmap_single(osdev->dev, NBUF_MAPPED_PADDR_LO(buf),
                     skb_end_pointer(buf) - buf->data, dir);
#endif	/* #if !defined(A_SIMOS_DEVHOST) */
}

/**
 * @brief return the dma map info
 *
 * @param[in]  bmap
 * @param[out] sg (map_info ptr)
 */
void
__adf_nbuf_dmamap_info(__adf_os_dma_map_t bmap, adf_os_dmamap_info_t *sg)
{
    adf_os_assert(bmap->mapped);
    adf_os_assert(bmap->nsegs <= ADF_OS_MAX_SCATTER);

    memcpy(sg->dma_segs, bmap->seg, bmap->nsegs *
           sizeof(struct __adf_os_segment));
    sg->nsegs = bmap->nsegs;
}
/**
 * @brief return the frag data & len, where frag no. is
 *        specified by the index
 *
 * @param[in] buf
 * @param[out] sg (scatter/gather list of all the frags)
 *
 */
void
__adf_nbuf_frag_info(struct sk_buff *skb, adf_os_sglist_t  *sg)
{
#if defined(ADF_OS_DEBUG) || defined(__ADF_SUPPORT_FRAG_MEM)
    struct skb_shared_info  *sh = skb_shinfo(skb);
#endif
    adf_os_assert(skb != NULL);
    sg->sg_segs[0].vaddr = skb->data;
    sg->sg_segs[0].len   = skb->len;
    sg->nsegs            = 1;

#ifndef __ADF_SUPPORT_FRAG_MEM
    adf_os_assert(sh->nr_frags == 0);
#else
    for(int i = 1; i <= sh->nr_frags; i++){
        skb_frag_t    *f        = &sh->frags[i - 1];
        sg->sg_segs[i].vaddr    = (uint8_t *)(page_address(f->page) +
                                  f->page_offset);
        sg->sg_segs[i].len      = f->size;

        adf_os_assert(i < ADF_OS_MAX_SGLIST);
    }
    sg->nsegs += i;
#endif
}

a_status_t
__adf_nbuf_set_rx_cksum(struct sk_buff *skb, adf_nbuf_rx_cksum_t *cksum)
{
    switch (cksum->l4_result) {
    case ADF_NBUF_RX_CKSUM_NONE:
        skb->ip_summed = CHECKSUM_NONE;
        break;
    case ADF_NBUF_RX_CKSUM_TCP_UDP_UNNECESSARY:
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        break;
    case ADF_NBUF_RX_CKSUM_TCP_UDP_HW:
        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum      = cksum->val;
        break;
    default:
        printk("ADF_NET:Unknown checksum type\n");
        adf_os_assert(0);
	return A_STATUS_ENOTSUPP;
    }
    return A_STATUS_OK;
}

adf_nbuf_tx_cksum_t
__adf_nbuf_get_tx_cksum(struct sk_buff *skb)
{
    switch (skb->ip_summed) {
    case CHECKSUM_NONE:
        return ADF_NBUF_TX_CKSUM_NONE;
    case CHECKSUM_PARTIAL:
        /* XXX ADF and Linux checksum don't map with 1-to-1. This is not 100%
         * correct. */
        return ADF_NBUF_TX_CKSUM_TCP_UDP;
    case CHECKSUM_COMPLETE:
        return ADF_NBUF_TX_CKSUM_TCP_UDP_IP;
    default:
        return ADF_NBUF_TX_CKSUM_NONE;
    }
}

a_status_t
__adf_nbuf_get_vlan_info(adf_net_handle_t hdl, struct sk_buff *skb,
                         adf_net_vlanhdr_t *vlan)
{
     return A_STATUS_OK;
}

a_uint8_t
__adf_nbuf_get_tid(struct sk_buff *skb)
{
    return skb->priority;
}

void
__adf_nbuf_set_tid(struct sk_buff *skb, a_uint8_t tid)
{
        skb->priority = tid;
}

a_uint8_t
__adf_nbuf_get_exemption_type(struct sk_buff *skb)
{
    return ADF_NBUF_EXEMPT_NO_EXEMPTION;
}

void
__adf_nbuf_dmamap_set_cb(__adf_os_dma_map_t dmap, void *cb, void *arg)
{
    return;
}

void
__adf_nbuf_reg_trace_cb(adf_nbuf_trace_update_t cb_func_ptr)
{
   trace_update_cb = cb_func_ptr;
   return;
}

/**
 * __adf_nbuf_data_get_dhcp_subtype() - get the subtype
 *              of DHCP packet.
 * @data: Pointer to DHCP packet data buffer
 *
 * This func. returns the subtype of DHCP packet.
 *
 * Return: subtype of the DHCP packet.
 */
enum adf_proto_subtype
__adf_nbuf_data_get_dhcp_subtype(uint8_t *data)
{
	enum adf_proto_subtype subtype = ADF_PROTO_INVALID;

	if ((data[DHCP_OPTION53_OFFSET] == DHCP_OPTION53) &&
		(data[DHCP_OPTION53_LENGTH_OFFSET] ==
					DHCP_OPTION53_LENGTH)) {

		switch (data[DHCP_OPTION53_STATUS_OFFSET]) {
		case DHCPDISCOVER:
			subtype = ADF_PROTO_DHCP_DISCOVER;
			break;
		case DHCPREQUEST:
			subtype = ADF_PROTO_DHCP_REQUEST;
			break;
		case DHCPOFFER:
			subtype = ADF_PROTO_DHCP_OFFER;
			break;
		case DHCPACK:
			subtype = ADF_PROTO_DHCP_ACK;
			break;
		case DHCPNAK:
			subtype = ADF_PROTO_DHCP_NACK;
			break;
		case DHCPRELEASE:
			subtype = ADF_PROTO_DHCP_RELEASE;
			break;
		case DHCPINFORM:
			subtype = ADF_PROTO_DHCP_INFORM;
			break;
		case DHCPDECLINE:
			subtype = ADF_PROTO_DHCP_DECLINE;
			break;
		default:
			break;
		}
	}

	return subtype;
}

/**
 * __adf_nbuf_data_get_eapol_subtype() - get the subtype
 *            of EAPOL packet.
 * @data: Pointer to EAPOL packet data buffer
 *
 * This func. returns the subtype of EAPOL packet.
 *
 * Return: subtype of the EAPOL packet.
 */
enum adf_proto_subtype
__adf_nbuf_data_get_eapol_subtype(uint8_t *data)
{
	uint16_t eapol_key_info;
	enum adf_proto_subtype subtype = ADF_PROTO_INVALID;
	uint16_t mask;

	eapol_key_info = (uint16_t)(*(uint16_t *)
			(data + EAPOL_KEY_INFO_OFFSET));

	mask = eapol_key_info & EAPOL_MASK;
	switch (mask) {
	case EAPOL_M1_BIT_MASK:
		subtype = ADF_PROTO_EAPOL_M1;
		break;
	case EAPOL_M2_BIT_MASK:
		subtype = ADF_PROTO_EAPOL_M2;
		break;
	case EAPOL_M3_BIT_MASK:
		subtype = ADF_PROTO_EAPOL_M3;
		break;
	case EAPOL_M4_BIT_MASK:
		subtype = ADF_PROTO_EAPOL_M4;
		break;
	default:
		break;
	}

	return subtype;
}

/**
 * __adf_nbuf_data_get_arp_subtype() - get the subtype
 *            of ARP packet.
 * @data: Pointer to ARP packet data buffer
 *
 * This func. returns the subtype of ARP packet.
 *
 * Return: subtype of the ARP packet.
 */
enum adf_proto_subtype
__adf_nbuf_data_get_arp_subtype(uint8_t *data)
{
	uint16_t subtype;
	enum adf_proto_subtype proto_subtype = ADF_PROTO_INVALID;

	subtype = (uint16_t)(*(uint16_t *)
			(data + ARP_SUB_TYPE_OFFSET));

	switch (adf_os_cpu_to_be16(subtype)) {
	case ARP_REQUEST:
		proto_subtype = ADF_PROTO_ARP_REQ;
		break;
	case ARP_RESPONSE:
		proto_subtype = ADF_PROTO_ARP_RES;
		break;
	default:
		break;
	}

	return proto_subtype;
}

/**
 * __adf_nbuf_data_get_icmp_subtype() - get the subtype
 *            of IPV4 ICMP packet.
 * @data: Pointer to IPV4 ICMP packet data buffer
 *
 * This func. returns the subtype of ICMP packet.
 *
 * Return: subtype of the ICMP packet.
 */
enum adf_proto_subtype
__adf_nbuf_data_get_icmp_subtype(uint8_t *data)
{
	uint8_t subtype;
	enum adf_proto_subtype proto_subtype = ADF_PROTO_INVALID;

	subtype = (uint8_t)(*(uint8_t *)
			(data + ICMP_SUBTYPE_OFFSET));

	VOS_TRACE(VOS_MODULE_ID_ADF, VOS_TRACE_LEVEL_DEBUG,
		"ICMP proto type: 0x%02x", subtype);

	switch (subtype) {
	case ICMP_REQUEST:
		proto_subtype = ADF_PROTO_ICMP_REQ;
		break;
	case ICMP_RESPONSE:
		proto_subtype = ADF_PROTO_ICMP_RES;
		break;
	default:
		break;
	}

	return proto_subtype;
}

/**
 * __adf_nbuf_data_get_icmpv6_subtype() - get the subtype
 *            of IPV6 ICMPV6 packet.
 * @data: Pointer to IPV6 ICMPV6 packet data buffer
 *
 * This func. returns the subtype of ICMPV6 packet.
 *
 * Return: subtype of the ICMPV6 packet.
 */
enum adf_proto_subtype
__adf_nbuf_data_get_icmpv6_subtype(uint8_t *data)
{
	uint8_t subtype;
	enum adf_proto_subtype proto_subtype = ADF_PROTO_INVALID;

	subtype = (uint8_t)(*(uint8_t *)
			(data + ICMPV6_SUBTYPE_OFFSET));

	VOS_TRACE(VOS_MODULE_ID_ADF, VOS_TRACE_LEVEL_DEBUG,
		"ICMPv6 proto type: 0x%02x", subtype);

	switch (subtype) {
	case ICMPV6_REQUEST:
		proto_subtype = ADF_PROTO_ICMPV6_REQ;
		break;
	case ICMPV6_RESPONSE:
		proto_subtype = ADF_PROTO_ICMPV6_RES;
		break;
	case ICMPV6_RS:
		proto_subtype = ADF_PROTO_ICMPV6_RS;
		break;
	case ICMPV6_RA:
		proto_subtype = ADF_PROTO_ICMPV6_RA;
		break;
	case ICMPV6_NS:
		proto_subtype = ADF_PROTO_ICMPV6_NS;
		break;
	case ICMPV6_NA:
		proto_subtype = ADF_PROTO_ICMPV6_NA;
		break;
	default:
		break;
	}

	return proto_subtype;
}

/**
 * __adf_nbuf_data_get_ipv4_proto() - get the proto type
 *            of IPV4 packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. returns the proto type of IPV4 packet.
 *
 * Return: proto type of IPV4 packet.
 */
uint8_t
__adf_nbuf_data_get_ipv4_proto(uint8_t *data)
{
	uint8_t proto_type;

	proto_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));
	return proto_type;
}

/**
 * __adf_nbuf_data_get_ipv6_proto() - get the proto type
 *            of IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. returns the proto type of IPV6 packet.
 *
 * Return: proto type of IPV6 packet.
 */
uint8_t
__adf_nbuf_data_get_ipv6_proto(uint8_t *data)
{
	uint8_t proto_type;

	proto_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));
	return proto_type;
}

/**
 * __adf_nbuf_data_is_dhcp_pkt() - check if it is DHCP packet.
 * @data: Pointer to DHCP packet data buffer
 *
 * This func. checks whether it is a DHCP packet or not.
 *
 * Return: TRUE if it is a DHCP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_dhcp_pkt(uint8_t *data)
{
   a_uint16_t    SPort;
   a_uint16_t    DPort;

    SPort = (a_uint16_t)(*(a_uint16_t *)(data + ADF_NBUF_TRAC_IPV4_OFFSET +
                                     ADF_NBUF_TRAC_IPV4_HEADER_SIZE));
    DPort = (a_uint16_t)(*(a_uint16_t *)(data + ADF_NBUF_TRAC_IPV4_OFFSET +
                                     ADF_NBUF_TRAC_IPV4_HEADER_SIZE + sizeof(a_uint16_t)));

    if (((ADF_NBUF_TRAC_DHCP_SRV_PORT == adf_os_cpu_to_be16(SPort)) &&
       (ADF_NBUF_TRAC_DHCP_CLI_PORT == adf_os_cpu_to_be16(DPort))) ||
       ((ADF_NBUF_TRAC_DHCP_CLI_PORT == adf_os_cpu_to_be16(SPort)) &&
       (ADF_NBUF_TRAC_DHCP_SRV_PORT == adf_os_cpu_to_be16(DPort))))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/**
 * __adf_nbuf_data_is_eapol_pkt() - check if it is EAPOL packet.
 * @data: Pointer to EAPOL packet data buffer
 *
 * This func. checks whether it is a EAPOL packet or not.
 *
 * Return: TRUE if it is a EAPOL packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_eapol_pkt(uint8_t *data)
{
    a_uint16_t    ether_type;

    ether_type = (a_uint16_t)(*(a_uint16_t *)(data +
			ADF_NBUF_TRAC_ETH_TYPE_OFFSET));
    if (ADF_NBUF_TRAC_EAPOL_ETH_TYPE == adf_os_cpu_to_be16(ether_type))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/**
 * __adf_nbuf_data_is_ipv4_arp_pkt() - check if it is ARP packet.
 * @data: Pointer to ARP packet data buffer
 *
 * This func. checks whether it is a ARP packet or not.
 *
 * Return: TRUE if it is a ARP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv4_arp_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)(data +
				ADF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == adf_os_cpu_to_be16(ADF_NBUF_TRAC_ARP_ETH_TYPE))
		return true;
	else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv4_pkt() - check if it is IPV4 packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. checks whether it is a IPV4 packet or not.
 *
 * Return: TRUE if it is a IPV4 packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv4_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)(data +
				ADF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == adf_os_cpu_to_be16(ADF_NBUF_TRAC_IPV4_ETH_TYPE))
		return true;
	else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv4_mcast_pkt() - check if it is IPV4 multicast packet.
 * @data: Pointer to IPV4 packet data buffer
 *
 * This func. checks whether it is a IPV4 muticast packet or not.
 *
 * Return: TRUE if it is a IPV4 multicast packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv4_mcast_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t *dst_addr =
			(uint8_t *)(data + ADF_NBUF_TRAC_IPV4_DEST_ADDR_OFFSET);

		/*
		 * Check first byte of the IP address and if it
		 * from 224 to 239, then it can represent multicast IP.
		 */
		if (dst_addr[0] >= 224 && dst_addr[0]  <= 239)
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv6_mcast_pkt() - check if it is IPV6 multicast packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. checks whether it is a IPV6 muticast packet or not.
 *
 * Return: TRUE if it is a IPV6 multicast packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv6_mcast_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv6_pkt(data)) {
		uint16_t *dst_addr;

		dst_addr = (uint16_t *)
			(data + ADF_NBUF_TRAC_IPV6_DEST_ADDR_OFFSET);

		/*
		 * Check first byte of the IP address and if it
		 * 0xFF00 then it is a IPV6 mcast packet.
		 */
		if (*dst_addr ==
		     adf_os_cpu_to_be16(ADF_NBUF_TRAC_IPV6_DEST_ADDR))
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv6_pkt() - check if it is IPV6 packet.
 * @data: Pointer to IPV6 packet data buffer
 *
 * This func. checks whether it is a IPV6 packet or not.
 *
 * Return: TRUE if it is a IPV6 packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv6_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)(data +
				ADF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == adf_os_cpu_to_be16(ADF_NBUF_TRAC_IPV6_ETH_TYPE))
		return true;
	else
		return false;
}

/**
 * __adf_nbuf_data_is_icmp_pkt() - check if it is IPV4 ICMP packet.
 * @data: Pointer to IPV4 ICMP packet data buffer
 *
 * This func. checks whether it is a ICMP packet or not.
 *
 * Return: TRUE if it is a ICMP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_icmp_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));

		if (pkt_type == ADF_NBUF_TRAC_ICMP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_icmpv6_pkt() - check if it is IPV6 ICMPV6 packet.
 * @data: Pointer to IPV6 ICMPV6 packet data buffer
 *
 * This func. checks whether it is a ICMPV6 packet or not.
 *
 * Return: TRUE if it is a ICMPV6 packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_icmpv6_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv6_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));

		if (pkt_type == ADF_NBUF_TRAC_ICMPV6_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv4_udp_pkt() - check if it is IPV4 UDP packet.
 * @data: Pointer to IPV4 UDP packet data buffer
 *
 * This func. checks whether it is a IPV4 UDP packet or not.
 *
 * Return: TRUE if it is a IPV4 UDP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv4_udp_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));

		if (pkt_type == ADF_NBUF_TRAC_UDP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv4_tcp_pkt() - check if it is IPV4 TCP packet.
 * @data: Pointer to IPV4 TCP packet data buffer
 *
 * This func. checks whether it is a IPV4 TCP packet or not.
 *
 * Return: TRUE if it is a IPV4 TCP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv4_tcp_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv4_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV4_PROTO_TYPE_OFFSET));

		if (pkt_type == ADF_NBUF_TRAC_TCP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv6_udp_pkt() - check if it is IPV6 UDP packet.
 * @data: Pointer to IPV6 UDP packet data buffer
 *
 * This func. checks whether it is a IPV6 UDP packet or not.
 *
 * Return: TRUE if it is a IPV6 UDP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv6_udp_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv6_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));

		if (pkt_type == ADF_NBUF_TRAC_UDP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

/**
 * __adf_nbuf_data_is_ipv6_tcp_pkt() - check if it is IPV6 TCP packet.
 * @data: Pointer to IPV6 TCP packet data buffer
 *
 * This func. checks whether it is a IPV6 TCP packet or not.
 *
 * Return: TRUE if it is a IPV6 TCP packet
 *         FALSE if not
 */
bool __adf_nbuf_data_is_ipv6_tcp_pkt(uint8_t *data)
{
	if (__adf_nbuf_data_is_ipv6_pkt(data)) {
		uint8_t pkt_type;

		pkt_type = (uint8_t)(*(uint8_t *)(data +
				ADF_NBUF_TRAC_IPV6_PROTO_TYPE_OFFSET));

		if (pkt_type == ADF_NBUF_TRAC_TCP_TYPE)
			return true;
		else
			return false;
	} else
		return false;
}

#ifdef QCA_PKT_PROTO_TRACE
void
__adf_nbuf_trace_update(struct sk_buff *buf, char *event_string)
{
   char string_buf[NBUF_PKT_TRAC_MAX_STRING];

   if ((!trace_update_cb) || (!event_string)) {
      return;
   }

   if (!adf_nbuf_trace_get_proto_type(buf)) {
      return;
   }

   /* Buffer over flow */
   if (NBUF_PKT_TRAC_MAX_STRING <=
       (adf_os_str_len(event_string) + NBUF_PKT_TRAC_PROTO_STRING)) {
      return;
   }

   adf_os_mem_zero(string_buf,
                   NBUF_PKT_TRAC_MAX_STRING);
   adf_os_mem_copy(string_buf,
                   event_string, adf_os_str_len(event_string));
   switch (adf_nbuf_trace_get_proto_type(buf)) {
   case NBUF_PKT_TRAC_TYPE_EAPOL:
      adf_os_mem_copy(string_buf + adf_os_str_len(event_string),
                      "EPL", adf_os_str_len("EPL"));
      break;
   case NBUF_PKT_TRAC_TYPE_DHCP:
      adf_os_mem_copy(string_buf + adf_os_str_len(event_string),
                      "DHC", adf_os_str_len("DHC"));
      break;
   case NBUF_PKT_TRAC_TYPE_MGMT_ACTION:
      adf_os_mem_copy(string_buf + adf_os_str_len(event_string),
                      "MACT", adf_os_str_len("MACT"));
      break;
   case NBUF_PKT_TRAC_TYPE_ARP:
      adf_os_mem_copy(string_buf + adf_os_str_len(event_string),
                      "ARP", adf_os_str_len("ARP"));
      break;
   case NBUF_PKT_TRAC_TYPE_NS:
      adf_os_mem_copy(string_buf + adf_os_str_len(event_string),
                      "NS", adf_os_str_len("NS"));
      break;
   case NBUF_PKT_TRAC_TYPE_NA:
      adf_os_mem_copy(string_buf + adf_os_str_len(event_string),
                      "NA", adf_os_str_len("NA"));
      break;
   default:
      break;
   }

   trace_update_cb(string_buf);
   return;
}
#endif /* QCA_PKT_PROTO_TRACE */

#ifdef MEMORY_DEBUG
#define ADF_NET_BUF_TRACK_MAX_SIZE    (1024)

/**
 * struct adf_nbuf_track_t - Network buffer track structure
 *
 * @p_next: Pointer to next
 * @net_buf: Pointer to network buffer
 * @file_name: File name
 * @line_num: Line number
 * @size: Size
 */
struct adf_nbuf_track_t {
	struct adf_nbuf_track_t *p_next;
	adf_nbuf_t net_buf;
	uint8_t *file_name;
	uint32_t line_num;
	size_t size;
};

static adf_os_spinlock_t g_adf_net_buf_track_lock[ADF_NET_BUF_TRACK_MAX_SIZE];
typedef struct adf_nbuf_track_t ADF_NBUF_TRACK;

static ADF_NBUF_TRACK *gp_adf_net_buf_track_tbl[ADF_NET_BUF_TRACK_MAX_SIZE];
static struct kmem_cache *nbuf_tracking_cache;
static ADF_NBUF_TRACK *adf_net_buf_track_free_list;
static adf_os_spinlock_t adf_net_buf_track_free_list_lock;
static uint32_t adf_net_buf_track_free_list_count;
static uint32_t adf_net_buf_track_used_list_count;
static uint32_t adf_net_buf_track_max_used;
static uint32_t adf_net_buf_track_max_free;
static uint32_t adf_net_buf_track_max_allocated;

/**
 * adf_update_max_used() - update adf_net_buf_track_max_used tracking variable
 *
 * tracks the max number of network buffers that the wlan driver was tracking
 * at any one time.
 *
 * Return: none
 */
static inline void adf_update_max_used(void)
{
	int sum;

	if (adf_net_buf_track_max_used <
	    adf_net_buf_track_used_list_count)
		adf_net_buf_track_max_used = adf_net_buf_track_used_list_count;
	sum = adf_net_buf_track_free_list_count +
		adf_net_buf_track_used_list_count;
	if (adf_net_buf_track_max_allocated < sum)
		adf_net_buf_track_max_allocated = sum;
}

/**
 * adf_update_max_free() - update adf_net_buf_track_free_list_count
 *
 * tracks the max number tracking buffers kept in the freelist.
 *
 * Return: none
 */
static inline void adf_update_max_free(void)
{
	if (adf_net_buf_track_max_free <
	    adf_net_buf_track_free_list_count)
		adf_net_buf_track_max_free = adf_net_buf_track_free_list_count;
}

/**
 * adf_nbuf_track_alloc() - allocate a cookie to track nbufs allocated by wlan
 *
 * This function pulls from a freelist if possible and uses kmem_cache_alloc.
 * This function also adds fexibility to adjust the allocation and freelist
 * schemes.
 *
 * Return: a pointer to an unused ADF_NBUF_TRACK structure may not be zeroed.
 */
static ADF_NBUF_TRACK *adf_nbuf_track_alloc(void)
{
	int flags = GFP_KERNEL;
	ADF_NBUF_TRACK *new_node = NULL;

	adf_os_spin_lock_irqsave(&adf_net_buf_track_free_list_lock);
	adf_net_buf_track_used_list_count++;
	if (adf_net_buf_track_free_list != NULL) {
		new_node = adf_net_buf_track_free_list;
		adf_net_buf_track_free_list =
			adf_net_buf_track_free_list->p_next;
		adf_net_buf_track_free_list_count--;
	}
	adf_update_max_used();
	adf_os_spin_unlock_irqrestore(&adf_net_buf_track_free_list_lock);

	if (new_node != NULL)
		return new_node;

	if (in_interrupt() || irqs_disabled() || in_atomic())
		flags = GFP_ATOMIC;

	return kmem_cache_alloc(nbuf_tracking_cache, flags);
}

/* FREEQ_POOLSIZE initial and minimum desired freelist poolsize */
#define FREEQ_POOLSIZE 2048

/**
 * adf_nbuf_track_free() - free the nbuf tracking cookie.
 * @node: adf nbuf tarcking node
 *
 * Matches calls to adf_nbuf_track_alloc.
 * Either frees the tracking cookie to kernel or an internal
 * freelist based on the size of the freelist.
 *
 * Return: none
 */
static void adf_nbuf_track_free(ADF_NBUF_TRACK *node)
{
	if (!node)
		return;

	/* Try to shrink the freelist if free_list_count > than FREEQ_POOLSIZE
	 * only shrink the freelist if it is bigger than twice the number of
	 * nbufs in use. If the driver is stalling in a consistent bursty
	 * fasion, this will keep 3/4 of thee allocations from the free list
	 * while also allowing the system to recover memory as less frantic
	 * traffic occurs.
	 */

	adf_os_spin_lock_irqsave(&adf_net_buf_track_free_list_lock);

	adf_net_buf_track_used_list_count--;
	if (adf_net_buf_track_free_list_count > FREEQ_POOLSIZE &&
	   (adf_net_buf_track_free_list_count >
	    adf_net_buf_track_used_list_count << 1)) {
		kmem_cache_free(nbuf_tracking_cache, node);
	} else {
		node->p_next = adf_net_buf_track_free_list;
		adf_net_buf_track_free_list = node;
		adf_net_buf_track_free_list_count++;
	}
	adf_update_max_free();
	adf_os_spin_unlock_irqrestore(&adf_net_buf_track_free_list_lock);
}

/**
 * adf_nbuf_track_prefill() - prefill the nbuf tracking cookie freelist
 *
 * Removes a 'warmup time' characteristic of the freelist.  Prefilling
 * the freelist first makes it performant for the first iperf udp burst
 * as well as steady state.
 *
 * Return: None
 */
static void adf_nbuf_track_prefill(void)
{
	int i;
	ADF_NBUF_TRACK *node, *head;

	/* prepopulate the freelist */
	head = NULL;
	for (i = 0; i < FREEQ_POOLSIZE; i++) {
		node = adf_nbuf_track_alloc();
		if (node == NULL)
			continue;
		node->p_next = head;
		head = node;
	}
	while (head) {
		node = head->p_next;
		adf_nbuf_track_free(head);
		head = node;
	}
}

/**
 * adf_nbuf_track_memory_manager_create() - manager for nbuf tracking cookies
 *
 * This initializes the memory manager for the nbuf tracking cookies.  Because
 * these cookies are all the same size and only used in this feature, we can
 * use a kmem_cache to provide tracking as well as to speed up allocations.
 * To avoid the overhead of allocating and freeing the buffers (including SLUB
 * features) a freelist is prepopulated here.
 *
 * Return: None
 */
static void adf_nbuf_track_memory_manager_create(void)
{
	adf_os_spinlock_init(&adf_net_buf_track_free_list_lock);
	nbuf_tracking_cache = kmem_cache_create("adf_nbuf_tracking_cache",
						sizeof(ADF_NBUF_TRACK),
						0, 0, NULL);

	adf_nbuf_track_prefill();
}

/**
 * adf_nbuf_track_memory_manager_destroy() - manager for nbuf tracking cookies
 *
 * Empty the freelist and print out usage statistics when it is no longer
 * needed. Also the kmem_cache should be destroyed here so that it can warn if
 * any nbuf tracking cookies were leaked.
 *
 * Return: None
 */
static void adf_nbuf_track_memory_manager_destroy(void)
{
	ADF_NBUF_TRACK *node, *tmp;

	adf_print("%s: %d residual freelist size",
			  __func__, adf_net_buf_track_free_list_count);

	adf_print("%s: %d max freelist size observed",
			  __func__, adf_net_buf_track_max_free);

	adf_print("%s: %d max buffers used observed",
			  __func__, adf_net_buf_track_max_used);

	adf_print("%s: %d max buffers allocated observed",
			  __func__, adf_net_buf_track_max_allocated);

	adf_os_spin_lock_irqsave(&adf_net_buf_track_free_list_lock);
	node = adf_net_buf_track_free_list;

	while (node) {
		tmp = node;
		node = node->p_next;
		kmem_cache_free(nbuf_tracking_cache, tmp);
		adf_net_buf_track_free_list_count--;
	}

	if (adf_net_buf_track_free_list_count != 0)
		adf_print("%s: %d unfreed tracking memory lost in freelist",
			  __func__, adf_net_buf_track_free_list_count);

	if (adf_net_buf_track_used_list_count != 0)
		adf_print("%s: %d unfreed tracking memory still in use",
			  __func__, adf_net_buf_track_used_list_count);

	adf_net_buf_track_free_list = NULL;
	adf_net_buf_track_free_list_count = 0;
	adf_net_buf_track_used_list_count = 0;
	adf_net_buf_track_max_used = 0;
	adf_net_buf_track_max_free = 0;
	adf_net_buf_track_max_allocated = 0;

	adf_os_spin_unlock_irqrestore(&adf_net_buf_track_free_list_lock);
	kmem_cache_destroy(nbuf_tracking_cache);
}

void adf_nbuf_free_debug(adf_nbuf_t net_buf, uint8_t *file, uint32_t line)
{
	/* Remove SKB from internal ADF tracking table */
	adf_nbuf_panic_on_free_if_mapped(net_buf, file, line);
	if (adf_os_likely(net_buf))
		adf_net_buf_debug_delete_node(net_buf);

	adf_nbuf_history_add(net_buf, file, line, ADF_NBUF_FREE);
	__adf_nbuf_free(net_buf);
}

/**
 * adf_net_buf_debug_init() - initialize network buffer debug functionality
 *
 * ADF network buffer debug feature tracks all SKBs allocated by WLAN driver
 * in a hash table and when driver is unloaded it reports about leaked SKBs.
 * WLAN driver module whose allocated SKB is freed by network stack are
 * suppose to call adf_net_buf_debug_release_skb() such that the SKB is not
 * reported as memory leak.
 *
 * Return: none
 */
void adf_net_buf_debug_init(void)
{
	uint32_t i;

	adf_os_atomic_set(&adf_nbuf_history_index, -1);

	adf_nbuf_map_tracking_init();
	adf_nbuf_track_memory_manager_create();

	for (i = 0; i < ADF_NET_BUF_TRACK_MAX_SIZE; i++) {
		gp_adf_net_buf_track_tbl[i] = NULL;
		adf_os_spinlock_init(&g_adf_net_buf_track_lock[i]);
	}

	return;
}

/**
 * adf_net_buf_debug_exit() - exit network buffer debug functionality
 *
 * Exit network buffer tracking debug functionality and log SKB memory leaks
 * As part of exiting the functionality, free the leaked memory and
 * cleanup the tracking buffers.
 *
 * Return: none
 */
void adf_net_buf_debug_exit(void)
{
	uint32_t i;
	ADF_NBUF_TRACK *p_node;
	ADF_NBUF_TRACK *p_prev;

	for (i = 0; i < ADF_NET_BUF_TRACK_MAX_SIZE; i++) {
		adf_os_spin_lock_irqsave(&g_adf_net_buf_track_lock[i]);
		p_node = gp_adf_net_buf_track_tbl[i];
		while (p_node) {
			p_prev = p_node;
			p_node = p_node->p_next;
			adf_print("SKB buf memory Leak@ File %s, @Line %d, size %zu",
				  p_prev->file_name, p_prev->line_num,
				  p_prev->size);
			adf_nbuf_track_free(p_prev);
		}
		adf_os_spin_unlock_irqrestore(&g_adf_net_buf_track_lock[i]);
	}

	adf_nbuf_track_memory_manager_destroy();
	adf_nbuf_map_tracking_deinit();

	return;
}

/**
 * adf_net_buf_debug_hash() - hash network buffer pointer
 *
 * Return: hash value
 */
uint32_t adf_net_buf_debug_hash(adf_nbuf_t net_buf)
{
	uint32_t i;

	i = (uint32_t) (((uintptr_t) net_buf) >> 4);
	i += (uint32_t) (((uintptr_t) net_buf) >> 14);
	i &= (ADF_NET_BUF_TRACK_MAX_SIZE - 1);

	return i;
}

/**
 * adf_net_buf_debug_look_up() - look up network buffer in debug hash table
 *
 * Return: If skb is found in hash table then return pointer to network buffer
 *         else return NULL
 */
ADF_NBUF_TRACK *adf_net_buf_debug_look_up(adf_nbuf_t net_buf)
{
	uint32_t i;
	ADF_NBUF_TRACK *p_node;

	i = adf_net_buf_debug_hash(net_buf);
	p_node = gp_adf_net_buf_track_tbl[i];

	while (p_node) {
		if (p_node->net_buf == net_buf)
			return p_node;
		p_node = p_node->p_next;
	}

	return NULL;
}

/**
 * adf_net_buf_debug_add_node() - store skb in debug hash table
 *
 * Return: none
 */
void adf_net_buf_debug_add_node(adf_nbuf_t net_buf, size_t size,
				uint8_t *file_name, uint32_t line_num)
{
	uint32_t i;
	ADF_NBUF_TRACK *p_node;
	ADF_NBUF_TRACK *new_node;

	new_node = adf_nbuf_track_alloc();

	i = adf_net_buf_debug_hash(net_buf);
	adf_os_spin_lock_irqsave(&g_adf_net_buf_track_lock[i]);

	p_node = adf_net_buf_debug_look_up(net_buf);

	if (p_node) {
		adf_print("Double allocation of skb ! Already allocated from %pK %s %d current alloc from %pK %s %d",
			  p_node->net_buf, p_node->file_name, p_node->line_num,
			  net_buf, file_name, line_num);
		adf_os_warn(1);
		adf_nbuf_track_free(new_node);
		goto done;
	} else {
		p_node = new_node;
		if (p_node) {
			p_node->net_buf = net_buf;
			p_node->file_name = file_name;
			p_node->line_num = line_num;
			p_node->size = size;
			p_node->p_next = gp_adf_net_buf_track_tbl[i];
			gp_adf_net_buf_track_tbl[i] = p_node;
		} else {
			adf_print(
				  "Mem alloc failed ! Could not track skb from %s %d of size %zu",
				  file_name, line_num, size);
			adf_os_warn(1);
		}
	}

done:
	adf_os_spin_unlock_irqrestore(&g_adf_net_buf_track_lock[i]);

	return;
}

/**
 * adf_net_buf_debug_delete_node() - remove skb from debug hash table
 *
 * Return: none
 */
void adf_net_buf_debug_delete_node(adf_nbuf_t net_buf)
{
	uint32_t i;
	bool found = false;
	ADF_NBUF_TRACK *p_head;
	ADF_NBUF_TRACK *p_node;
	ADF_NBUF_TRACK *p_prev;

	i = adf_net_buf_debug_hash(net_buf);
	adf_os_spin_lock_irqsave(&g_adf_net_buf_track_lock[i]);

	p_head = gp_adf_net_buf_track_tbl[i];

	/* Unallocated SKB */
	if (!p_head)
		goto done;

	p_node = p_head;
	/* Found at head of the table */
	if (p_head->net_buf == net_buf) {
		gp_adf_net_buf_track_tbl[i] = p_node->p_next;
		found = true;
		goto done;
	}

	/* Search in collision list */
	while (p_node) {
		p_prev = p_node;
		p_node = p_node->p_next;
		if ((NULL != p_node) && (p_node->net_buf == net_buf)) {
			p_prev->p_next = p_node->p_next;
			found = true;
			break;
		}
	}

done:
	adf_os_spin_unlock_irqrestore(&g_adf_net_buf_track_lock[i]);

	if (!found) {
		adf_print("Unallocated buffer ! Double free of net_buf %pK ?",
			  net_buf);
		adf_os_warn(1);
	} else {
		adf_nbuf_track_free(p_node);
	}

	return;
}

/**
 * adf_net_buf_debug_release_skb() - release skb to avoid memory leak
 * @net_buf: Network buf holding head segment (single)
 *
 * WLAN driver module whose allocated SKB is freed by network stack are
 * suppose to call this API before returning SKB to network stack such
 * that the SKB is not reported as memory leak.
 *
 * Return: none
 */
void adf_net_buf_debug_release_skb(adf_nbuf_t net_buf)
{
	adf_nbuf_t ext_list = adf_nbuf_get_ext_list(net_buf);

	while (ext_list) {
		/*
		 * Take care to free if it is Jumbo packet connected using
		 * frag_list
		 */
		adf_nbuf_t next;

		next = adf_nbuf_queue_next(ext_list);
		adf_net_buf_debug_delete_node(ext_list);
		ext_list = next;
	}
	adf_net_buf_debug_delete_node(net_buf);
}
#endif /*MEMORY_DEBUG */

/**
 * adf_nbuf_update_radiotap() - Update radiotap header from rx_status
 *
 * @rx_status: Pointer to rx_status.
 * @nbuf:      nbuf pointe to which radiotap has to be updated
 * @headroom_sz: Available headroom size.
 *
 * Return: length of rtap_len updated.
 */
int adf_nbuf_update_radiotap(struct mon_rx_status *rx_status, adf_nbuf_t nbuf,
			     u_int32_t headroom_sz)
{
	uint8_t rtap_buf[sizeof(struct ieee80211_radiotap_header) + 100] = {0};
	struct ieee80211_radiotap_header *rthdr =
		(struct ieee80211_radiotap_header *)rtap_buf;
	uint32_t rtap_hdr_len = sizeof(struct ieee80211_radiotap_header);
	uint32_t rtap_len = rtap_hdr_len;

	/* IEEE80211_RADIOTAP_TSFT              __le64       microseconds*/
	rthdr->it_present = cpu_to_le32(1 << IEEE80211_RADIOTAP_TSFT);
	put_unaligned_le64(rx_status->tsft,
			   (void *)&rtap_buf[rtap_len]);
	rtap_len += 8;

	/* IEEE80211_RADIOTAP_FLAGS u8*/
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_FLAGS);
	rtap_buf[rtap_len] = rx_status->flags;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_RATE  u8           500kb/s*/
	if (!(rx_status->mcs_info.valid || rx_status->vht_info.valid)) {
		rthdr->it_present |=
			cpu_to_le32(1 << IEEE80211_RADIOTAP_RATE);
		rtap_buf[rtap_len] = rx_status->rate;
		rtap_len += 1;
	}

	/* IEEE80211_RADIOTAP_CHANNEL */
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_CHANNEL);
	/* padding */
	if (rx_status->mcs_info.valid || rx_status->vht_info.valid) {
		rtap_buf[rtap_len] = 0;
		rtap_len += 1;
	}
	/* Channel frequency in Mhz */
	put_unaligned_le16(rx_status->chan, (void *)&rtap_buf[rtap_len]);
	rtap_len += 2;
	/* Channel flags. */
	put_unaligned_le16(rx_status->chan_flags, (void *)&rtap_buf[rtap_len]);
	rtap_len += 2;

	/* IEEE80211_RADIOTAP_DBM_ANTSIGNAL */
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
#define NORMALIZED_TO_NOISE_FLOOR (-96)
	/*
	 * rssi_comb is int dB, need to convert it to dBm.
	 * normalize value to noise floor of -96 dBm
	 */
	rtap_buf[rtap_len] = rx_status->ant_signal_db +
		NORMALIZED_TO_NOISE_FLOOR;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_DBM_ANTNOISE */
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_DBM_ANTNOISE);
	rtap_buf[rtap_len] = NORMALIZED_TO_NOISE_FLOOR;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_ANTENNA */
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_ANTENNA);
	rtap_buf[rtap_len] = rx_status->nr_ant;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_MCS: u8 known, u8 flags, u8 mcs */
	if (rx_status->mcs_info.valid) {
		rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_MCS);
		/*
		 * known fields: band width, mcs index, short GI, FEC type,
		 * STBC streams, ness.
		 */
		rtap_buf[rtap_len] = 0x77;
		rtap_len += 1;
		/* band width */
		rtap_buf[rtap_len] = 0;
		rtap_buf[rtap_len] |= (rx_status->mcs_info.bw & 0x3);
		/* short GI */
		rtap_buf[rtap_len] |= ((rx_status->mcs_info.sgi << 2) & 0x4);
		/* FEC type */
		rtap_buf[rtap_len] |= ((rx_status->mcs_info.fec << 4) & 0x10);
		/* STBC streams */
		rtap_buf[rtap_len] |= ((rx_status->mcs_info.stbc << 5) & 0x60);
		/* ness */
		rtap_buf[rtap_len] |= ((rx_status->mcs_info.ness << 7) & 0x80);
		rtap_len += 1;
		/* mcs index */
		rtap_buf[rtap_len] = rx_status->mcs_info.mcs;
		rtap_len += 1;
	}

	/* IEEE80211_RADIOTAP_VHT: u16, u8, u8, u8[4], u8, u8, u16 */
	if (rx_status->vht_info.valid) {
		rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_VHT);
		/* padding */
		rtap_buf[rtap_len] = 0;
		rtap_len += 1;
		/*
		 * known fields: STBC, TXOP_PS_NOT_ALLOWED,
		 * Short GI NSYM disambiguation, short GI,
		 * LDPC extra OFDM symbol, Beamformed ,
		 * bandwidth, gid, Partial AID
		 */
		put_unaligned_le16(0x1ff, (void *)&rtap_buf[rtap_len]);
		rtap_len += 2;
		/* STBC */
		rtap_buf[rtap_len] = 0;
		rtap_buf[rtap_len] |= (rx_status->vht_info.stbc & 0x1);
		/* TXOP_PS_NOT_ALLOWED */
		rtap_buf[rtap_len] |=
			((rx_status->vht_info.txps_forbidden << 1) & 0x2);
		/* short GI */
		rtap_buf[rtap_len] |=
			((rx_status->vht_info.sgi << 2) & 0x4);
		/* short GI NSYM disambiguation */
		rtap_buf[rtap_len] |=
			((rx_status->vht_info.sgi_disambiguation << 3) & 0x8);
		/* LDPC Extra OFDM symbol */
		rtap_buf[rtap_len] |=
			((rx_status->vht_info.ldpc_extra_symbol << 4) & 0x10);
		/* Beamformed */
		rtap_buf[rtap_len] |=
			((rx_status->vht_info.beamformed << 5) & 0x20);
		rtap_len += 1;
		/* band width, transform to radiotap format */
		rtap_buf[rtap_len] =
			((rx_status->vht_info.bw == 2) ?
			 4 : rx_status->vht_info.bw) & 0x1f;
		rtap_len += 1;
		/* nss */
		rtap_buf[rtap_len] |= ((1 + rx_status->vht_info.nss) & 0x0f);
		/* mcs */
		rtap_buf[rtap_len] |= ((rx_status->vht_info.mcs << 4) & 0xf0);
		rtap_len += 1;
		/* only support SG, so set 0 other 3 users */
		rtap_buf[rtap_len] = 0;
		rtap_len += 1;
		rtap_buf[rtap_len] = 0;
		rtap_len += 1;
		rtap_buf[rtap_len] = 0;
		rtap_len += 1;
		/* LDPC */
		rtap_buf[rtap_len] = rx_status->vht_info.coding;
		rtap_len += 1;
		/* gid */
		rtap_buf[rtap_len] = rx_status->vht_info.gid;
		rtap_len += 1;
		/* pid */
		put_unaligned_le16((uint16_t)(rx_status->vht_info.paid),
				   (void *)&rtap_buf[rtap_len]);
		rtap_len += 2;
	}

	rthdr->it_len = cpu_to_le16(rtap_len);

	if (headroom_sz >= rtap_len) {
		adf_nbuf_pull_head(nbuf, headroom_sz  - rtap_len);
		adf_os_mem_copy(adf_nbuf_data(nbuf), rthdr, rtap_len);
	} else {
		/* If no headroom, append to tail */
		uint8_t *rtap_start = adf_nbuf_put_tail(nbuf, rtap_len);

		if (!rtap_start) {
			adf_print("No enough tail room to save radiotap len: "
				"%d", rtap_len);
			return 0;
		}
		adf_os_mem_copy(rtap_start, rthdr, rtap_len);
		adf_nbuf_trim_tail(nbuf, rtap_len);
	}

	return rtap_len;
}

/**
 * adf_nbuf_construct_radiotap() - fill in the info into radiotap buf
 *
 * @rtap_buf: pointer to radiotap buffer
 * @tsf: timestamp of packet
 * @rssi_comb: rssi of packet
 *
 * Return: length of rtap_len updated.
 */
uint16_t adf_nbuf_construct_radiotap(
		uint8_t *rtap_buf,
		uint32_t tsf,
		uint32_t rssi_comb)
{
	struct ieee80211_radiotap_header *rthdr =
		(struct ieee80211_radiotap_header *)rtap_buf;
	uint32_t rtap_hdr_len = sizeof(struct ieee80211_radiotap_header);
	uint32_t rtap_len = rtap_hdr_len;

	/* IEEE80211_RADIOTAP_TSFT              __le64       microseconds*/
	rthdr->it_present = cpu_to_le32(1 << IEEE80211_RADIOTAP_TSFT);
	put_unaligned_le64((uint64_t)tsf,
			   (void *)&rtap_buf[rtap_len]);
	rtap_len += 8;

	/* IEEE80211_RADIOTAP_FLAGS u8*/
/*	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_FLAGS);
	rtap_buf[rtap_len] = 0x10;
	rtap_len += 1; */

	/* IEEE80211_RADIOTAP_DBM_ANTSIGNAL */
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
#define NORMALIZED_TO_NOISE_FLOOR (-96)
	/*
	 * rssi_comb is int dB, need to convert it to dBm.
	 * normalize value to noise floor of -96 dBm
	 */
	rtap_buf[rtap_len] = rssi_comb +
		NORMALIZED_TO_NOISE_FLOOR;
	rtap_len += 1;

	/* IEEE80211_RADIOTAP_DBM_ANTNOISE */
	rthdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_DBM_ANTNOISE);
	rtap_buf[rtap_len] = NORMALIZED_TO_NOISE_FLOOR;
	rtap_len += 1;

	rthdr->it_len = cpu_to_le16(rtap_len);

	return rthdr->it_len;
}

/**
 * __adf_nbuf_validate_skb_cb() - validate skb CB
 *
 * SKB control block size limit is 48 byte, add compile time
 * assert if SKB control block is exceeding 48 byte.
 *
 * Return: none
 */
void
__adf_nbuf_validate_skb_cb(void)
{
	/*
	 * Add compile time assert if SKB control block is exceeding
	 * 48 byte.
	 */
	BUILD_BUG_ON(sizeof(struct cvg_nbuf_cb) >
		FIELD_SIZEOF(struct sk_buff, cb));
}

/**
 * __adf_nbuf_is_wai() - Check if frame is WAI
 * @data: pointer to skb data buffer
 *
 * This function checks if the frame is WAPI.
 *
 * Return: true (1) if WAPI
 *
 */
bool __adf_nbuf_is_wai_pkt(uint8_t *data)
{
	uint16_t ether_type;

	ether_type = (uint16_t)(*(uint16_t *)
			(data + ADF_NBUF_TRAC_ETH_TYPE_OFFSET));

	if (ether_type == VOS_SWAP_U16(ADF_NBUF_TRAC_WAI_ETH_TYPE))
		return true;

	return false;
}

/**
 * __adf_nbuf_is_group_pkt() - Check if frame is multicast packet
 * @data: pointer to skb data buffer
 *
 * This function checks if the frame is multicast packet.
 *
 * Return: true (1) if multicast
 *
 */
bool __adf_nbuf_is_multicast_pkt(uint8_t *data)
{
	struct adf_mac_addr *mac_addr = (struct adf_mac_addr*)data;

	if ( mac_addr->bytes[0] & 0x01 )
		return true;

	return false;
}

/**
 * __adf_nbuf_is_bcast_pkt() - Check if frame is broadcast packet
 * @data: pointer to skb data buffer
 *
 * This function checks if the frame is broadcast packet.
 *
 * Return: true (1) if broadcast
 *
 */
bool __adf_nbuf_is_bcast_pkt(uint8_t *data)
{
	struct adf_mac_addr *mac_addr = (struct adf_mac_addr*)data;
	struct adf_mac_addr bcast_addr = VOS_MAC_ADDR_BROADCAST_INITIALIZER;

	if (!memcmp( mac_addr, &bcast_addr, VOS_MAC_ADDR_SIZE))
		return true;

	return false;
}

