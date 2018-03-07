#ifdef CONFIG_SCHED_QHMP
#include "qhmp_sched.h"
#else
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sched

#if !defined(_TRACE_SCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCHED_H

#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

struct rq;
struct group_cpu_time;
struct migration_sum_data;
extern const char *task_event_names[];

/*
 * Tracepoint for calling kthread_stop, performed to end a kthread:
 */
TRACE_EVENT(sched_kthread_stop,

	TP_PROTO(struct task_struct *t),

	TP_ARGS(t),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, t->comm, TASK_COMM_LEN);
		__entry->pid	= t->pid;
	),

	TP_printk("comm=%s pid=%d", __entry->comm, __entry->pid)
);

/*
 * Tracepoint for the return value of the kthread stopping:
 */
TRACE_EVENT(sched_kthread_stop_ret,

	TP_PROTO(int ret),

	TP_ARGS(ret),

	TP_STRUCT__entry(
		__field(	int,	ret	)
	),

	TP_fast_assign(
		__entry->ret	= ret;
	),

	TP_printk("ret=%d", __entry->ret)
);

/*
 * Tracepoint for task enqueue/dequeue:
 */
TRACE_EVENT(sched_enq_deq_task,

	TP_PROTO(struct task_struct *p, bool enqueue, unsigned int cpus_allowed),

	TP_ARGS(p, enqueue, cpus_allowed),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(	int,	cpu			)
		__field(	bool,	enqueue			)
		__field(unsigned int,	nr_running		)
		__field(unsigned long,	cpu_load		)
		__field(unsigned int,	rt_nr_running		)
		__field(unsigned int,	cpus_allowed		)
#ifdef CONFIG_SCHED_HMP
		__field(unsigned int,	demand			)
#ifdef CONFIG_SCHED_FREQ_INPUT
		__field(unsigned int,	pred_demand		)
#endif
#endif
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
		__entry->cpu		= task_cpu(p);
		__entry->enqueue	= enqueue;
		__entry->nr_running	= task_rq(p)->nr_running;
		__entry->cpu_load	= task_rq(p)->cpu_load[0];
		__entry->rt_nr_running	= task_rq(p)->rt.rt_nr_running;
		__entry->cpus_allowed	= cpus_allowed;
#ifdef CONFIG_SCHED_HMP
		__entry->demand		= p->ravg.demand;
#ifdef CONFIG_SCHED_FREQ_INPUT
		__entry->pred_demand	= p->ravg.pred_demand;
#endif
#endif
	),

	TP_printk("cpu=%d %s comm=%s pid=%d prio=%d nr_running=%u cpu_load=%lu rt_nr_running=%u affine=%x"
#ifdef CONFIG_SCHED_HMP
		 " demand=%u"
#ifdef CONFIG_SCHED_FREQ_INPUT
		 " pred_demand=%u"
#endif
#endif
			, __entry->cpu,
			__entry->enqueue ? "enqueue" : "dequeue",
			__entry->comm, __entry->pid,
			__entry->prio, __entry->nr_running,
			__entry->cpu_load, __entry->rt_nr_running, __entry->cpus_allowed
#ifdef CONFIG_SCHED_HMP
			, __entry->demand
#ifdef CONFIG_SCHED_FREQ_INPUT
			, __entry->pred_demand
#endif
#endif
			)
);

#ifdef CONFIG_SCHED_HMP

TRACE_EVENT(sched_task_load,

	TP_PROTO(struct task_struct *p, bool boost, int reason,
		 bool sync, bool need_idle, bool fast_path, int best_cpu),

	TP_ARGS(p, boost, reason, sync, need_idle, fast_path, best_cpu),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(unsigned int,	demand			)
		__field(	bool,	boost			)
		__field(	int,	reason			)
		__field(	bool,	sync			)
		__field(	bool,	need_idle		)
		__field(	bool,	fast_path		)
		__field(	int,	best_cpu		)
		__field(	u64,	latency			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->demand		= p->ravg.demand;
		__entry->boost		= boost;
		__entry->reason		= reason;
		__entry->sync		= sync;
		__entry->need_idle	= need_idle;
		__entry->fast_path	= fast_path;
		__entry->best_cpu	= best_cpu;
		__entry->latency	= p->state == TASK_WAKING ?
						      sched_ktime_clock() -
						      p->ravg.mark_start : 0;
	),

	TP_printk("%d (%s): demand=%u boost=%d reason=%d sync=%d need_idle=%d fast_path=%d best_cpu=%d latency=%llu",
		__entry->pid, __entry->comm, __entry->demand,
		__entry->boost, __entry->reason, __entry->sync,
		__entry->need_idle, __entry->fast_path,
		__entry->best_cpu, __entry->latency)
);

TRACE_EVENT(sched_set_preferred_cluster,

	TP_PROTO(struct related_thread_group *grp, u64 total_demand),

	TP_ARGS(grp, total_demand),

	TP_STRUCT__entry(
		__field(		int,	id			)
		__field(		u64,	demand			)
		__field(		int,	cluster_first_cpu	)
	),

	TP_fast_assign(
		__entry->id			= grp->id;
		__entry->demand			= total_demand;
		__entry->cluster_first_cpu	= grp->preferred_cluster ?
							cluster_first_cpu(grp->preferred_cluster)
							: -1;
	),

	TP_printk("group_id %d total_demand %llu preferred_cluster_first_cpu %d",
			__entry->id, __entry->demand,
			__entry->cluster_first_cpu)
);

DECLARE_EVENT_CLASS(sched_cpu_load,

	TP_PROTO(struct rq *rq, int idle, u64 irqload, unsigned int power_cost, int temp),

	TP_ARGS(rq, idle, irqload, power_cost, temp),

	TP_STRUCT__entry(
		__field(unsigned int, cpu			)
		__field(unsigned int, idle			)
		__field(unsigned int, nr_running		)
		__field(unsigned int, nr_big_tasks		)
		__field(unsigned int, load_scale_factor		)
		__field(unsigned int, capacity			)
		__field(	 u64, cumulative_runnable_avg	)
		__field(	 u64, irqload			)
		__field(unsigned int, max_freq			)
		__field(unsigned int, power_cost		)
		__field(	 int, cstate			)
		__field(	 int, dstate			)
		__field(	 int, temp			)
	),

	TP_fast_assign(
		__entry->cpu			= rq->cpu;
		__entry->idle			= idle;
		__entry->nr_running		= rq->nr_running;
		__entry->nr_big_tasks		= rq->hmp_stats.nr_big_tasks;
		__entry->load_scale_factor	= cpu_load_scale_factor(rq->cpu);
		__entry->capacity		= cpu_capacity(rq->cpu);
		__entry->cumulative_runnable_avg = rq->hmp_stats.cumulative_runnable_avg;
		__entry->irqload		= irqload;
		__entry->max_freq		= cpu_max_freq(rq->cpu);
		__entry->power_cost		= power_cost;
		__entry->cstate			= rq->cstate;
		__entry->dstate			= rq->cluster->dstate;
		__entry->temp			= temp;
	),

	TP_printk("cpu %u idle %d nr_run %u nr_big %u lsf %u capacity %u cr_avg %llu irqload %llu fmax %u power_cost %u cstate %d dstate %d temp %d",
	__entry->cpu, __entry->idle, __entry->nr_running, __entry->nr_big_tasks,
	__entry->load_scale_factor, __entry->capacity,
	__entry->cumulative_runnable_avg, __entry->irqload,
	__entry->max_freq, __entry->power_cost, __entry->cstate,
	__entry->dstate, __entry->temp)
);

DEFINE_EVENT(sched_cpu_load, sched_cpu_load_wakeup,
	TP_PROTO(struct rq *rq, int idle, u64 irqload, unsigned int power_cost, int temp),
	TP_ARGS(rq, idle, irqload, power_cost, temp)
);

DEFINE_EVENT(sched_cpu_load, sched_cpu_load_lb,
	TP_PROTO(struct rq *rq, int idle, u64 irqload, unsigned int power_cost, int temp),
	TP_ARGS(rq, idle, irqload, power_cost, temp)
);

DEFINE_EVENT(sched_cpu_load, sched_cpu_load_cgroup,
	TP_PROTO(struct rq *rq, int idle, u64 irqload, unsigned int power_cost, int temp),
	TP_ARGS(rq, idle, irqload, power_cost, temp)
);

TRACE_EVENT(sched_set_boost,

	TP_PROTO(int ref_count),

	TP_ARGS(ref_count),

	TP_STRUCT__entry(
		__field(unsigned int, ref_count			)
	),

	TP_fast_assign(
		__entry->ref_count = ref_count;
	),

	TP_printk("ref_count=%d", __entry->ref_count)
);

TRACE_EVENT(sched_update_task_ravg,

	TP_PROTO(struct task_struct *p, struct rq *rq, enum task_event evt,
		 u64 wallclock, u64 irqtime, u64 cycles, u64 exec_time,
		 struct group_cpu_time *cpu_time),

	TP_ARGS(p, rq, evt, wallclock, irqtime, cycles, exec_time, cpu_time),

	TP_STRUCT__entry(
		__array(	char,	comm,   TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	pid_t,	cur_pid			)
		__field(unsigned int,	cur_freq		)
		__field(	u64,	wallclock		)
		__field(	u64,	mark_start		)
		__field(	u64,	delta_m			)
		__field(	u64,	win_start		)
		__field(	u64,	delta			)
		__field(	u64,	irqtime			)
		__field(enum task_event,	evt		)
		__field(unsigned int,	demand			)
		__field(unsigned int,	sum			)
		__field(	 int,	cpu			)
#ifdef CONFIG_SCHED_FREQ_INPUT
		__field(unsigned int,	pred_demand		)
		__field(	u64,	rq_cs			)
		__field(	u64,	rq_ps			)
		__field(	u64,	grp_cs			)
		__field(	u64,	grp_ps			)
		__field(	u64,	grp_nt_cs			)
		__field(	u64,	grp_nt_ps			)
		__field(	u32,	curr_window		)
		__field(	u32,	prev_window		)
		__field(	u64,	nt_cs			)
		__field(	u64,	nt_ps			)
		__field(	u32,	active_windows		)
#endif
	),

	TP_fast_assign(
		__entry->wallclock      = wallclock;
		__entry->win_start      = rq->window_start;
		__entry->delta          = (wallclock - rq->window_start);
		__entry->evt            = evt;
		__entry->cpu            = rq->cpu;
		__entry->cur_pid        = rq->curr->pid;
		__entry->cur_freq       = cpu_cycles_to_freq(cycles, exec_time);
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid            = p->pid;
		__entry->mark_start     = p->ravg.mark_start;
		__entry->delta_m        = (wallclock - p->ravg.mark_start);
		__entry->demand         = p->ravg.demand;
		__entry->sum            = p->ravg.sum;
		__entry->irqtime        = irqtime;
#ifdef CONFIG_SCHED_FREQ_INPUT
		__entry->pred_demand     = p->ravg.pred_demand;
		__entry->rq_cs          = rq->curr_runnable_sum;
		__entry->rq_ps          = rq->prev_runnable_sum;
		__entry->grp_cs = cpu_time ? cpu_time->curr_runnable_sum : 0;
		__entry->grp_ps = cpu_time ? cpu_time->prev_runnable_sum : 0;
		__entry->grp_nt_cs = cpu_time ? cpu_time->nt_curr_runnable_sum : 0;
		__entry->grp_nt_ps = cpu_time ? cpu_time->nt_prev_runnable_sum : 0;
		__entry->curr_window	= p->ravg.curr_window;
		__entry->prev_window	= p->ravg.prev_window;
		__entry->nt_cs		= rq->nt_curr_runnable_sum;
		__entry->nt_ps		= rq->nt_prev_runnable_sum;
		__entry->active_windows	= p->ravg.active_windows;
#endif
	),

	TP_printk("wc %llu ws %llu delta %llu event %s cpu %d cur_freq %u cur_pid %d task %d (%s) ms %llu delta %llu demand %u sum %u irqtime %llu"
#ifdef CONFIG_SCHED_FREQ_INPUT
		" pred_demand %u rq_cs %llu rq_ps %llu cur_window %u prev_window %u nt_cs %llu nt_ps %llu active_wins %u grp_cs %lld grp_ps %lld, grp_nt_cs %llu, grp_nt_ps: %llu"
#endif
		, __entry->wallclock, __entry->win_start, __entry->delta,
		task_event_names[__entry->evt], __entry->cpu,
		__entry->cur_freq, __entry->cur_pid,
		__entry->pid, __entry->comm, __entry->mark_start,
		__entry->delta_m, __entry->demand,
		__entry->sum, __entry->irqtime
#ifdef CONFIG_SCHED_FREQ_INPUT
		, __entry->pred_demand, __entry->rq_cs, __entry->rq_ps,
		__entry->curr_window, __entry->prev_window,
		  __entry->nt_cs, __entry->nt_ps,
		  __entry->active_windows,
		__entry->grp_cs, __entry->grp_ps,
		__entry->grp_nt_cs, __entry->grp_nt_ps
#endif
		)
);

TRACE_EVENT(sched_get_task_cpu_cycles,

	TP_PROTO(int cpu, int event, u64 cycles, u64 exec_time),

	TP_ARGS(cpu, event, cycles, exec_time),

	TP_STRUCT__entry(
		__field(int,		cpu		)
		__field(int,		event		)
		__field(u64,		cycles		)
		__field(u64,		exec_time	)
		__field(u32,		freq		)
		__field(u32,		legacy_freq	)
	),

	TP_fast_assign(
		__entry->cpu 		= cpu;
		__entry->event 		= event;
		__entry->cycles 	= cycles;
		__entry->exec_time 	= exec_time;
		__entry->freq		= cpu_cycles_to_freq(cycles, exec_time);
		__entry->legacy_freq 	= cpu_cur_freq(cpu);
	),

	TP_printk("cpu=%d event=%d cycles=%llu exec_time=%llu freq=%u legacy_freq=%u",
		  __entry->cpu, __entry->event, __entry->cycles,
		  __entry->exec_time, __entry->freq, __entry->legacy_freq)
);

TRACE_EVENT(sched_update_history,

	TP_PROTO(struct rq *rq, struct task_struct *p, u32 runtime, int samples,
			enum task_event evt),

	TP_ARGS(rq, p, runtime, samples, evt),

	TP_STRUCT__entry(
		__array(	char,	comm,   TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(unsigned int,	runtime			)
		__field(	 int,	samples			)
		__field(enum task_event,	evt		)
		__field(unsigned int,	demand			)
#ifdef CONFIG_SCHED_FREQ_INPUT
		__field(unsigned int,	pred_demand		)
#endif
		__array(	 u32,	hist, RAVG_HIST_SIZE_MAX)
		__field(unsigned int,	nr_big_tasks		)
		__field(	 int,	cpu			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid            = p->pid;
		__entry->runtime        = runtime;
		__entry->samples        = samples;
		__entry->evt            = evt;
		__entry->demand         = p->ravg.demand;
#ifdef CONFIG_SCHED_FREQ_INPUT
		__entry->pred_demand     = p->ravg.pred_demand;
#endif
		memcpy(__entry->hist, p->ravg.sum_history,
					RAVG_HIST_SIZE_MAX * sizeof(u32));
		__entry->nr_big_tasks   = rq->hmp_stats.nr_big_tasks;
		__entry->cpu            = rq->cpu;
	),

	TP_printk("%d (%s): runtime %u samples %d event %s demand %u"
#ifdef CONFIG_SCHED_FREQ_INPUT
		" pred_demand %u"
#endif
		" (hist: %u %u %u %u %u) cpu %d nr_big %u",
		__entry->pid, __entry->comm,
		__entry->runtime, __entry->samples,
		task_event_names[__entry->evt],
		__entry->demand,
#ifdef CONFIG_SCHED_FREQ_INPUT
		__entry->pred_demand,
#endif
		__entry->hist[0], __entry->hist[1],
		__entry->hist[2], __entry->hist[3],
		__entry->hist[4], __entry->cpu, __entry->nr_big_tasks)
);

TRACE_EVENT(sched_reset_all_window_stats,

	TP_PROTO(u64 window_start, u64 window_size, u64 time_taken,
		int reason, unsigned int old_val, unsigned int new_val),

	TP_ARGS(window_start, window_size, time_taken,
		reason, old_val, new_val),

	TP_STRUCT__entry(
		__field(	u64,	window_start		)
		__field(	u64,	window_size		)
		__field(	u64,	time_taken		)
		__field(	int,	reason			)
		__field(unsigned int,	old_val			)
		__field(unsigned int,	new_val			)
	),

	TP_fast_assign(
		__entry->window_start = window_start;
		__entry->window_size = window_size;
		__entry->time_taken = time_taken;
		__entry->reason	= reason;
		__entry->old_val = old_val;
		__entry->new_val = new_val;
	),

	TP_printk("time_taken %llu window_start %llu window_size %llu reason %s old_val %u new_val %u",
		  __entry->time_taken, __entry->window_start,
		  __entry->window_size,
		  sched_window_reset_reasons[__entry->reason],
		  __entry->old_val, __entry->new_val)
);

#ifdef CONFIG_SCHED_FREQ_INPUT

TRACE_EVENT(sched_update_pred_demand,

	TP_PROTO(struct rq *rq, struct task_struct *p, u32 runtime, int pct,
		 unsigned int pred_demand),

	TP_ARGS(rq, p, runtime, pct, pred_demand),

	TP_STRUCT__entry(
		__array(	char,	comm,   TASK_COMM_LEN	)
		__field(       pid_t,	pid			)
		__field(unsigned int,	runtime			)
		__field(	 int,	pct			)
		__field(unsigned int,	pred_demand		)
		__array(	  u8,	bucket, NUM_BUSY_BUCKETS)
		__field(	 int,	cpu			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid            = p->pid;
		__entry->runtime        = runtime;
		__entry->pct            = pct;
		__entry->pred_demand     = pred_demand;
		memcpy(__entry->bucket, p->ravg.busy_buckets,
					NUM_BUSY_BUCKETS * sizeof(u8));
		__entry->cpu            = rq->cpu;
	),

	TP_printk("%d (%s): runtime %u pct %d cpu %d pred_demand %u (buckets: %u %u %u %u %u %u %u %u %u %u)",
		__entry->pid, __entry->comm,
		__entry->runtime, __entry->pct, __entry->cpu,
		__entry->pred_demand, __entry->bucket[0], __entry->bucket[1],
		__entry->bucket[2], __entry->bucket[3],__entry->bucket[4],
		__entry->bucket[5], __entry->bucket[6], __entry->bucket[7],
		__entry->bucket[8], __entry->bucket[9])
);

TRACE_EVENT(sched_migration_update_sum,

	TP_PROTO(struct task_struct *p, enum migrate_types migrate_type, struct migration_sum_data *d),

	TP_ARGS(p, migrate_type, d),

	TP_STRUCT__entry(
		__field(int,		tcpu			)
		__field(int,		pid			)
		__field(	u64,	cs			)
		__field(	u64,	ps			)
		__field(	s64,	nt_cs			)
		__field(	s64,	nt_ps			)
		__field(enum migrate_types,	migrate_type	)
		__field(	s64,	src_cs			)
		__field(	s64,	src_ps			)
		__field(	s64,	dst_cs			)
		__field(	s64,	dst_ps			)
		__field(	s64,	src_nt_cs		)
		__field(	s64,	src_nt_ps		)
		__field(	s64,	dst_nt_cs		)
		__field(	s64,	dst_nt_ps		)
	),

	TP_fast_assign(
		__entry->tcpu		= task_cpu(p);
		__entry->pid		= p->pid;
		__entry->migrate_type	= migrate_type;
		__entry->src_cs		= d->src_rq ?
						d->src_rq->curr_runnable_sum :
						d->src_cpu_time->curr_runnable_sum;
		__entry->src_ps		= d->src_rq ?
						d->src_rq->prev_runnable_sum :
						d->src_cpu_time->prev_runnable_sum;
		__entry->dst_cs		= d->dst_rq ?
						d->dst_rq->curr_runnable_sum :
						d->dst_cpu_time->curr_runnable_sum;
		__entry->dst_ps		= d->dst_rq ?
						d->dst_rq->prev_runnable_sum :
						d->dst_cpu_time->prev_runnable_sum;
		__entry->src_nt_cs		= d->src_rq ?
						d->src_rq->nt_curr_runnable_sum :
						d->src_cpu_time->nt_curr_runnable_sum;
		__entry->src_nt_ps		= d->src_rq ?
						d->src_rq->nt_prev_runnable_sum :
						d->src_cpu_time->nt_prev_runnable_sum;
		__entry->dst_nt_cs		= d->dst_rq ?
						d->dst_rq->nt_curr_runnable_sum :
						d->dst_cpu_time->nt_curr_runnable_sum;
		__entry->dst_nt_ps		= d->dst_rq ?
						d->dst_rq->nt_prev_runnable_sum :
						d->dst_cpu_time->nt_prev_runnable_sum;
	),

	TP_printk("pid %d task_cpu %d migrate_type %s src_cs %llu src_ps %llu dst_cs %lld dst_ps %lld src_nt_cs %llu src_nt_ps %llu dst_nt_cs %lld dst_nt_ps %lld",
		__entry->pid, __entry->tcpu, migrate_type_names[__entry->migrate_type],
		__entry->src_cs, __entry->src_ps, __entry->dst_cs, __entry->dst_ps,
		__entry->src_nt_cs, __entry->src_nt_ps, __entry->dst_nt_cs, __entry->dst_nt_ps)
);

TRACE_EVENT(sched_get_busy,

	TP_PROTO(int cpu, u64 load, u64 nload, u64 pload, int early),

	TP_ARGS(cpu, load, nload, pload, early),

	TP_STRUCT__entry(
		__field(	int,	cpu			)
		__field(	u64,	load			)
		__field(	u64,	nload			)
		__field(	u64,	pload			)
		__field(	int,	early			)
	),

	TP_fast_assign(
		__entry->cpu		= cpu;
		__entry->load		= load;
		__entry->nload		= nload;
		__entry->pload		= pload;
		__entry->early		= early;
	),

	TP_printk("cpu %d load %lld new_task_load %lld predicted_load %lld early %d",
		__entry->cpu, __entry->load, __entry->nload,
		__entry->pload, __entry->early)
);

TRACE_EVENT(sched_freq_alert,

	TP_PROTO(int cpu, int pd_notif, int check_groups, struct rq *rq,
		u64 new_load),

	TP_ARGS(cpu, pd_notif, check_groups, rq, new_load),

	TP_STRUCT__entry(
		__field(	int,	cpu			)
		__field(	int,	pd_notif		)
		__field(	int,	check_groups		)
		__field(	u64,	old_busy_time		)
		__field(	u64,	ps			)
		__field(	u64,	new_load		)
		__field(	u64,	old_pred		)
		__field(	u64,	new_pred		)
	),

	TP_fast_assign(
		__entry->cpu		= cpu;
		__entry->pd_notif	= pd_notif;
		__entry->check_groups	= check_groups;
		__entry->old_busy_time	= rq->old_busy_time;
		__entry->ps		= rq->prev_runnable_sum;
		__entry->new_load	= new_load;
		__entry->old_pred	= rq->old_estimated_time;
		__entry->new_pred	= rq->hmp_stats.pred_demands_sum;
	),

	TP_printk("cpu %d pd_notif=%d check_groups %d old_busy_time=%llu prev_sum=%lld new_load=%llu old_pred=%llu new_pred=%llu",
		__entry->cpu, __entry->pd_notif, __entry->check_groups,
		__entry->old_busy_time, __entry->ps, __entry->new_load,
		__entry->old_pred, __entry->new_pred)
);

#endif	/* CONFIG_SCHED_FREQ_INPUT */

#endif	/* CONFIG_SCHED_HMP */

/*
 * Tracepoint for waking up a task:
 */
DECLARE_EVENT_CLASS(sched_wakeup_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(__perf_task(p)),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(	int,	success			)
		__field(	int,	target_cpu		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
		__entry->success	= 1; /* rudiment, kill when possible */
		__entry->target_cpu	= task_cpu(p);
	),

	TP_printk("comm=%s pid=%d prio=%d target_cpu=%03d",
		  __entry->comm, __entry->pid, __entry->prio,
		  __entry->target_cpu)
);

/*
 * Tracepoint called when waking a task; this tracepoint is guaranteed to be
 * called from the waking context.
 */
DEFINE_EVENT(sched_wakeup_template, sched_waking,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint called when the task is actually woken; p->state == TASK_RUNNNG.
 * It it not always called from the waking context.
 */
DEFINE_EVENT(sched_wakeup_template, sched_wakeup,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for waking up a new task:
 */
DEFINE_EVENT(sched_wakeup_template, sched_wakeup_new,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

#ifdef CREATE_TRACE_POINTS
static inline long __trace_sched_switch_state(struct task_struct *p)
{
	long state = p->state;

#ifdef CONFIG_PREEMPT
	/*
	 * For all intents and purposes a preempted task is a running task.
	 */
	if (preempt_count() & PREEMPT_ACTIVE)
		state = TASK_RUNNING | TASK_STATE_MAX;
#endif

	return state;
}
#endif

/*
 * Tracepoint for task switches, performed by the scheduler:
 */
TRACE_EVENT(sched_switch,

	TP_PROTO(struct task_struct *prev,
		 struct task_struct *next),

	TP_ARGS(prev, next),

	TP_STRUCT__entry(
		__array(	char,	prev_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	prev_pid			)
		__field(	int,	prev_prio			)
		__field(	long,	prev_state			)
		__array(	char,	next_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	next_pid			)
		__field(	int,	next_prio			)
	),

	TP_fast_assign(
		memcpy(__entry->next_comm, next->comm, TASK_COMM_LEN);
		__entry->prev_pid	= prev->pid;
		__entry->prev_prio	= prev->prio;
		__entry->prev_state	= __trace_sched_switch_state(prev);
		memcpy(__entry->prev_comm, prev->comm, TASK_COMM_LEN);
		__entry->next_pid	= next->pid;
		__entry->next_prio	= next->prio;
	),

	TP_printk("prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d",
		__entry->prev_comm, __entry->prev_pid, __entry->prev_prio,
		__entry->prev_state & (TASK_STATE_MAX-1) ?
		  __print_flags(__entry->prev_state & (TASK_STATE_MAX-1), "|",
				{ 1, "S"} , { 2, "D" }, { 4, "T" }, { 8, "t" },
				{ 16, "Z" }, { 32, "X" }, { 64, "x" },
				{ 128, "K" }, { 256, "W" }, { 512, "P" }) : "R",
		__entry->prev_state & TASK_STATE_MAX ? "+" : "",
		__entry->next_comm, __entry->next_pid, __entry->next_prio)
);

/*
 * Tracepoint for a task being migrated:
 */
TRACE_EVENT(sched_migrate_task,

	TP_PROTO(struct task_struct *p, int dest_cpu,
		 unsigned int load),

	TP_ARGS(p, dest_cpu, load),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(unsigned int,	load			)
		__field(	int,	orig_cpu		)
		__field(	int,	dest_cpu		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
		__entry->load		= load;
		__entry->orig_cpu	= task_cpu(p);
		__entry->dest_cpu	= dest_cpu;
	),

	TP_printk("comm=%s pid=%d prio=%d load=%d orig_cpu=%d dest_cpu=%d",
		  __entry->comm, __entry->pid, __entry->prio,  __entry->load,
		  __entry->orig_cpu, __entry->dest_cpu)
);

/*
 * Tracepoint for load balancing:
 */
#if NR_CPUS > 32
#error "Unsupported NR_CPUS for lb tracepoint."
#endif
TRACE_EVENT(sched_load_balance,

	TP_PROTO(int cpu, enum cpu_idle_type idle, int balance,
		 unsigned long group_mask, int busiest_nr_running,
		 unsigned long imbalance, unsigned int env_flags, int ld_moved,
		 unsigned int balance_interval),

	TP_ARGS(cpu, idle, balance, group_mask, busiest_nr_running,
		imbalance, env_flags, ld_moved, balance_interval),

	TP_STRUCT__entry(
		__field(	int,			cpu)
		__field(	enum cpu_idle_type,	idle)
		__field(	int,			balance)
		__field(	unsigned long,		group_mask)
		__field(	int,			busiest_nr_running)
		__field(	unsigned long,		imbalance)
		__field(	unsigned int,		env_flags)
		__field(	int,			ld_moved)
		__field(	unsigned int,		balance_interval)
	),

	TP_fast_assign(
		__entry->cpu			= cpu;
		__entry->idle			= idle;
		__entry->balance		= balance;
		__entry->group_mask		= group_mask;
		__entry->busiest_nr_running	= busiest_nr_running;
		__entry->imbalance		= imbalance;
		__entry->env_flags		= env_flags;
		__entry->ld_moved		= ld_moved;
		__entry->balance_interval	= balance_interval;
	),

	TP_printk("cpu=%d state=%s balance=%d group=%#lx busy_nr=%d imbalance=%ld flags=%#x ld_moved=%d bal_int=%d",
		  __entry->cpu,
		  __entry->idle == CPU_IDLE ? "idle" :
		  (__entry->idle == CPU_NEWLY_IDLE ? "newly_idle" : "busy"),
		  __entry->balance,
		  __entry->group_mask, __entry->busiest_nr_running,
		  __entry->imbalance, __entry->env_flags, __entry->ld_moved,
		  __entry->balance_interval)
);

/*
 * Tracepoint for a CPU going offline/online:
 */
TRACE_EVENT(sched_cpu_hotplug,

	TP_PROTO(int affected_cpu, int error, int status),

	TP_ARGS(affected_cpu, error, status),

	TP_STRUCT__entry(
		__field(	int,	affected_cpu		)
		__field(	int,	error			)
		__field(	int,	status			)
	),

	TP_fast_assign(
		__entry->affected_cpu	= affected_cpu;
		__entry->error		= error;
		__entry->status		= status;
	),

	TP_printk("cpu %d %s error=%d", __entry->affected_cpu,
		__entry->status ? "online" : "offline", __entry->error)
);

DECLARE_EVENT_CLASS(sched_process_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(p),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
	),

	TP_printk("comm=%s pid=%d prio=%d",
		  __entry->comm, __entry->pid, __entry->prio)
);

/*
 * Tracepoint for freeing a task:
 */
DEFINE_EVENT(sched_process_template, sched_process_free,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));


/*
 * Tracepoint for a task exiting:
 */
DEFINE_EVENT(sched_process_template, sched_process_exit,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for waiting on task to unschedule:
 */
DEFINE_EVENT(sched_process_template, sched_wait_task,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for a waiting task:
 */
TRACE_EVENT(sched_process_wait,

	TP_PROTO(struct pid *pid),

	TP_ARGS(pid),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
		__entry->pid		= pid_nr(pid);
		__entry->prio		= current->prio;
	),

	TP_printk("comm=%s pid=%d prio=%d",
		  __entry->comm, __entry->pid, __entry->prio)
);

/*
 * Tracepoint for do_fork:
 */
TRACE_EVENT(sched_process_fork,

	TP_PROTO(struct task_struct *parent, struct task_struct *child),

	TP_ARGS(parent, child),

	TP_STRUCT__entry(
		__array(	char,	parent_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	parent_pid			)
		__array(	char,	child_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	child_pid			)
	),

	TP_fast_assign(
		memcpy(__entry->parent_comm, parent->comm, TASK_COMM_LEN);
		__entry->parent_pid	= parent->pid;
		memcpy(__entry->child_comm, child->comm, TASK_COMM_LEN);
		__entry->child_pid	= child->pid;
	),

	TP_printk("comm=%s pid=%d child_comm=%s child_pid=%d",
		__entry->parent_comm, __entry->parent_pid,
		__entry->child_comm, __entry->child_pid)
);

/*
 * Tracepoint for exec:
 */
TRACE_EVENT(sched_process_exec,

	TP_PROTO(struct task_struct *p, pid_t old_pid,
		 struct linux_binprm *bprm),

	TP_ARGS(p, old_pid, bprm),

	TP_STRUCT__entry(
		__string(	filename,	bprm->filename	)
		__field(	pid_t,		pid		)
		__field(	pid_t,		old_pid		)
	),

	TP_fast_assign(
		__assign_str(filename, bprm->filename);
		__entry->pid		= p->pid;
		__entry->old_pid	= old_pid;
	),

	TP_printk("filename=%s pid=%d old_pid=%d", __get_str(filename),
		  __entry->pid, __entry->old_pid)
);

/*
 * XXX the below sched_stat tracepoints only apply to SCHED_OTHER/BATCH/IDLE
 *     adding sched_stat support to SCHED_FIFO/RR would be welcome.
 */
DECLARE_EVENT_CLASS(sched_stat_template,

	TP_PROTO(struct task_struct *tsk, u64 delay),

	TP_ARGS(__perf_task(tsk), __perf_count(delay)),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( u64,	delay			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid	= tsk->pid;
		__entry->delay	= delay;
	),

	TP_printk("comm=%s pid=%d delay=%Lu [ns]",
			__entry->comm, __entry->pid,
			(unsigned long long)__entry->delay)
);


/*
 * Tracepoint for accounting wait time (time the task is runnable
 * but not actually running due to scheduler contention).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_wait,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting sleep time (time the task is not runnable,
 * including iowait, see below).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_sleep,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting iowait time (time the task is not runnable
 * due to waiting on IO to complete).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_iowait,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting blocked time (time the task is in uninterruptible).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_blocked,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for recording the cause of uninterruptible sleep.
 */
TRACE_EVENT(sched_blocked_reason,

	TP_PROTO(struct task_struct *tsk),

	TP_ARGS(tsk),

	TP_STRUCT__entry(
		__field( pid_t,	pid	)
		__field( void*, caller	)
		__field( bool, io_wait	)
	),

	TP_fast_assign(
		__entry->pid	= tsk->pid;
		__entry->caller = (void*)get_wchan(tsk);
		__entry->io_wait = tsk->in_iowait;
	),

	TP_printk("pid=%d iowait=%d caller=%pS", __entry->pid, __entry->io_wait, __entry->caller)
);

/*
 * Tracepoint for accounting runtime (time the task is executing
 * on a CPU).
 */
DECLARE_EVENT_CLASS(sched_stat_runtime,

	TP_PROTO(struct task_struct *tsk, u64 runtime, u64 vruntime),

	TP_ARGS(tsk, __perf_count(runtime), vruntime),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( u64,	runtime			)
		__field( u64,	vruntime			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid		= tsk->pid;
		__entry->runtime	= runtime;
		__entry->vruntime	= vruntime;
	),

	TP_printk("comm=%s pid=%d runtime=%Lu [ns] vruntime=%Lu [ns]",
			__entry->comm, __entry->pid,
			(unsigned long long)__entry->runtime,
			(unsigned long long)__entry->vruntime)
);

DEFINE_EVENT(sched_stat_runtime, sched_stat_runtime,
	     TP_PROTO(struct task_struct *tsk, u64 runtime, u64 vruntime),
	     TP_ARGS(tsk, runtime, vruntime));

/*
 * Tracepoint for showing priority inheritance modifying a tasks
 * priority.
 */
TRACE_EVENT(sched_pi_setprio,

	TP_PROTO(struct task_struct *tsk, int newprio),

	TP_ARGS(tsk, newprio),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( int,	oldprio			)
		__field( int,	newprio			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid		= tsk->pid;
		__entry->oldprio	= tsk->prio;
		__entry->newprio	= newprio;
	),

	TP_printk("comm=%s pid=%d oldprio=%d newprio=%d",
			__entry->comm, __entry->pid,
			__entry->oldprio, __entry->newprio)
);

#ifdef CONFIG_DETECT_HUNG_TASK
TRACE_EVENT(sched_process_hang,
	TP_PROTO(struct task_struct *tsk),
	TP_ARGS(tsk),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid = tsk->pid;
	),

	TP_printk("comm=%s pid=%d", __entry->comm, __entry->pid)
);
#endif /* CONFIG_DETECT_HUNG_TASK */

DECLARE_EVENT_CLASS(sched_move_task_template,

	TP_PROTO(struct task_struct *tsk, int src_cpu, int dst_cpu),

	TP_ARGS(tsk, src_cpu, dst_cpu),

	TP_STRUCT__entry(
		__field( pid_t,	pid			)
		__field( pid_t,	tgid			)
		__field( pid_t,	ngid			)
		__field( int,	src_cpu			)
		__field( int,	src_nid			)
		__field( int,	dst_cpu			)
		__field( int,	dst_nid			)
	),

	TP_fast_assign(
		__entry->pid		= task_pid_nr(tsk);
		__entry->tgid		= task_tgid_nr(tsk);
		__entry->ngid		= task_numa_group_id(tsk);
		__entry->src_cpu	= src_cpu;
		__entry->src_nid	= cpu_to_node(src_cpu);
		__entry->dst_cpu	= dst_cpu;
		__entry->dst_nid	= cpu_to_node(dst_cpu);
	),

	TP_printk("pid=%d tgid=%d ngid=%d src_cpu=%d src_nid=%d dst_cpu=%d dst_nid=%d",
			__entry->pid, __entry->tgid, __entry->ngid,
			__entry->src_cpu, __entry->src_nid,
			__entry->dst_cpu, __entry->dst_nid)
);

/*
 * Tracks migration of tasks from one runqueue to another. Can be used to
 * detect if automatic NUMA balancing is bouncing between nodes
 */
DEFINE_EVENT(sched_move_task_template, sched_move_numa,
	TP_PROTO(struct task_struct *tsk, int src_cpu, int dst_cpu),

	TP_ARGS(tsk, src_cpu, dst_cpu)
);

DEFINE_EVENT(sched_move_task_template, sched_stick_numa,
	TP_PROTO(struct task_struct *tsk, int src_cpu, int dst_cpu),

	TP_ARGS(tsk, src_cpu, dst_cpu)
);

TRACE_EVENT(sched_swap_numa,

	TP_PROTO(struct task_struct *src_tsk, int src_cpu,
		 struct task_struct *dst_tsk, int dst_cpu),

	TP_ARGS(src_tsk, src_cpu, dst_tsk, dst_cpu),

	TP_STRUCT__entry(
		__field( pid_t,	src_pid			)
		__field( pid_t,	src_tgid		)
		__field( pid_t,	src_ngid		)
		__field( int,	src_cpu			)
		__field( int,	src_nid			)
		__field( pid_t,	dst_pid			)
		__field( pid_t,	dst_tgid		)
		__field( pid_t,	dst_ngid		)
		__field( int,	dst_cpu			)
		__field( int,	dst_nid			)
	),

	TP_fast_assign(
		__entry->src_pid	= task_pid_nr(src_tsk);
		__entry->src_tgid	= task_tgid_nr(src_tsk);
		__entry->src_ngid	= task_numa_group_id(src_tsk);
		__entry->src_cpu	= src_cpu;
		__entry->src_nid	= cpu_to_node(src_cpu);
		__entry->dst_pid	= task_pid_nr(dst_tsk);
		__entry->dst_tgid	= task_tgid_nr(dst_tsk);
		__entry->dst_ngid	= task_numa_group_id(dst_tsk);
		__entry->dst_cpu	= dst_cpu;
		__entry->dst_nid	= cpu_to_node(dst_cpu);
	),

	TP_printk("src_pid=%d src_tgid=%d src_ngid=%d src_cpu=%d src_nid=%d dst_pid=%d dst_tgid=%d dst_ngid=%d dst_cpu=%d dst_nid=%d",
			__entry->src_pid, __entry->src_tgid, __entry->src_ngid,
			__entry->src_cpu, __entry->src_nid,
			__entry->dst_pid, __entry->dst_tgid, __entry->dst_ngid,
			__entry->dst_cpu, __entry->dst_nid)
);

/*
 * Tracepoint for waking a polling cpu without an IPI.
 */
TRACE_EVENT(sched_wake_idle_without_ipi,

	TP_PROTO(int cpu),

	TP_ARGS(cpu),

	TP_STRUCT__entry(
		__field(	int,	cpu	)
	),

	TP_fast_assign(
		__entry->cpu	= cpu;
	),

	TP_printk("cpu=%d", __entry->cpu)
);

TRACE_EVENT(sched_get_nr_running_avg,

	TP_PROTO(int avg, int big_avg, int iowait_avg),

	TP_ARGS(avg, big_avg, iowait_avg),

	TP_STRUCT__entry(
		__field( int,	avg			)
		__field( int,	big_avg			)
		__field( int,	iowait_avg		)
	),

	TP_fast_assign(
		__entry->avg		= avg;
		__entry->big_avg	= big_avg;
		__entry->iowait_avg	= iowait_avg;
	),

	TP_printk("avg=%d big_avg=%d iowait_avg=%d",
		__entry->avg, __entry->big_avg, __entry->iowait_avg)
);

TRACE_EVENT(core_ctl_eval_need,

	TP_PROTO(unsigned int cpu, unsigned int old_need,
		 unsigned int new_need, unsigned int updated),
	TP_ARGS(cpu, old_need, new_need, updated),
	TP_STRUCT__entry(
		__field(u32, cpu)
		__field(u32, old_need)
		__field(u32, new_need)
		__field(u32, updated)
	),
	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->old_need = old_need;
		__entry->new_need = new_need;
		__entry->updated = updated;
	),
	TP_printk("cpu=%u, old_need=%u, new_need=%u, updated=%u", __entry->cpu,
		  __entry->old_need, __entry->new_need, __entry->updated)
);

TRACE_EVENT(core_ctl_set_busy,

	TP_PROTO(unsigned int cpu, unsigned int busy,
		 unsigned int old_is_busy, unsigned int is_busy),
	TP_ARGS(cpu, busy, old_is_busy, is_busy),
	TP_STRUCT__entry(
		__field(u32, cpu)
		__field(u32, busy)
		__field(u32, old_is_busy)
		__field(u32, is_busy)
	),
	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->busy = busy;
		__entry->old_is_busy = old_is_busy;
		__entry->is_busy = is_busy;
	),
	TP_printk("cpu=%u, busy=%u, old_is_busy=%u, new_is_busy=%u",
		  __entry->cpu, __entry->busy, __entry->old_is_busy,
		  __entry->is_busy)
);

#endif /* _TRACE_SCHED_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
#endif /* CONFIG_SCHED_QHMP */
