// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched/clock.h>
#include "printk_ringbuffer.h"

/*
 * This is a test module that starts "num_online_cpus()" writer threads
 * that each write data of varying length. They do this as fast as
 * they can.
 *
 * Dictionary data is stored in a separate data ring. The writers will
 * only write dictionary data about half the time. This is to make the
 * test more realistic with text and dict data rings containing
 * different data blocks.
 *
 * Because the threads are running in such tight loops, they will call
 * schedule() from time to time so the system stays alive.
 *
 * If the writers encounter an error, the test is aborted. Test results are
 * recorded to the ftrace buffers, with some additional information also
 * provided via printk. The test can be aborted manually by removing the
 * module. (Ideally the test should never abort on its own.)
 */

/* used by writers to signal reader of new records */
DECLARE_WAIT_QUEUE_HEAD(test_wait);

/* test data structure */
struct rbdata {
	int len;
	char text[0];
};

static char *test_running;
static int halt_test;

/* dump text or dictionary data to the trace buffers */
static void print_record(const char *name, struct rbdata *dat, u64 seq)
{
	char buf[160];

	snprintf(buf, sizeof(buf), "%s", dat->text);
	buf[sizeof(buf) - 1] = 0;

	trace_printk("seq=%llu len=%d %sval=%s\n",
		     seq, dat->len, name,
		     dat->len < sizeof(buf) ? buf : "<invalid>");
}

static bool check_data(struct rbdata *dat, u64 seq, unsigned long num)
{
	static int allow_errors = 1;
	int len;

	len = strnlen(dat->text, 160);

	if (len != dat->len || len >= 160) {
		if (--allow_errors == 0)
			WRITE_ONCE(halt_test, 1);
		trace_printk("reader%lu invalid len for %llu (%d<->%d/0x%x)\n",
			     num, seq, len, dat->len, dat->len);
		return false;
	}

	while (len) {
		len--;
		if (dat->text[len] != dat->text[0]) {
			if (--allow_errors == 0)
				WRITE_ONCE(halt_test, 1);
			trace_printk("reader%lu bad data\n", num);
			return false;
		}
	}

	return true;
}

static bool printable(char *data)
{
	char c;
	int i;

	c = data[0];

	for (i = 0; i < 8; i++) {
		if (data[i] < 'A' || data[i] > 'Z')
			return false;
		if (data[i] != c)
			return false;
	}

	return true;
}

static void raw_dump(struct printk_ringbuffer *rb)
{
	struct prb_desc_ring *der = &rb->desc_ring;
	struct prb_data_ring *dar = &rb->text_data_ring;
	struct prb_desc *d;
	unsigned long *l;
	char *data;
	int i;

	trace_printk("BEGIN raw dump\n");

	trace_printk("BEGIN desc_ring\n");
	for (i = 0; i < (1 << der->count_bits); i++) {
		d = &der->descs[i];
		trace_printk("%05d: sv=%016lx begin=%016lx next=%016lx\n",
			i, atomic_long_read(&d->state_var),
			d->text_blk_lpos.begin,
			d->text_blk_lpos.next);
	}
	trace_printk("END desc_ring\n");

	trace_printk("BEGIN text_data_ring\n");
	for (i = 0; i < (1 << dar->size_bits); i += 8) {
		data = &dar->data[i];
		if (printable(data)) {
			trace_printk("%04x: %c%c%c%c%c%c%c%c (%02x)\n", i,
				data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7],
				data[0]);
		} else {
			l = (unsigned long *)data;
			trace_printk("%04x: %016lx\n", i, *l);
		}
	}
	trace_printk("END text_data_ring\n");

	trace_printk("END raw dump\n");
}

/*
 * sequentially dump all the valid records in the ringbuffer
 * (used to verify memory integrity)
 *
 * Since there is no reader interface, the internal members are
 * directly accessed. This function is called after all writers
 * are finished so there is no need for any memory barriers.
 */
static void dump_rb(struct printk_ringbuffer *rb)
{
	struct printk_info info;
	struct printk_record r;
	char text_buf[200];
	char dict_buf[200];
	u64 seq = 0;

	prb_rec_init_rd(&r, &info, &text_buf[0], sizeof(text_buf),
			&dict_buf[0], sizeof(dict_buf));

	trace_printk("BEGIN full dump\n");

	while (prb_read_valid(rb, seq, &r)) {
		/* check/track the sequence */
		if (info.seq != seq)
			trace_printk("DROPPED %llu\n", info.seq - seq);

		if (!check_data((struct rbdata *)&r.text_buf[0], info.seq, 7))
			trace_printk("*** BAD ***\n");

		print_record("TEXT", (struct rbdata *)&r.text_buf[0],
			     info.seq);
		if (info.dict_len) {
			print_record("DICT", (struct rbdata *)&r.dict_buf[0],
				     info.seq);
		}

		seq = info.seq + 1;
	}

	trace_printk("END full dump\n");

	raw_dump(rb);
}

DEFINE_PRINTKRB(test_rb, 10, 5, 5);

static int prbtest_writer(void *data)
{
	unsigned long num = (unsigned long)data;
	struct prb_reserved_entry e;
	char text_id = 'A' + num;
	char dict_id = 'a' + num;
	unsigned long count = 0;
	struct printk_record r;
	u64 min_ns = (u64)-1;
	struct rbdata *dat;
	u64 total_ns = 0;
	u64 max_ns = 0;
	u64 post_ns;
	u64 pre_ns;
	u64 seq;
	int len;

	set_cpus_allowed_ptr(current, cpumask_of(num));

	pr_err("prbtest: start thread %03lu (writer)\n", num);

	for (;;) {
		len = sizeof(struct rbdata) + (prandom_u32() & 0x7f) + 2;

		/* specify the text/dict sizes for reservation */
		/* only add a dictionary on some records */
		if (len % 2)
			prb_rec_init_wr(&r, len, len);
		else
			prb_rec_init_wr(&r, len, 0);

		pre_ns = local_clock();

		if (prb_reserve(&e, &test_rb, &r)) {
			dat = (struct rbdata *)&r.text_buf[0];
			dat->len = len - sizeof(struct rbdata) - 1;
			memset(&dat->text[0], text_id, dat->len);
			dat->text[dat->len] = 0;
			r.info->text_len = len;

			/* dictionary reservation is allowed to fail */
			if (r.dict_buf) {
				dat = (struct rbdata *)&r.dict_buf[0];
				dat->len = len - sizeof(struct rbdata) - 1;
				memset(&dat->text[0], dict_id, dat->len);
				dat->text[dat->len] = 0;
				r.info->dict_len = len;
			} else if (r.text_buf_size % 2) {
				trace_printk(
				    "writer%lu (%c) dict dropped: seq=%llu\n",
				    num, text_id, r.info->seq);
			}

			r.info->caller_id = num + 1048576;
			seq = r.info->seq;

			prb_commit(&e);

			post_ns = local_clock();

			/* append another struct */
			prb_rec_init_wr(&r, len, 0);
			if (prb_reserve_in_last(&e, &test_rb, &r, num + 1048576)) {
				if (r.info->seq != seq) {
					trace_printk("writer%lu (%c) unexpected seq: %llu != %llu\n",
						     num, text_id, r.info->seq, seq);
				}
				if (r.info->text_len != len) {
					trace_printk("writer%lu (%c) unexpected text_len: %u != %u\n",
						     num, text_id, r.info->text_len, len);
				}
				dat = (struct rbdata *)&r.text_buf[len];
				dat->len = len - sizeof(struct rbdata) - 1;
				memset(&dat->text[0], text_id, dat->len);
				dat->text[dat->len] = 0;
				r.info->text_len += len;
				prb_commit(&e);
			}

			wake_up_interruptible(&test_wait);

			post_ns -= pre_ns;
			if (post_ns < min_ns)
				min_ns = post_ns;
			if (post_ns > max_ns)
				max_ns = post_ns;
			total_ns += post_ns;
		}

		if ((count++ & 0x3fff) == 0)
			schedule();

		if (READ_ONCE(halt_test) == 1)
			break;
	}

	/* change @total_ns to average */
	do_div(total_ns, count);

	pr_err("prbtest: end thread %03lu (wrote %lu, max/avg/min %llu/%llu/%llu)\n",
	       num, count, max_ns, total_ns, min_ns);

	test_running[num] = 0;

	return 0;
}

static int prbtest_reader(void *data)
{
	unsigned long num = (unsigned long)data;
	unsigned long total_lost = 0;
	unsigned long max_lost = 0;
	unsigned long count = 0;
	struct printk_info info;
	struct printk_record r;
	struct rbdata *dat;
	char text_buf[400];
	char dict_buf[400];
	int did_sched = 1;
	u64 seq = 0;

	set_cpus_allowed_ptr(current, cpumask_of(num));

	prb_rec_init_rd(&r, &info, &text_buf[0], sizeof(text_buf),
			&dict_buf[0], sizeof(dict_buf));

	pr_err("prbtest: start thread %03lu (reader)\n", num);

	while (!wait_event_interruptible(test_wait,
				kthread_should_stop() ||
				prb_read_valid(&test_rb, seq, &r))) {
		if (kthread_should_stop())
			break;
		/* check/track the sequence */
		if (info.seq < seq) {
			WRITE_ONCE(halt_test, 1);
			trace_printk("reader%lu invalid seq %llu -> %llu\n",
				num, seq, info.seq);
		} else if (info.seq != seq && !did_sched) {
			total_lost += info.seq - seq;
			if (max_lost < info.seq - seq)
				max_lost = info.seq - seq;
		}

		dat = (struct rbdata *)&r.text_buf[0];
		if (!check_data(dat, info.seq, num))
			trace_printk("text error\n");

		if (info.text_len > dat->len + sizeof(struct rbdata) + 1) {
			dat = (struct rbdata *)&r.text_buf[dat->len + sizeof(struct rbdata) + 1];
			if (!check_data(dat, info.seq, num))
				trace_printk("text extension error\n");

			if (info.dict_len) {
				dat = (struct rbdata *)&r.dict_buf[0];
				if (!check_data(dat, info.seq, num))
					trace_printk("dict extension error\n");
			}
		} else if (info.dict_len) {
			dat = (struct rbdata *)&r.dict_buf[0];
			if (!check_data(dat, info.seq, num))
				trace_printk("dict error\n");
		} else if (info.text_len % 2) {
			trace_printk("dict dropped: seq=%llu\n", info.seq);
		}

		did_sched = 0;
		if ((count++ & 0x3fff) == 0) {
			did_sched = 1;
			schedule();
		}

		if (READ_ONCE(halt_test) == 1)
			break;

		seq = info.seq + 1;
	}

	pr_err(
	 "reader%lu: total_lost=%lu max_lost=%lu total_read=%lu seq=%llu\n",
	 num, total_lost, max_lost, count, info.seq);

	pr_err("prbtest: end thread %03lu (reader)\n", num);

	while (!kthread_should_stop())
		msleep(1000);
	test_running[num] = 0;

	return 0;
}

static int module_test_running;
static struct task_struct *reader_thread;

static int start_test(void *arg)
{
	struct task_struct *thread;
	unsigned long i;
	int num_cpus;

	num_cpus = num_online_cpus();
	test_running = kzalloc(num_cpus, GFP_KERNEL);
	if (!test_running)
		return -ENOMEM;

	module_test_running = 1;

	pr_err("prbtest: starting test\n");

	for (i = 0; i < num_cpus; i++) {
		test_running[i] = 1;
		if (i < num_cpus - 1) {
			thread = kthread_run(prbtest_writer, (void *)i,
					     "prbtest writer");
		} else {
			thread = kthread_run(prbtest_reader, (void *)i,
					     "prbtest reader");
			reader_thread = thread;
		}
		if (IS_ERR(thread)) {
			pr_err("prbtest: unable to create thread %lu\n", i);
			test_running[i] = 0;
		}
	}

	for (;;) {
		msleep(1000);

		for (i = 0; i < num_cpus; i++) {
			if (test_running[i] == 1)
				break;
		}
		if (i == num_cpus)
			break;
	}

	pr_err("prbtest: completed test\n");

	dump_rb(&test_rb);

	module_test_running = 0;

	return 0;
}

static int prbtest_init(void)
{
	kthread_run(start_test, NULL, "prbtest");
	return 0;
}

static void prbtest_exit(void)
{
	if (reader_thread && !IS_ERR(reader_thread))
		kthread_stop(reader_thread);

	WRITE_ONCE(halt_test, 1);

	while (module_test_running)
		msleep(1000);
	kfree(test_running);
}

module_init(prbtest_init);
module_exit(prbtest_exit);

MODULE_AUTHOR("John Ogness <john.ogness@linutronix.de>");
MODULE_DESCRIPTION("printk ringbuffer test");
MODULE_LICENSE("GPL v2");
