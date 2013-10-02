#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kthread.h>
#include <linux/rbtree.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>

#define KFDNS_STAT_WINDOW 16384
#define KFDNS_PROCFS_STAT "kfdns"
#define DNS_HEADER_SIZE 12


struct ipstat_tree_node {
	struct rb_node node;
	uint ip;
	uint counter;
};

struct blockedip_tree_node {
	struct rb_node node;
	uint ip;
	uint counter;
};


static struct task_struct *kfdns_counter_thread;
static struct nf_hook_ops bundle;
static uint ips[KFDNS_STAT_WINDOW];
static struct rb_root ipstat_tree = RB_ROOT;
static struct rb_root kfdns_blockedip_tree = RB_ROOT;
static DEFINE_SPINLOCK(rec_lock);
static DEFINE_RWLOCK(rwlock);
static int threshold = 1000;

/*  
 *  DNS HEADER:
 *
 *  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                        ID                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|    Z   |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QDCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     ANCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     NSCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     ARCOUNT                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

static void kfdns_send_tc_packet(struct sk_buff *in_skb, uint dst_ip, uint dst_port, uint src_ip, const unsigned char *data)
{
	unsigned char *ndata;
	struct sk_buff *nskb;
	struct iphdr *iph;
	struct udphdr *udph;
	int udp_len;

	udp_len = sizeof(struct udphdr) + DNS_HEADER_SIZE;	
	nskb = alloc_skb(sizeof(struct iphdr) + udp_len +
			LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb) {
		printk(KERN_ERR "kfdns: Error, can`t allocate memory to DNS reply\n");
		return;
	}
	skb_reserve(nskb, LL_MAX_HEADER);
	skb_reset_network_header(nskb);

	iph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	iph->version	= 4;
	iph->ihl	= sizeof(struct iphdr) / 4;
	iph->ttl	= 64;
	iph->tos	= 0;
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
	iph->protocol	= IPPROTO_UDP;
	iph->saddr	= src_ip;
	iph->daddr	= dst_ip;
	iph->tot_len	= htons(sizeof(struct iphdr) + udp_len);
	iph->check	= 0;
	iph->check	= ip_fast_csum((unsigned char *)iph, iph->ihl);
	
	udph = (struct udphdr *)skb_put(nskb, sizeof(struct udphdr));
	memset(udph, 0, sizeof(*udph));
	udph->source = htons(53);
	udph->dest = dst_port;
	udph->len = htons(udp_len);
	skb_dst_set(nskb, dst_clone(skb_dst(in_skb)));
	nskb->protocol	= htons(ETH_P_IP);
	ndata = (char *)skb_put(nskb, DNS_HEADER_SIZE);
	memcpy(ndata, data, DNS_HEADER_SIZE); //copy header from query
	*(ndata + 2) |= 0x82; //set responce and tc bits
	udph->check = 0;
	udph->check = csum_tcpudp_magic(src_ip, dst_ip,
			udp_len, IPPROTO_UDP,
			csum_partial(udph, udp_len, 0));
	if(ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;
	ip_local_out(nskb);
	return;		
	
free_nskb:
	printk(KERN_ERR "Not good\n");
	kfree_skb(nskb);
}

static int kfdns_check_dns_header(unsigned char *data, uint len)
{
	if (len < DNS_HEADER_SIZE)
		return -1;
	if (*(data + sizeof(u16)) & 0x80)
		return 0; //response
	return 1; //request
}

static int kfdns_blockedip_tree_insert(uint ip, uint count)
{
	struct rb_node **link = &kfdns_blockedip_tree.rb_node;
	struct rb_node *parent = NULL;
	struct blockedip_tree_node *data;
	struct blockedip_tree_node *new;
	int len;
	unsigned long flags;
	while(*link) {
		parent = *link;
		data = rb_entry(parent, struct blockedip_tree_node, node);
		if (ip < data->ip)
			link = &(*link)->rb_left;
		else if (ip > data->ip)
			link = &(*link)->rb_right;
		else
			return 0;
	}
	len = sizeof(struct blockedip_tree_node);
	new = kzalloc(len, GFP_KERNEL);
	if (new == NULL)
		return -ENOMEM;
	local_bh_disable();
	write_lock_irqsave(&rwlock, flags);
	new->ip = ip;
	new->counter = count;
//	printk(KERN_INFO "kfdns: ip: %i blocked for DNS requests via UDP", new->ip);
	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, &kfdns_blockedip_tree);
	write_unlock_irqrestore(&rwlock, flags);
	local_bh_enable();
	return 0;
}

static void kfdns_blockedip_tree_free(void)
{
	struct rb_node *n = kfdns_blockedip_tree.rb_node;
	struct rb_node *parent;
	struct blockedip_tree_node *data;
	unsigned long flags;
	write_lock_irqsave(&rwlock, flags);
	while(n) {
		if (n->rb_left) {
			n = n->rb_left;
			continue;
		}
		if (n->rb_right) {
			n = n->rb_right;
			continue;
		}
		parent = rb_parent(n);
		data = rb_entry(n, struct blockedip_tree_node, node);
		rb_erase(n, &kfdns_blockedip_tree);
		kfree(data);
		n = parent;
	}
	write_unlock_irqrestore(&rwlock, flags);
}

static int kfdns_blockedip_tree_search(uint ip)
{
	struct rb_node *n = kfdns_blockedip_tree.rb_node;
	struct blockedip_tree_node *data;
	int res = 0;
	unsigned long flags;
	read_lock_irqsave(&rwlock, flags);
	while (n) {
		data = rb_entry(n, struct blockedip_tree_node, node);
		if (ip < data->ip) {
			n = n->rb_left;
		} else if (ip > data->ip) {
			n = n->rb_right;
		} else {
			res = 1;
			goto out;
		}
	}
out:
	read_unlock_irqrestore(&rwlock, flags);
	return res;
}

static void kfdns_blockedip_tree_del_ip(uint ip)
{
	struct rb_node *n = kfdns_blockedip_tree.rb_node;
	struct blockedip_tree_node *data;
	unsigned long flags;
	write_lock_irqsave(&rwlock, flags);
	while (n) {
		data = rb_entry(n, struct blockedip_tree_node, node);
		if (ip < data->ip) {
			n = n->rb_left;
		} else if (ip > data->ip) {
			n = n->rb_right;
		} else {
			rb_erase(n, &kfdns_blockedip_tree);
			kfree(data);
			break;
		}
	}
	write_unlock_irqrestore(&rwlock, flags);
}

static struct ipstat_tree_node *rb_ipstat_insert_and_count(uint ip)
{
	struct rb_node **link = &ipstat_tree.rb_node;
	struct rb_node *parent = NULL;
	struct ipstat_tree_node *data;
	struct ipstat_tree_node *new;
	int len;
	while(*link) {
		parent = *link;
		data = rb_entry(parent, struct ipstat_tree_node, node);
		if (ip < data->ip)
			link = &(*link)->rb_left;
		else if (ip > data->ip)
			link = &(*link)->rb_right;
		else {
			data->counter++;
			return data;
		}
	}
	len = sizeof(struct ipstat_tree_node);
	new = kzalloc(len, GFP_KERNEL);
	if(!new)
		return NULL;
	new->ip = ip;
	new->counter = 1;
	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, &ipstat_tree);
	return new;
}

static int rb_ipstat_find_and_free(void)
{
	struct rb_node *n = ipstat_tree.rb_node;
	struct rb_node *parent;
	struct ipstat_tree_node *data;
	while (n) {
		if (n->rb_left) {
			n = n->rb_left;
			continue;
		}
		if (n->rb_right) {
			n = n->rb_right;
			continue;
		}
		parent = rb_parent(n);
		data = rb_entry(n, struct ipstat_tree_node, node);
		if (data) {
			if (data->counter > threshold) {
				if (kfdns_blockedip_tree_insert(data->ip, data->counter) < 0)
					return -ENOMEM;
			} else {
				//TODO: implement hysteresis, or something more interested
				kfdns_blockedip_tree_del_ip(data->ip);
			}
			rb_erase(&data->node, &ipstat_tree);
			kfree(data);
		}
		n = parent;
	}
	return 0;
}


static int kfdns_update_stat(void)
{
	unsigned long flags;
	unsigned long i;
	int err = 0;
	local_bh_disable();
	spin_lock_irqsave(&rec_lock, flags);
	for(i = 0;i < KFDNS_STAT_WINDOW; i++) {
		if(!rb_ipstat_insert_and_count(ips[i]))
			err = -ENOMEM;	
	}
	spin_unlock_irqrestore(&rec_lock, flags);
	local_bh_enable();
	if (err == 0)
		return rb_ipstat_find_and_free();
	return err;
}

static int kfdns_add_ip(uint ip)
{
	unsigned long flags;
	static unsigned int n = 0;	
	spin_lock_irqsave(&rec_lock, flags);
	ips[n % KFDNS_STAT_WINDOW] = ip;
	n++;
	spin_unlock_irqrestore(&rec_lock, flags);
	return 0;
}

static int kfdns_counter_fn(void *data)
{
	int err;
	for(;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		msleep(1000);
		if (kthread_should_stop())
			break;
		if ((err = kfdns_update_stat())) {
			printk(KERN_ERR "kfdns: error while counting stats, err: %i\n", err);
			return err;
		}
	}
	return 0;
}

static uint kfdns_packet_hook(uint hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *) )
{
	struct iphdr *ip;
	struct udphdr *udp;
	unsigned char *data;
	unsigned int datalen;
	if (skb->protocol == htons(ETH_P_IP)) {
		ip = (struct iphdr *)skb_network_header(skb);
		if (ip->version == 4 && ip->protocol == IPPROTO_UDP) {
			skb_set_transport_header(skb, ip->ihl * 4);
			udp = (struct udphdr *)skb_transport_header(skb);
			if (udp->dest == htons(53)) {
				datalen = skb->len - sizeof(struct iphdr) - sizeof(struct udphdr);
				data = skb->data + sizeof(struct udphdr) + sizeof(struct iphdr);
				//Drop packet if it hasn`t got valid dns query header
				if (kfdns_check_dns_header(data, datalen) != 1)
					return NF_DROP;
				kfdns_add_ip(ip->saddr);
				if (kfdns_blockedip_tree_search(ip->saddr)) {
					kfdns_send_tc_packet(skb, ip->saddr, udp->source, ip->daddr, data);
					return NF_DROP;
				}
			}
		}
	}
	return NF_ACCEPT;
}

static void *kfdns_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct rb_node *node;
	int n = *pos;
	int i;
	read_lock_irq(&rwlock);
	if (n == 0)
		return SEQ_START_TOKEN;

	node = rb_first(&kfdns_blockedip_tree);
	for (i = 0; node && i < n; i++)
		node = rb_next(node);
	return node;
}

static void *kfdns_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct rb_node *node = v;

	(*pos)++;

	if (v == SEQ_START_TOKEN)
		return rb_first(&kfdns_blockedip_tree);
	
	return rb_next(node);
}

static void kfdns_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_irq(&rwlock);
}

static int kfdns_seq_show(struct seq_file *seq, void *v)
{
	struct blockedip_tree_node *l = container_of(v, struct blockedip_tree_node, node);
	if (v == SEQ_START_TOKEN) {
		 seq_puts(seq, "IP        counter\n");
	} else {
		seq_printf(seq, "%pI4    %u\n", &l->ip, l->counter);
	}
	return 0;
}

static const struct seq_operations kfdns_seq_ops = {
	.start  = kfdns_seq_start,
	.next   = kfdns_seq_next,
	.stop   = kfdns_seq_stop,
	.show   = kfdns_seq_show,
};

static int kfdns_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &kfdns_seq_ops,
		sizeof(struct neigh_seq_state));
}

static const struct file_operations kfdns_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= kfdns_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
};

static int kfdns_net_init(struct net *net)
{
	if (!proc_create(KFDNS_PROCFS_STAT, S_IRUGO, net->proc_net, &kfdns_seq_fops))
		return -ENOMEM;
	return 0;
}

static void kfdns_net_exit(struct net *net)
{
	remove_proc_entry(KFDNS_PROCFS_STAT, net->proc_net);
}

static struct pernet_operations kfdns_net_ops = {
	.init = kfdns_net_init,
	.exit = kfdns_net_exit,
};

static int kfdns_init(void)
{
	int err;
	printk(KERN_INFO "Starting kfdns module, threshold = %d \n", threshold);
	register_pernet_subsys(&kfdns_net_ops);
	kfdns_counter_thread = kthread_run(kfdns_counter_fn, NULL, "kfdns_counter_thread");
	if (IS_ERR(kfdns_counter_thread)) {
		printk(KERN_ERR "kfdns: creating thread failed\n");
		err = PTR_ERR(kfdns_counter_thread);
		return err;
	}
	bundle.hook = kfdns_packet_hook;
	bundle.owner = THIS_MODULE;
	bundle.pf = PF_INET;
//	bundle.hooknum = NF_INET_PRE_ROUTING;
	bundle.hooknum = NF_INET_LOCAL_IN;
	bundle.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&bundle);
	return 0;
}
static void kfdns_exit(void)
{
	kthread_stop(kfdns_counter_thread); 
	nf_unregister_hook(&bundle);
	rb_ipstat_find_and_free();
	kfdns_blockedip_tree_free();
	unregister_pernet_subsys(&kfdns_net_ops);
	printk(KERN_INFO "Stoping kfdns module\n");
}

module_init(kfdns_init);
module_exit(kfdns_exit);

module_param(threshold, int, 0);
MODULE_PARM_DESC(threshold, "Max number of reuests from one IP passed to dns");

MODULE_AUTHOR("Daniil Cherednik <dan.cherednik@gmail.com>");
MODULE_DESCRIPTION("filter DNS requests");
MODULE_LICENSE("GPL");


