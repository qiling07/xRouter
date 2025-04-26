#ifndef LATENCY_H
#define LATENCY_H

#include <stddef.h>

/**
 * Probe latency to each host in the given network (CIDR notation).
 * For each IP in the subnet (excluding network and broadcast),
 * send 10 ICMP echo requests, measure RTTs, compute min/avg/max/mdev,
 * and append a line "IP min=%.3fms avg=%.3fms max=%.3fms mdev=%.3fms\n" to out.
 * If no replies at all, append "IP: timeout\n".
 *
 * @param network_cidr string like "10.10.1.0/24"
 * @param out          buffer to write results into
 * @param out_sz       size of out buffer
 */
void latency_probe_all(const char *network_cidr, char *out, size_t out_sz);

#endif // LATENCY_H