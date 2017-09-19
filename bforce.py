#!/usr/bin/env python

"""
    Brute-force a LUKS block-device header.

    This program implements cryptsetup with test passphrase to run in 
    multiple processes. 

    Uses k-n-permutation (also called variation-k of n).
    The number of items returned is n! / (n-k)!

    Sep 2017, Timo Koehler
"""
import itertools
import os
import sys
import time
import datetime
import subprocess
import multiprocessing

test_flag = False

if (test_flag):
    N = ["tree", "lemon", "green", "blue", "skye", "red", "test"]
    k = 4
    procs = 4
else:
    N = ["lemon", "green", "blue", "sky", "water", "deep",
         "tracks", "hot", "summer", "red", "stone", "orange",
         "fruit", "air", "fun", "sun", "nice", "big", "rocks",
         "cool", "small", "work", "works", "working", "bad", "is", "dark"]
    k = 4
    procs = 64


class Counter(object):

    def __init__(self, value=0, total=0, terminate=0, proc_count=0):
        self.count = multiprocessing.Value('i', value)
        self.total = multiprocessing.Value('i', total)
        self.terminate = multiprocessing.Value('i', terminate)
        self.proc_count = multiprocessing.Value('i', proc_count)
        self.lock_count = multiprocessing.Lock()
        self.lock_total = multiprocessing.Lock()
        self.lock_terminate = multiprocessing.Lock()
        self.lock_proc_count = multiprocessing.Lock()

    def increment(self, count):
        with self.lock_count:
            self.count.value += count

    def set_total(self, count):
        with self.lock_total:
            self.total.value += count

    def set_terminate(self):
        with self.lock_terminate:
            self.terminate.value = 1

    def inc_proc_count(self):
        with self.lock_proc_count:
            self.proc_count.value += 1

    def dec_proc_count(self):
        with self.lock_proc_count:
            self.proc_count.value -= 1

    def get_value(self):
        with self.lock_count:
            return self.count.value

    def get_total(self):
        with self.lock_total:
            return self.total.value

    def get_terminate(self):
        with self.lock_terminate:
            return self.terminate.value

    def get_proc_count(self):
        with self.lock_proc_count:
            return self.proc_count.value


def monitor(counter):
    upd_sec = 4
    """
    print("Starting counter " + multiprocessing.current_process().name)
    """
    while True:
        if counter.get_terminate():
            break

        procs = counter.get_proc_count();
        count = counter.get_value()
        n = counter.get_total()

        if (count == 0):
            percent, rate_s, rate_ms, x, est_d, est_h, est_m = 0, 0, 0, 0, 0, 0, 0
            start_time = datetime.datetime.now()
        else:
            elapsed_time = datetime.datetime.now() - start_time
            sec = elapsed_time.total_seconds()
            rate_s = count / sec
            rate_ms = sec * 1000 / count
            x = (n - count) / rate_s
            est_d = x / 86400
            est_h = (x % 86400) / 3600
            est_m = (x % 3600) / 60
            percent = (count * 100) / n

        sys.stdout.write('\r[ procs:%d, %d/%d, %d%%, %d ms, %0.2f /s, estimate remaining time: %dd%dh%dm ]'
                         % (procs, count, n, percent, rate_ms, rate_s, est_d, est_h, est_m))
        sys.stdout.flush()

        if (percent == 100):
            break

        time.sleep(upd_sec)


def worker(k_perms, first, last, counter):
    batch_upd = 10
    """
    print("Starting worker "
          + multiprocessing.current_process().name
          + ", first:" + str(first + 1)
          + ", last:" + str(last)
          + ", items:" + str(last - first))
    """
    counter.inc_proc_count();
    intvl_count = 0
    for i in k_perms[first:last]:
        if counter.get_terminate():
            break

        intvl_count += 1
        if (not intvl_count % batch_upd):
            counter.increment(intvl_count)
            intvl_count = 0

        teststring = ""
        shellcommands = ""

        """
        Some additional string manipulation of the passphrase.
        """
        if (test_flag):
            perm_str = ' '.join(i)
            perm_lst = perm_str.split()
            perm_lst[0] = perm_lst[0].capitalize()
            teststring = ' '.join(perm_lst)
        else:
            perm_str = ' '.join(i)
            perm_lst = perm_str.split()

            # a.4
            perm_lst[k - 2] = perm_lst[k - 2][0:1].upper() + perm_lst[k - 2][1:]
            
            # a.n)
            teststring = "Tree " + ' '.join(perm_lst)

        if (test_flag):
            shellcommands = "echo " \
                + "\"" \
                + teststring \
                + "\"" \
                + " | cryptsetup luksOpen --test-passphrase ./save-header 2>/dev/null"
        else:
            shellcommands = "echo " \
                + "\"" \
                + teststring \
                + "\"" \
                + " | cryptsetup luksOpen --test-passphrase ./backup-header 2>/dev/null"

        rc = subprocess.call(shellcommands, shell=True)
        if rc == 0:
            print("\n\nFound: " + teststring + "\n")
            counter.set_terminate()
            break
        elif rc == 2:
            continue
        else:
            print("\nrc:" + str(rc) + " command: " + shellcommands)

    counter.increment(intvl_count)
    counter.dec_proc_count();


if __name__ == "__main__":
    counter = Counter()
    k_perms = list(itertools.permutations(N, k))
    k_perms_size = len(k_perms)
    counter.set_total(k_perms_size)

    print("\nk-permutations of n: n!/(n-k)!, n=" + str(len(N))
          + ", k=" + str(k)
          + ", k-n-permutations:" + str(counter.get_total()))

    monitorObj = multiprocessing.Process(target=monitor, args=(counter,))
    monitorObj.start()

    first = 0
    chunk = k_perms_size / procs
    rem = k_perms_size % procs
    last = chunk

    spawned = []
    for i in range(procs):
        workerObj = multiprocessing.Process(target=worker,
                                            args=(k_perms, first, last, counter))
        first = last
        if(rem):
            last += chunk + 1
            rem -= 1
        else:
            last += chunk

        workerObj.start()
        spawned.append(workerObj)
        time.sleep(2.7)

    for workerObj in spawned:
        workerObj.join()

    monitorObj.join()
    print("\nProcesses joined. Exiting.")
    sys.exit()
