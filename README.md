# luks-bruteforce

This project was started to track my efforts in brute-forcing a lost
LUKS passphrase which belongs to a Ceph rbd volume. Because speed 
matters the initial assumption was that running the passphrase test in a 
multithreaded program will be fast enough. 

The first thing to do was to extract the LUKS header from the rbd volume. 
The header file is just a few MB of size and therefore easy to copy to 
the servers running the brute-force.

Rbd map the volume, which resides in the 'volumes' pool in Ceph storage:

	sudo rbd map volumes/volume-<id>

This returns with the volume mapped to /dev/rbd0. 
Then extract the header from the rbd volume:

	sudo cryptsetup luksHeaderBackup --header-backup-file $HOME/backup-header /dev/rbd0



### Permutation

In the given case some basic assumption exists about the characteristics 
of the searched passphrase. For example, the format, characters and no element 
occurs more than once, but without the requirement of using all the elements 
from a given set. Because of this I decided to use the k-permutations of n 
algorithm [1].

In Python, itertools.permutations implements a k-n-permutation. I want to use 
the cryptsetup C API directly. In C++ the standard library offers full permutations 
of a range with std::next_permutation, but not k-n permutations. After some more 
reading in [2][3][4][5] I decided to try a reference implementation of k-n permutation 
from [5]. The implementation is building on std::next_permutation.

It should be noted that std::next_permutation is a lexicographic algorithm. A particular 
lexicographic ordering of the input elements is required. Therefore std::sort is used 
to sort the input elements in the range [first, last) in ascending order before calling 
std::next_permutation. The last generated permutation of std::next_permutation is the 
lexicographic minimum of the ascending sorted input. The lexicographic minimum is the 
descending sorted input. To prove it, if you sort the input for std::next_permutation 
in descending order, instead of ascending order, then std::next_permutation returns 
exactly one permutation, which is the lexicographic minimum of the input.

The number of k-n-permutations for the given case are in the area of 10^6. For example, 
with n=28 and k=5 we get 11793600 permutations. Even with n=34 we get 33390720 
permutations which is a problem of small size. The number of k-permutations of n 
is n!/(n-k)!.


### TEST 1

bforce.cpp

The idea was to create a multithreaded program and using the cryptsetup API
(C language) directly to test the header keyslot with a NULL device string,
which effectively implements the cryptsetup --test-passphrase option available
from the cryptsetup shell prompt. Ubuntu 16.04 ships with cryptsetup 1.6.6.
To compile the program it requires to install the cryptsetup headers:

	sudo apt install libcryptsetup-dev

Compiling the program:

	g++ -std=c++11 -Wall -o bforce bforce.cpp -lcryptsetup -lpthread


### RESULTS

Testing on a server with 16 CPU sockets with Hyperthreading enabled and 
using Ubuntu 16.04 (server) with the default kernel settings and the 
program using the scheduler policy SCHED_OTHER.

It shows that the multithreaded program is extremely slow, even with tuning
the CPU affinity of the threads or setting a more aggressive nice value 
for the worker threads. My initial doubts about false sharing of counter 
variables or latency caused by thread migration to CPU on different NUMA 
node were proven not to be the root cause of the slowness of decrypting 
with the passphrase. 

| Test                           |  runtime     |  rate     |
|--------------------------------|--------------|-----------|
|multithreaded (32 threads):     |              |           |   
|default, free floating cpu,     |              |           |
|nice 0                          |  657.20 ms   |   1.52 /s |
|cpu affinity, nice 0            |  636.39 ms   |   1.57 /s |
|cpu affinity, nice -11          |  655.57 ms   |   1.53 /s |


So the results looks like the cryptsetup crypt_activate_by_passphrase() 
runs only in a single thread.



### TEST 2

bforce.py

The next attempt was to use multiple processes instead of threads and
measure the time and rate for one cryptsetup test passphrase attempt.
On the same server and with the default process priority and scheduler.


### RESULT

| Test                          |  runtime     |   rate     |
|-------------------------------|--------------|------------|
|64 processes                   |   24 ms      |   41.51 /s |


Much better. The speed is 27 x faster than with test 1. 
Beyond 32 processes the speedup smoothly decreases to 1 ms with a maximum 
rate at 64 processes.


### TEST 3 
(TODO)

The runtime could be improved by avoiding the process forks from test 2 
by using a pool of threads running in a multiprocesses environment, for
exmple, running 4 threads from within 16 forked processes. The processes
are forked at program init and ensure the threads run on a dedicated CPU 
socket.   


### TEST 4
(TODO)

Determine the multithreading capabilities of dm-crypt. Any kernel config
required to make the passphrase test running multithreaded and not just
on the CPU where the process was forked.




## References

[1] https://en.wikipedia.org/wiki/Permutation

[2] Sedgewick, R. "Permutation Generation Methods", 
    Computer Science and Division of Applied Mathematics, 
    Brown Unwersity, Prowdence, Rhode Island 02912
    
[3] Sedgewick,  R. "Permutation generation methods", 
    Dagstuhl Workshop on Data Structures, Wadern, Germany, February, 2002. 
    https://www.cs.princeton.edu/~rs/talks/perms.pdf
    
[4] https://stackoverflow.com/questions/2211915/combination-and-permutation-in-c/2616837#2616837

[5] Brönnimann, H. "Algorithms for permutations and combinations, with and without repetitions",
    Polytechnic University and Bloomberg L.P., 2008-5-16, WG21/N2639



