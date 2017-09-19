//-------------------------------------------------------------------
// 
// Brute-force a LUKS block-device header.
// 
// This program runs a pool of threads to test the LUKS header with
// all permutations of N. Uses k-n-permutation (also called 
// variation-k of n). The number of items returned is n! / (n-k)!
//
// g++ -std=c++11 -Wall -o bforce bforce.cpp -lcryptsetup -lpthread
//
// Sep 2017, Timo Koehler
//-------------------------------------------------------------------
#include <algorithm>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <iterator>
#include <locale>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <cstddef>
extern "C" {
#include "libcryptsetup.h"
}

std::mutex print_mutex;
std::atomic<bool> worker_terminate(false);
std::atomic_ullong luks_done(0);
std::atomic_ullong k_perms_count(0);
std::atomic_int thread_count(0);
typedef std::chrono::high_resolution_clock Clock;
typedef std::chrono::duration<double> sec;
typedef std::chrono::duration<double, std::nano> ns;
typedef std::chrono::duration<double, std::milli> ms;
bool test_flag;

//
// This template function implements a k-n-permutation algorithm 
// without repetition from this proposal document at:
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2008/n2639.pdf
//
// This algorithm is based on std::next_permutation and requires
// the input range [first,last) in reverse lexicographic order
// with sort(first,last). The original (input) sequence has no 
// duplicate values.
//
template <class BidirectionalIterator>
bool next_partial_permutation(BidirectionalIterator first,
                              BidirectionalIterator middle,
                              BidirectionalIterator last) {
  std::reverse(middle, last);
  return std::next_permutation(first, last);
}

//
// Helper function to test if the LUKS header can be loaded. 
//
int load_luks_header_test(const char* path) {
  struct crypt_device *cd;
  int rc;

  rc = crypt_init(&cd, path);
  if (rc < 0 ) {
    std::cout << "crypt_init() failed for " << path
              << ". rc: " << rc
              << ". Check path or permissions." << std::endl;
    return rc;
  }

  rc = crypt_load(cd, CRYPT_LUKS1, nullptr);
  if (rc < 0) {
    std::cout << "crypt_load() failed on device "
              << crypt_get_device_name(cd)
              << ". rc: " << rc
              << std::endl;
    crypt_free(cd);
    return rc;
  }
  return 0;
}

//
// This thread counts the number of attempts and gives an
// estimate of time until all items in N have been tested.
//
void monitor_thread(void) {
  unsigned long long int count, n;
  float rate_s;
  int percent, x, est_d, est_h, est_m, upd_sec = 4;
  Clock::time_point t0;
  ms rate_ms;

  /*
    std::thread::id this_id = std::this_thread::get_id();
    print_mutex.lock();
    std::cout << "Monitor tid " << this_id << " is executing" << std::endl;
    print_mutex.unlock();
  */

  while (true) {
    if (worker_terminate)
      break;

    count = luks_done.load();
    n = k_perms_count.load();

    if (count == 0) {
      percent = rate_s = x = est_d = est_h = est_m = 0;
      t0 = Clock::now();
    } else {
      sec elapsed_time = Clock::now() - t0;
      rate_s = count / elapsed_time.count();
      rate_ms = elapsed_time / count;
      x = (n - count) / rate_s;
      est_d = static_cast<unsigned int>(x / 86400LL);
      est_h = static_cast<unsigned int>((x % 86400LL) / 3600U);
      est_m = static_cast<unsigned int>((x % 3600LL) / 60U);
      percent = static_cast<int>((count * 100) / n);
    }

    print_mutex.lock();
    std::cout << "\r[ threads:"
              << thread_count.load() << ", "
              << count << "/" << n << ", "
              << percent << "%, "
              << rate_ms.count() << " ms, "
              << std::fixed << std::setprecision(2)
              << rate_s << " /s, estimate remaining time: "
              << est_d << "d" << est_h << "h" << est_m << "m"
              << " ]";
    std::cout.flush();
    print_mutex.unlock();

    if (percent == 100)
      break;

    std::this_thread::sleep_for(std::chrono::seconds(upd_sec));
  }
}

//
// The worker thread function. It uses the cryptsetup API to test the
// header keyslot with the passphrase.
//
template<class ConstIterator, class ConstChar>
void worker(ConstIterator first, ConstIterator last, ConstChar path) {
  ConstIterator iter = first;
  struct crypt_device *cd;
  std::string::iterator it;
  std::istringstream ss;
  std::ostringstream oss;
  std::vector<std::string> word;
  int batch_upd = 10;
  int rc;

  /*
    std::thread::id this_id = std::this_thread::get_id();
    print_mutex.lock();
    std::cout << "Worker tid " << this_id << " is executing. Items: "
              << std::distance(iter, last) << std::endl;
    print_mutex.unlock();
  */

  crypt_init(&cd, path);
  crypt_load(cd, CRYPT_LUKS1, nullptr);

  ++thread_count;
  int intvl_count = 0;
  while (iter != last) {
    if (worker_terminate)
      break;

    ++intvl_count;
    if (intvl_count % batch_upd == 0) {
      luks_done += intvl_count;
      intvl_count = 0;
    }

    ss.str(*iter);
    word = {std::istream_iterator<std::string>(ss), {}};

    //
    // Some additional string manipulation of the passphrase.
    //
    if (test_flag) {
      it = (word.begin())->begin();
      *it = std::toupper(*it, std::locale());
    } else {
      it = (word.begin())->begin();
      *it = std::toupper(*it, std::locale());
      it = (word.end() - 1)->end() - 1;
      *it = std::toupper(*it, std::locale());
    }

    std::copy(word.begin(), word.end() - 1, std::ostream_iterator<std::string>(oss, " "));
    oss << word.back();
    rc = crypt_activate_by_passphrase(cd,
                                      nullptr,
                                      0, //CRYPT_ANY_SLOT or show with: "cryptsetup luksDump <header>" 
                                      oss.str().c_str(),
                                      oss.str().size(),
                                      CRYPT_ACTIVATE_READONLY);
    if (rc >= 0) {
      print_mutex.lock();
      std::cout << "\n\nFound: " << oss.str() << "\n";
      std::cout.flush();
      print_mutex.unlock();
      worker_terminate.exchange(true);
    }

    ss.str("");
    ss.clear();
    word.clear();
    oss.str("");
    oss.clear();
    ++iter;
  }
  crypt_free(cd);
  luks_done += intvl_count;
  --thread_count;
}

//
// The main thread of the program uses a string vector N and the LUKS
// header file at the given path variable in order to test the generated 
// passphrases. N, path and create_threads must be edited to meet the 
// actual environment.
//
int main(int argc, const char * argv[]) {
  test_flag = true;
  int k, create_threads;
  const char* path;
  std::vector<std::thread> workerObj;
  std::vector<std::string> N, k_perms;
  std::vector<std::string>::const_iterator first, last;
  std::string p;

  if (test_flag) {
    N = {"tree", "lemon", "green", "blue", "skye", "red", "test"};
    k = 4;
    path = "./save-header";
    create_threads = 4;
  } else {
    N = {"tree", "lemon", "green", "blue", "sky", "water", "deep", "tracks", \
         "hot", "summer", "red", "stone", "orange", "fruit", "air", "fun", \
         "sun", "nice", "big", "rocks", "cool", "small", "work", "works", \
         "working", "bad", "is", "dark"
        };
    k = 5;
    path = "./backup-header";
    create_threads = 64;
  }

  int rc = load_luks_header_test(path);
  if (rc) {
    std::cout << "Loading LUKS header at " << path << " failed." << std::endl;
    return 1;
  }

  std::sort(N.begin(), N.end());
  Clock::time_point t0 = Clock::now();

  do {
    p.append(N[0]);
    for (int j = 1; j < k; ++j) {
      p.append(" ");
      p.append(N[j]);
    }
    k_perms.push_back(p);
    p.clear();
  } while (next_partial_permutation(N.begin(), N.begin() + k, N.end()));

  k_perms_count = k_perms.size();
  unsigned long long int _k_perms_count = k_perms_count.load();

  Clock::time_point t1 = Clock::now();
  sec s0 = t1 - t0;
  ns ss0 = s0 / _k_perms_count;

  print_mutex.lock();
  std::cout << "\nk-permutations of n: n!/(n-k)!, n=" << N.size()
            << ", k=" << k
            << ", k-n-permutations:" << _k_perms_count << std::endl;
  std::cout << "Total time:" << s0.count()
            << " s, per cycle:" << ss0.count() << " ns"
            << std::endl;
  print_mutex.unlock();

  std::thread monitorObj(&monitor_thread);

  unsigned long long int chunk = _k_perms_count / create_threads;
  unsigned long long int rem = _k_perms_count % create_threads;
  first = k_perms.begin();
  last = first + chunk;

  for (int i = 1; i <= create_threads; ++i) {
    workerObj.push_back(std::thread(&worker<std::vector<std::string>::const_iterator,
                                    const char*>,
                                    first,
                                    last,
                                    path));
    first = last;
    if (rem) {
      last += chunk + 1;
      --rem;
    } else {
      last += chunk;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2777));
  }

  for (auto& th : workerObj) {
    th.join();
  }

  monitorObj.join();
  std::cout << "\nThreads joined. Exiting." << std::endl;

  return 0;
}
