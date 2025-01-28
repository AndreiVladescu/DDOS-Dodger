import requests
import time
from concurrent.futures import ThreadPoolExecutor

URL = "http://192.168.0.90"  # Replace with your ESP8266 server's URL
TOTAL_REQUESTS = 100         # Number of requests per test run
CONCURRENT_THREADS = 10      # Number of concurrent threads
TIMEOUT = 5                  # Request timeout in seconds
REPEAT_TESTS = 100           # Number of times to repeat the test

def send_request(_):
    start_time = time.time()
    try:
        response = requests.get(URL, timeout=TIMEOUT)
        response_time = time.time() - start_time
        if response.status_code == 200:
            return response_time, True
        else:
            return response_time, False
    except requests.exceptions.RequestException:
        return None, False

def run_single_test():
    response_times = []
    successes = 0
    failures = 0

    with ThreadPoolExecutor(max_workers=CONCURRENT_THREADS) as executor:
        results = list(executor.map(send_request, range(TOTAL_REQUESTS)))

    for response_time, success in results:
        if success:
            successes += 1
            response_times.append(response_time)
        else:
            failures += 1

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    max_response_time = max(response_times, default=0)
    min_response_time = min(response_times, default=0)

    return successes, failures, avg_response_time, max_response_time, min_response_time

def main():
    total_successes = 0
    total_failures = 0
    avg_response_times = []
    max_response_times = []
    min_response_times = []

    print(f"Starting benchmark on {URL} with {CONCURRENT_THREADS} threads, {TOTAL_REQUESTS} requests per run, repeated {REPEAT_TESTS} times.")

    for i in range(REPEAT_TESTS):
        successes, failures, avg_response_time, max_response_time, min_response_time = run_single_test()
        total_successes += successes
        total_failures += failures
        avg_response_times.append(avg_response_time)
        max_response_times.append(max_response_time)
        min_response_times.append(min_response_time)

        print(f"Run {i + 1}/{REPEAT_TESTS} completed: {successes} successes, {failures} failures, Avg response time: {avg_response_time:.3f} seconds")

    overall_avg_response_time = sum(avg_response_times) / len(avg_response_times)
    overall_max_response_time = max(max_response_times)
    overall_min_response_time = min(min_response_times)
    total_requests = REPEAT_TESTS * TOTAL_REQUESTS

    print("\nFinal Results:")
    print(f"Total Requests Sent: {total_requests}")
    print(f"Total Successful Requests: {total_successes}")
    print(f"Total Failed Requests: {total_failures}")
    print(f"Overall Success Rate: {total_successes / total_requests * 100:.3f}%")
    print(f"Overall Failure Rate: {total_failures / total_requests * 100:.3f}%")
    print(f"Overall Average Response Time: {overall_avg_response_time:.3f} seconds")
    print(f"Overall Maximum Response Time: {overall_max_response_time:.3f} seconds")
    print(f"Overall Minimum Response Time: {overall_min_response_time:.3f} seconds")

if __name__ == "__main__":
    main()
