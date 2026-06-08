import matplotlib.pyplot as plt
from collections import Counter

# Example simulated data
ips = ["192.168.1.10", "192.168.1.10", "10.0.0.8", "172.16.0.5", "172.16.0.5"]

count = Counter(ips)

plt.bar(count.keys(), count.values())
plt.title("Suspicious IP Activity Dashboard")
plt.xlabel("IP Address")
plt.ylabel("Event Count")

plt.show()