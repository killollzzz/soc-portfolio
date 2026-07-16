from collections import Counter
import sys

filename = sys.argv[1] if len(sys.argv) > 1 else 'access.log'

ips = []
error_404 = 0
error_500 = 0

with open(filename, 'r') as f:
    lines = f.readlines()
    for line in lines:
        newstroka = line.split()
        ip = newstroka[0]
        ips.append(ip)
        if len(newstroka) >= 8 and newstroka[7] == '404':
            error_404 += 1
        if len(newstroka) >= 8 and newstroka[7] == '500':
            error_500 += 1

popularip = Counter(ips).most_common(5)

print(f"Файл: {filename}")
print("Топ-5 IP по запросам:")
for ip, count in popularip:
    print(f"{ip} — {count} запросов")

print(f"\nОшибок 404: {error_404} из {len(lines)}")
print(f"Ошибок 500: {error_500} из {len(lines)}")
