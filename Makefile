.PHONY: *

gogo: stop-services build truncate-logs start-services bench

stop-services:
	sudo systemctl stop nginx
	sudo systemctl stop isuda.go.service
	sudo systemctl stop mysql.service

build:
	cd go/ && make

truncate-logs:
	sudo truncate --size 0 /var/log/nginx/access.log
	sudo truncate --size 0 /var/log/nginx/error.log
	sudo truncate --size 0 /var/log/mysql/mysql-slow.log && sudo chmod 666 /var/log/mysql/mysql-slow.log
	sudo truncate --size 0 /var/log/mysql/error.log

start-services:
	sudo systemctl start mysql.service
	sudo systemctl start isuda.go.service
	sudo systemctl start nginx

kataribe: timestamp=$(date "+%Y%m%d-%H%M%S")
kataribe:
	mkdir -p ~/kataribe-logs
	sudo cp /var/log/nginx/access.log /tmp/last-access.log && sudo chmod 666 /tmp/last-access.log
	cat /tmp/last-access.log | ./kataribe -conf kataribe.toml > ~/kataribe-logs/$timestamp.log
	cat ~/kataribe-logs/$timestamp.log

bench:
	cd ../isucon6q/ && ./isucon6q-bench
