cp conf/haproxy.service /lib/systemd/system/
cp haproxy-systemd-wrapper /usr/local/sbin/
systemctl daemon-reload

