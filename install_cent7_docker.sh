
yum -y update
yum -y install vim* sysstat
echo "export HISTTIMEFORMAT=\"%F %T \"" >> /etc/profile.d/history.sh
source /etc/profile.d/history.sh


# docker install
curl -fsSL https://get.docker.com/ | sudo sh

systemctl start docker.service
systemctl enable docker.service
systemctl status docker.service
docker version


# docker pull apache/zeppelin
docker pull apache/zeppelin:0.8.2

mkdir -p logs
mkdir -p notebook

# docker run -p 8080:8080 --rm --name zeppelin apache/zeppelin:0.8.2
docker run -p 8080:8080 --rm -v $PWD/logs:/logs -v $PWD/notebook:/notebook -e ZEPPELIN_LOG_DIR=’/logs’ -e ZEPPELIN_NOTEBOOK_DIR=’/notebook’ --name zeppelin apache/zeppelin:0.8.2
