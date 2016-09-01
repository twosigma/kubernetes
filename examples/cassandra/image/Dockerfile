# Copyright 2016 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM google/debian:jessie

COPY cassandra.list /etc/apt/sources.list.d/cassandra.list
COPY run.sh /run.sh
COPY cassandra.yaml /cassandra.yaml
COPY logback.xml /logback.xml
COPY kubernetes-cassandra.jar /kubernetes-cassandra.jar
COPY oracle-java8-jdk_8u101_amd64.deb /

RUN gpg --keyserver pgp.mit.edu --recv-keys F758CE318D77295D && \
  gpg --export --armor F758CE318D77295D | apt-key add - && \
  gpg --keyserver pgp.mit.edu --recv-keys 2B5C1B00 && \
  gpg --export --armor 2B5C1B00 | apt-key add - && \
  gpg --keyserver pgp.mit.edu --recv-keys 0353B12C && \
  gpg --export --armor 0353B12C | apt-key add - && \
  apt-get update && \
  apt-get install curl -y --force-yes && \
  echo "deb http://debian.datastax.com/community stable main" | tee -a /etc/apt/sources.list.d/cassandra.sources.list && \
  perl -pi -e 's/jessie main/jessie main contrib non-free/' /etc/apt/sources.list && \
  curl -L https://debian.datastax.com/debian/repo_key | apt-key add - && \
  apt-get update && \
  apt-get install java-package -y --force-yes && \
  apt-get install libgl1-mesa-glx libgtk2.0-0 libxslt1.1 libxtst6 libxxf86vm1 -y --force-yes && \
  dpkg -i /oracle-java8-jdk_8u101_amd64.deb && \
  apt-get -qq -y install procps cassandra=2.1.13 dsc21=2.1.13-1 cassandra-tools=2.1.13 && \
  apt-get purge java-package -y && \
  apt-get clean -y && \
  chmod a+rx /run.sh && \
  mkdir -p /cassandra_data/data && \
  mkdir -p /agent && \
  cd /agent && \
  curl -L http://downloads.datastax.com/community/datastax-agent-5.2.4.tar.gz | tar xz && \
  chown -R cassandra: /agent && \
  mv /logback.xml /etc/cassandra/ && \
  mv /cassandra.yaml /etc/cassandra/ && \
  chown -R cassandra: /etc/cassandra /cassandra_data /run.sh \
    /kubernetes-cassandra.jar && \
  chmod o+w -R /etc/cassandra /cassandra_data && \
  rm -rf \
        doc \
        man \
        info \
        locale \
        /var/lib/apt/lists/* \
        /var/log/* \
        /var/cache/debconf/* \
        common-licenses \
        ~/.bashrc \
        /etc/systemd \
        /lib/lsb \
        /lib/udev \
        /usr/share/doc/ \
        /usr/share/doc-base/ \
        /usr/share/man/ \
        /tmp/*


VOLUME ["/cassandra_data/data"]

# 7000: intra-node communication
# 7001: TLS intra-node communication
# 7199: JMX
# 9042: CQL
# 9160: thrift service not included cause it is going away
EXPOSE 7000 7001 7199 9042

USER cassandra

CMD /run.sh
