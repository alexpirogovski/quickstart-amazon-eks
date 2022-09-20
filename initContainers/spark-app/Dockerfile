FROM apache/spark-py:v3.2.1
USER root
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN apt-get update && apt-get -y install wget git
WORKDIR  /hadoop
RUN wget https://archive.apache.org/dist/hadoop/common/hadoop-3.3.1/hadoop-3.3.1.tar.gz
RUN tar --strip=5 -xf  hadoop-3.3.1.tar.gz hadoop-3.3.1/share/hadoop/tools/lib
RUN mv *.jar /opt/spark/jars/
WORKDIR /
RUN rm -rf /hadoop
