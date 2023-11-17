FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3.6 python3-pip python3-setuptools python3-dev default-libmysqlclient-dev libgtk2.0-dev libgtk-3-dev libjpeg-dev libtiff-dev libsdl1.2-dev libgstreamer-plugins-base1.0-dev mysql-server libc-dev musl-dev

ENV http_proxy=
ENV https_proxy=
WORKDIR /app
COPY req.txt /app/requirements.txt
RUN pip3 install -r requirements.txt
COPY . /app
ENV PYTHONPATH "${PYTHONPATH}:/app"
EXPOSE 4040
ENTRYPOINT ["python3"]
CMD ["-u","app.py"]
