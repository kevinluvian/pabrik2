from warehouse.skleem.co/firebird_reader_base

RUN apt-get update && apt-get install -y \
python3 \
python3-pip \
python3-dev \
libpq-dev \
&& rm -rf /var/lib/apt/lists/*

COPY . /home/app

WORKDIR /home/app

RUN pip3 install -r requirements.txt

EXPOSE 8001

ENTRYPOINT ["/home/app/start.sh"]
