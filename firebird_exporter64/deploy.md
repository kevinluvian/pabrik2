VERSION=$(date +%Y%m%d%H%M%S)
docker build --platform=linux/amd64 -t warehouse.skleem.co/firebird_exporter64:$VERSION -t warehouse.skleem.co/firebird_exporter64:latest .

docker push warehouse.skleem.co/firebird_exporter64:latest
