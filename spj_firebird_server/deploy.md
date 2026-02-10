VERSION=$(date +%Y%m%d%H%M%S)
docker build --platform=linux/amd64 -t warehouse.skleem.co/spj_firebird_server:$VERSION -t warehouse.skleem.co/spj_firebird_server:latest .

docker push warehouse.skleem.co/spj_firebird_server:latest
