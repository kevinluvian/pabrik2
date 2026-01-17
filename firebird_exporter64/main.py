import fdb
import time
from flask import Flask, request, Response, abort, jsonify
from flask_httpauth import HTTPBasicAuth
from prometheus_client import Gauge, generate_latest

app = Flask(__name__)
auth = HTTPBasicAuth()

# Define the Prometheus metric
product_stock = Gauge('product_stock', 'Stock of product ever sold from SPJ to FCC', ['product_code', 'product_name', 'product_unit'])

# Sample credentials (in production, use environment variables or a secure store)
users = {
    "kevinfirebirdexporter": "kevinfirebirdexporter123"  # username: password
}

@auth.verify_password
def verify_password(username, password):
    if users.get(username) == password:
        return username
    return None

@app.route('/custom', methods=['POST'])
@auth.login_required
def custom():
    data = request.json
    if 'query' not in data:
        return abort(404)
    query = data['query']
    if 'SELECT' not in query:
        return abort(404)
    types = data['types']
    fields = data['fields']

    # Connect to your database and fetch the row count
    # 100.101.51.40 is the tailscale ip of the harmoni server which hosts the DB.
    connection = fdb.connect(database='100.101.51.40/3050:D:\App\GLSJ\Db\GLSJ.FDB', user='SYSDBA', password='masterkey', charset='ISO8859_1')
    cur = connection.cursor()
    cur.execute(query)
    result = []
    for row in cur.fetchall():
        row_result = {}
        for idx, col in enumerate(row):
            col_result = col
            if types[idx] == 'str':
                col_result = str(col_result).strip()
            if types[idx] == 'str_upper':
                col_result = str(col_result).strip().upper()
            if types[idx] == 'str_lower':
                col_result = str(col_result).strip().lower()
            if types[idx] == 'int':
                col_result = int(col_result)
            if types[idx] == 'float':
                col_result = float(col_result)
            if types[idx] == 'timestamp':
                col_result = time.mktime(col_result.timetuple())
            row_result[fields[idx]] = col_result
        result.append(row_result)
    return jsonify(result)


@app.route('/metrics')
@auth.login_required
def metrics():
    # Connect to your database and fetch the row count
    # 100.101.51.40 is the tailscale ip of the harmoni server which hosts the DB.
    connection = fdb.connect(database='100.101.51.40/3050:D:\App\GLSJ\Db\GLSJ.FDB', user='SYSDBA', password='masterkey', charset='ISO8859_1')
    cur = connection.cursor()
    cur.execute("""SELECT 
     export.F_PROCODE,
     p.F_PRONAME,
     p.F_UNIT,
     (sum(s.F_BEGBAL)  +
		(sum(s.F_SR01) + sum(s.F_SR02) + sum(s.F_SR03) + sum(s.F_SR04) + sum(s.F_SR05) + sum(s.F_SR06) + sum(s.F_SR07) + sum(s.F_SR08) + sum(s.F_SR09) + sum(s.F_SR10) + sum(s.F_SR11) + sum(s.F_SR12)) +
		(sum(s.F_PL01) + sum(s.F_PL02) + sum(s.F_PL03) + sum(s.F_PL04) + sum(s.F_PL05) + sum(s.F_PL06) + sum(s.F_PL07) + sum(s.F_PL08) + sum(s.F_PL09) + sum(s.F_PL10) + sum(s.F_PL11) + sum(s.F_PL12)) +
		(sum(s.F_IN01) + sum(s.F_IN02) + sum(s.F_IN03) + sum(s.F_IN04) + sum(s.F_IN05) + sum(s.F_IN06) + sum(s.F_IN07) + sum(s.F_IN08) + sum(s.F_IN09) + sum(s.F_IN10) + sum(s.F_IN11) + sum(s.F_IN12)) - 
		(sum(s.F_PR01) + sum(s.F_PR02) + sum(s.F_PR03) + sum(s.F_PR04) + sum(s.F_PR05) + sum(s.F_PR06) + sum(s.F_PR07) + sum(s.F_PR08) + sum(s.F_PR09) + sum(s.F_PR10) + sum(s.F_PR11) + sum(s.F_PR12)) -
		(sum(s.F_OUT01) + sum(s.F_OUT02) + sum(s.F_OUT03) + sum(s.F_OUT04) + sum(s.F_OUT05) + sum(s.F_OUT06) + sum(s.F_OUT07) + sum(s.F_OUT08) + sum(s.F_OUT09) + sum(s.F_OUT10) + sum(s.F_OUT11) + sum(s.F_OUT12))) AS CurrentStock
 FROM (
     SELECT
         bpbd.F_PROCODE
     FROM
         BPBH bpbh
     INNER JOIN BPBD bpbd ON bpbh.F_BPBNO = bpbd.F_BPBNO
     WHERE
         bpbh.F_SUPCODE = 'S0016'
     GROUP BY bpbd.F_PROCODE) as export
 INNER JOIN PRODUCT p ON export.F_PROCODE = p.F_PROCODE
 INNER JOIN STOC s ON p.F_PROCODE = s.F_PROCODE
 WHERE s.F_YEAR >= 2024
 GROUP BY p.F_PROCODE, p.F_UNIT, p.F_PRONAME, export.F_PROCODE, s.F_YEAR;""")
    for row in cur.fetchall():
        product_id, product_name, product_unit, current_stock = row
        current_stock = float(current_stock)
        product_stock.labels(product_id.strip().upper(), product_name.strip().upper(), product_unit.strip().upper()).set(current_stock)

    # Return the metrics in the Prometheus format
    return Response(generate_latest(product_stock), content_type="text/plain")

@app.route('/')
def home():
    return Response()

if __name__ == '__main__':
    from waitress import serve
    # Start the Flask app with authentication
    serve(app, host="0.0.0.0", port=8000)
