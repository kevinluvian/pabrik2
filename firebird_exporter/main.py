import fdb
from flask import Flask, Response
from flask_httpauth import HTTPBasicAuth
from prometheus_client import Gauge, generate_latest

app = Flask(__name__)
auth = HTTPBasicAuth()

# Define the Prometheus metric
product_stock = Gauge('product_stock', 'Stock of product ever sold from SPJ to FCC', ['product_code', 'product_name', 'product_unit'])

# Sample credentials (in production, use environment variables or a secure store)
users = {
    "admin": "password123"  # username: password
}

@auth.verify_password
def verify_password(username, password):
    if users.get(username) == password:
        return username
    return None

@app.route('/metrics')
@auth.login_required
def metrics():
    # Connect to your database and fetch the row count
    connection = fdb.connect(database='/home/app/GLSJ.FDB', user='SYSDBA', password='SUPER', charset='ISO8859_1')
    cur = connection.cursor()
    cur.execute("""SELECT 
     export.F_PROCODE,
     p.F_PRONAME,
     p.F_UNIT,
     sum(s.F_BEGBAL) + (sum(s.F_IN01) + sum(s.F_IN02) + sum(s.F_IN03) + sum(s.F_IN04) + sum(s.F_IN05) + sum(s.F_IN06) + sum(s.F_IN07) + sum(s.F_IN08) + sum(s.F_IN09) + sum(s.F_IN10) + sum(s.F_IN11) + sum(s.F_IN12)) - (sum(s.F_OUT01) + sum(s.F_OUT02) + sum(s.F_OUT03) + sum(s.F_OUT04) + sum(s.F_OUT05) + sum(s.F_OUT06) + sum(s.F_OUT07) + sum(s.F_OUT08) + sum(s.F_OUT09) + sum(s.F_OUT10) + sum(s.F_OUT11) + sum(s.F_OUT12)) AS CurrentStock
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
 WHERE s.F_YEAR = 2024
 GROUP BY p.F_PROCODE, p.F_UNIT, p.F_PRONAME, export.F_PROCODE, s.F_YEAR;""")
    for row in cur.fetchall():
        product_id, product_name, product_unit, current_stock = row
        current_stock = float(current_stock)
        product_stock.labels(product_id.strip().upper(), product_name.strip().upper(), product_unit.strip().upper()).set(current_stock)

    # Return the metrics in the Prometheus format
    return Response(generate_latest(product_stock), content_type="text/plain")

if __name__ == '__main__':
    # Start the Flask app with authentication
    app.run(host="0.0.0.0", port=8000)
