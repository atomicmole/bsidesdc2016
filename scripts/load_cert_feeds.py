# Copyright (c) 2016, Atomic Mole LLC
# All rights reserved.
#
# Load the SSLBL certificate feeds into an Amazon Resshift database via an S3 copy.  This creates
#   the relevant table in Redshift if it does not already exist.
import boto3
import configparser
import datetime
import psycopg2
import urllib2

def download_sslbl(bucket_name):
    s3 = boto3.resource('s3')
    req = urllib2.urlopen('https://sslbl.abuse.ch/blacklist/sslblacklist.csv', timeout=30)
    response = req.read()
    output = ''
    ignore = True
    for line in response.splitlines():
        if line.startswith('#'):
            continue
        fields = line.strip().split(',')
        if len(fields) > 2:
            record_time = datetime.datetime.strptime(fields[0], '%Y-%m-%d %H:%M:%S')
            output += fields[0] + ',' + fields[1] + ',' + fields[2] + ',abuse.ch SSL Fingerprint Blacklist\n'
    s3_filename = 'sslbl.csv'
    s3.Object(bucket_name, s3_filename).put(Body=output.encode())
    return 's3://' + bucket_name + '/' + s3_filename
    
def download_dyressl(bucket_name):
    s3 = boto3.resource('s3')
    req = urllib2.urlopen('https://sslbl.abuse.ch/blacklist/dyre_sslblacklist.csv', timeout=60)
    response = req.read()
    output = ''
    ignore = True
    for line in response.splitlines():
        if line.startswith('#'):
            continue
        fields = line.strip().split(',')
        if len(fields) > 2:
            record_time = datetime.datetime.strptime(fields[0], '%Y-%m-%d %H:%M:%S')
            output += fields[0] + ',' + fields[1] + ',' + fields[2] + ',abuse.ch Dyre C2 SSL Fingerprint Blacklist\n'
    s3_filename = 'dyressl.csv'
    s3.Object(bucket_name, s3_filename).put(Body=output.encode())
    return 's3://' + bucket_name + '/' + s3_filename

def redshift_connect(settings):
    REDSHIFT_HOSTNAME = settings.get('Redshift', 'REDSHIFT_HOSTNAME')
    REDSHIFT_DATABASE = settings.get('Redshift', 'REDSHIFT_DATABASE')
    REDSHIFT_USER     = settings.get('Redshift', 'REDSHIFT_USER')
    REDSHIFT_PASSWORD = settings.get('Redshift', 'REDSHIFT_PASSWORD')
    
    conn_string = 'dbname=\'' + REDSHIFT_DATABASE + '\' port=\'5439\' user=\'' + REDSHIFT_USER + '\''
    conn_string += ' password=\'' + REDSHIFT_PASSWORD + '\'' + ' host=\'' + REDSHIFT_HOSTNAME + '\''
    conn_string += ' connect_timeout=20 sslmode=require'
    return psycopg2.connect(conn_string)

def load_file_from_s3(s3_uri, db_conn, settings):
    COPY_AWS_ACCESS_KEY_ID = settings.get('Copy', 'COPY_AWS_ACCESS_KEY_ID')
    COPY_AWS_SECRET_KEY    = settings.get('Copy', 'COPY_AWS_SECRET_KEY')
    
    cursor = db_conn.cursor()
    copy_query = 'COPY feed_certs_new FROM \'' + s3_uri + '\''
    copy_query += ' credentials \'aws_access_key_id=' + COPY_AWS_ACCESS_KEY_ID
    copy_query += ';aws_secret_access_key=' + COPY_AWS_SECRET_KEY + '\''
    copy_query += ' delimiter \',\' DATEFORMAT \'auto\''
    cursor.execute(copy_query)
    print(s3_uri + ' loaded')

settings = configparser.RawConfigParser()
settings.read('settings.ini')
S3_BUCKET_NAME = settings.get('S3', 'S3_BUCKET_NAME')

feed_uris = []
feed_uris.append(download_sslbl(S3_BUCKET_NAME))
feed_uris.append(download_dyressl(S3_BUCKET_NAME))

db_conn = redshift_connect(settings)

# Create a new temporary table
cursor = db_conn.cursor()
query = 'CREATE TABLE feed_certs_new (ts TIMESTAMP NOT NULL, sha1 CHAR(40) DISTKEY SORTKEY,'
query += ' description VARCHAR(255), source VARCHAR(64))'
cursor.execute(query)

for uri in feed_uris:
    load_file_from_s3(uri, db_conn)
    
# Use query order suggested here: 
#   https://www.simple.com/engineering/safe-migrations-with-redshift
query = 'ALTER TABLE feed_certs RENAME TO feed_certs_old;'
query += 'ALTER TABLE feed_certs_new RENAME TO feed_certs;'
query += 'DROP TABLE feed_certs_old;'
cursor.execute(query)

db_conn.commit()
db_conn.close()
