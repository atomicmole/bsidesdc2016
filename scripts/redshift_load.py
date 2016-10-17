# Copyright (c) 2016, Atomic Mole LLC
# All rights reserved.
#
# Load a preprocessed metadata file from Amazon S3 into a Redshift database specified by a config
#   file.  This script creates the database table nessecary if it does not already exist.
import boto3
import configparser
import psycopg2
    
def redshift_connect(settings):
    REDSHIFT_HOSTNAME = settings.get('Redshift', 'REDSHIFT_HOSTNAME')
    REDSHIFT_DATABASE = settings.get('Redshift', 'REDSHIFT_DATABASE')
    REDSHIFT_USER     = settings.get('Redshift', 'REDSHIFT_USER')
    REDSHIFT_PASSWORD = settings.get('Redshift', 'REDSHIFT_PASSWORD')
    
    conn_string = 'dbname=\'' + REDSHIFT_DATABASE + '\' port=\'5439\' user=\'' + REDSHIFT_USER + '\''
    conn_string += ' password=\'' + REDSHIFT_PASSWORD + '\'' + ' host=\'' + REDSHIFT_HOSTNAME + '\''
    conn_string += ' connect_timeout=20 sslmode=require'
    return psycopg2.connect(conn_string)

def create_cert_table(db_conn):
    cursor = db_conn.cursor()
    query = 'CREATE TABLE IF NOT EXISTS cert_metadata(date DATE, sha1 CHAR(40) DISTKEY,'
    query += ' version VARCHAR(16), serial_number VARCHAR(255),'
    query += ' subject VARCHAR(8192), subject_c VARCHAR(2048), subject_cn VARCHAR(2048),'
    query += ' subject_l VARCHAR(2048), subject_o VARCHAR(2048), subject_ou VARCHAR(2048),'
    query += ' subject_st VARCHAR(2048), subject_emailaddress VARCHAR(2048),'
    query += ' subject_unstructuredname VARCHAR(2048), subject_serialnumber VARCHAR(2048),'
    # Same data fields as above, but subject -> issuer
    query += ' issuer VARCHAR(8192), issuer_c VARCHAR(2048), issuer_cn VARCHAR(2048),'
    query += ' issuer_l VARCHAR(2048), issuer_o VARCHAR(2048), issuer_ou VARCHAR(2048),'
    query += ' issuer_st VARCHAR(2048), issuer_emailaddress VARCHAR(2048),'
    query += ' issuer_unstructuredname VARCHAR(2048), issuer_serialnumber VARCHAR(2048),'
    
    query += ' not_valid_before TIMESTAMP, not_valid_before_raw VARCHAR(255),'
    query += ' not_valid_after TIMESTAMP, not_valid_after_raw VARCHAR(255),'
    query += ' duration BIGINT, key_algorithm VARCHAR(255), sig_algorithm VARCHAR(255),'
    query += ' key_type VARCHAR(255), key_length INT, exponent BIGINT, curve VARCHAR(255),'
    query += ' size INT, self_signed BOOLEAN, feed_match BOOLEAN);'
    cursor.execute(query)

def load_file_from_s3(s3_uri, db_conn, settings):
    COPY_AWS_ACCESS_KEY_ID = settings.get('Copy', 'COPY_AWS_ACCESS_KEY_ID')
    COPY_AWS_SECRET_KEY    = settings.get('Copy', 'COPY_AWS_SECRET_KEY')
    
    cursor = db_conn.cursor()
    copy_query = 'COPY cert_metadata FROM \'' + s3_uri + '\''
    copy_query += ' credentials \'aws_access_key_id=' + COPY_AWS_ACCESS_KEY_ID
    copy_query += ';aws_secret_access_key=' + COPY_AWS_SECRET_KEY + '\''
    copy_query += ' delimiter \'|\' DATEFORMAT AS \'YYYYMMDD\' TIMEFORMAT AS \'epochsecs\''
    copy_query += ' NULL AS \'-\' IGNOREHEADER 1 REMOVEQUOTES ESCAPE TRUNCATECOLUMNS'
    cursor.execute(copy_query)
    print(s3_uri + ' loaded')

# Read in our configuration file
settings = configparser.RawConfigParser()
settings.read('settings.ini')

db_conn = redshift_connect(settings)
# Make sure our table is in place
create_cert_table(db_conn)

s3 = boto3.client('s3')
S3_BUCKET_NAME = settings.get('S3', 'S3_BUCKET_NAME')

# NOTE: If you get an error on the line below that looks like thew following:
#     AttributeError: 'S3' object has no attribute 'list_objects_v2'
#   make sure you have the latest boto3 and botocore python packages installed 
response = s3.list_objects_v2(Bucket=S3_BUCKET_NAME)
if 'Contents' not in response:
    print('No objects found to load in s3 bucket: ' + S3_BUCKET_NAME)
else:    
    for s3_object in response['Contents']:
        if s3_object['Size'] > 0:
            s3_uri = 's3://' + S3_BUCKET_NAME + '/' + s3_object['Key']
            load_file_from_s3(s3_uri, db_conn, settings)
    db_conn.commit()
db_conn.close()
