# Copyright (c) 2016, Atomic Mole LLC
# All rights reserved.
#
# Load the SSLBL certificate feeds into an Amazon Resshift database via an S3 copy.  This creates
#   the relevant table in Redshift if it does not already exist.
import configparser
import psycopg2
import pprint

def redshift_connect(settings):
    REDSHIFT_HOSTNAME = settings.get('Redshift', 'REDSHIFT_HOSTNAME')
    REDSHIFT_DATABASE = settings.get('Redshift', 'REDSHIFT_DATABASE')
    REDSHIFT_USER     = settings.get('Redshift', 'REDSHIFT_USER')
    REDSHIFT_PASSWORD = settings.get('Redshift', 'REDSHIFT_PASSWORD')
    
    conn_string = 'dbname=\'' + REDSHIFT_DATABASE + '\' port=\'5439\' user=\'' + REDSHIFT_USER + '\''
    conn_string += ' password=\'' + REDSHIFT_PASSWORD + '\'' + ' host=\'' + REDSHIFT_HOSTNAME + '\''
    conn_string += ' connect_timeout=20 sslmode=require'
    return psycopg2.connect(conn_string)
    
field_counts = {}
field_names = [ 'subject_c',
                'subject_cn',
                'subject_l',
                'subject_o',
                'subject_ou',
                'subject_st',
                'subject_emailAddress',
                'subject_unstructuredName',
                'subject_serialNumber' ]
                
settings = configparser.RawConfigParser()
settings.read('settings.ini')                

db_conn = redshift_connect(settings)
cursor = db_conn.cursor()

# Figure out the ratio of our bad sample size to the total number of entries
query = 'SELECT COUNT(*) from cert_metadata WHERE feed_match = True'
cursor.execute(query)
bad_samples = cursor.fetchone()[0]
query = 'SELECT COUNT(*) from cert_metadata'
cursor.execute(query)
total_samples = cursor.fetchone()[0]

print('Bad:   ' + str(bad_samples))
print('Total: ' + str(total_samples))
# I realize this ratio is kind of backwards, but it's a lot easier to read this way and look for 
#   numbers closer to 1 
print('Ratio: ' + str(float(total_samples)/bad_samples))

for field in field_names:
    query = 'SELECT ' + field + ', COUNT(*) FROM cert_metadata WHERE feed_match = True GROUP BY '
    query += field + ' ORDER BY COUNT(*) DESC'
    cursor.execute(query)
    result = cursor.fetchall()
    values = []
    for row in result:
        if row[1] > 1:
            values.append((row[0], row[1]))
    field_counts[field] = values
    
interesting_values = {}
for field in field_counts:
    interesting_values[field] = []
    for value in field_counts[field]:
            query = 'SELECT COUNT(*) FROM cert_metadata WHERE ' + field + ' = \'' + value[0] + '\'' 
            cursor.execute(query)
            result = cursor.fetchone()
            # If the only time this value was seen was in the blacklist there's really no way to 
            #   confirm a pattern. Ignore it for now, since blacklisting by hash seems effective
            if result[0] > value[1]:
                ratio = float(result[0]) / value[1]
                if ratio > 1.5:
                    print(field + ': ' + value[0] + '     ' + str(value[1]) + ' -> ' + str(result[0]) + ' (' + str(ratio) + ')')
                    interesting_values[field].append(value)

# Format all the fields we're going to request                
field_list_string = ''
for field in field_names:
    if field_list_string == '':
        field_list_string = field
    else:
        field_list_string += ', ' + field
        
        
for field in interesting_values:
    for value in interesting_values[field]:
        query = 'SELECT ' + field_list_string + ' FROM cert_metadata WHERE '
        query += field + ' = \'' + value[0] + '\' and feed_match = True'
        cursor.execute(query)
        result = cursor.fetchall()
        values = {}
        for row in result:
            for column_num in xrange(len(field_names)):
                column_name = field_names[column_num]
                if column_name not in values:
                    values[column_name] = {}
                if row[column_num] not in values[column_name]:
                    values[column_name][row[column_num]] = 1
                else:
                    values[column_name][row[column_num]] += 1
        for column in values:
            for entry in values[column]:
                if field != column and values[column][entry] > 1:
                    print(field + ': ' + value[0] + ' + ' + column + ': ' + entry + '  ' + str(values[column][entry]))
        #pprint.pprint(values)
                
db_conn.close()
