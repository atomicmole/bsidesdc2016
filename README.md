# bsidesdc2016

1. Download cert files from Project Sonar here:
https://scans.io/study/sonar.ssl
2. Decompress gziped cert files
3. Run split_certs_redshift.py supplying the decompressed cert file as an argument.  This will create a corresponding csv file in the output subdirectory.
4. Create an Amazon S3 bucket and Redshift cluster, and modify the settings.ini file to correspond
5. Create an Amazon IAM user with GET and LIST permmissions for your S3 bucket and create an access key for that user.  Add those credentials to the settings.ini file.
5. Copy the csv files into the Amazon S3 bucket
6. Run the redshift_load.py script.  This will load the data from all csv files in the confgiured S3 bucket into your Redshift cluster.
7. Run load_cert_feeds.py to load the latest certificate feed data into your Redshift cluster.
8. Label all certificates that match the certificate blacklist by executing the query in update_feed_match.sql
9. ...
10. Profit!

Also included is the count_occurances.py script.  Once everything is set up this can flag common fields and assist with some basic clustering.
