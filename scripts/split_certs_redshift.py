# Copyright (c) 2016, Atomic Mole LLC
# All rights reserved.
#
# Take in an unzipped file of certificates from Project Sonar and create a metadata TSV file
#   in a format similar to that of Bro but with different fields and a simpler 1-line header
import base64
import calendar
import datetime
import re
import subprocess
import sys

field_names = [ 'date',
                'sha1',
                'version',
                'serial_number',
                'enc_subject',
                'enc_subject_C',
                'enc_subject_CN',
                'enc_subject_L',
                'enc_subject_O',
                'enc_subject_OU',
                'enc_subject_ST',
                'enc_subject_emailAddress',
                'enc_subject_unstructuredName',
                'enc_subject_serialNumber',
                'enc_issuer',
                'enc_issuer_C',
                'enc_issuer_CN',
                'enc_issuer_L',
                'enc_issuer_O',
                'enc_issuer_OU',
                'enc_issuer_ST',
                'enc_issuer_emailAddress',
                'enc_issuer_unstructuredName',
                'enc_issuer_serialNumber',
                'not_valid_before',
                'not_valid_before_raw',
                'not_valid_after',
                'not_valid_after_raw',
                'duration',
                'key_algorithm',
                'sig_algorithm',
                'key_type',
                'key_length',
                'exponent',
                'curve',
                'size',
                'self_signed',
                'feed_match' ]
    
# Convert the time from a string to a UNIX-time integer
def convert_time(time_string):
    timestamp = None
    try:
        timestamp = datetime.datetime.strptime(time_string, '%b %d %H:%M:%S %Y %Z')
    except ValueError:
        try:
            timestamp = datetime.datetime.strptime(time_string, '%b %d %H:%M:%S %Y')
        except ValueError:
            timestamp = None
    if timestamp != None:
        return int(calendar.timegm(timestamp.utctimetuple()))
    else:
        return None
    
# Take an issuer or subject string with subfields like below and split it up into a dictionary
# C=GB,ST=Yorks,L=York,O=MyCompany Ltd.,OU=IT,CN=localhost
def split_subfields(string):
    output = {}
    transformed = string.replace('/emailAddress=', ',emailAddress=')
    transformed = transformed.replace('/serialNumber=', ',serialNumber=')
    transformed = transformed.replace('/unstructuredName=', ',unstructuredName=')
    pairs = transformed.split(',')
    for pair in pairs:
        fields = pair.split('=', 1)
        if len(fields) != 2:
            #print('ERROR: Unrecognized string: ' + pair)
            continue
        output[fields[0]] = fields[1]
    return output
    
# Takes the output from the openssl x509 decoder and produces a dictionary
def openssl_output_to_dict(openssl_output):
    output = {}
    serial_number_line = False
    for line in openssl_output.splitlines():
        stripped = line.strip()
            
        if stripped.startswith('Version: '):
            version_string = stripped[9:]
            fields = version_string.split(' ')
            try:
                output['version'] = int(fields[0])
            except ValueError:
                pass
        elif stripped.startswith('Serial Number:'):
            possible_serial_number_string = stripped[15:]
            if possible_serial_number_string.find('(') != -1:
                fields = possible_serial_number_string.split(' ')
                output['serial_number'] = fields[1].replace('(0x','').replace('(-0x','-').replace(')','').upper()            
            else:    
                serial_number_line = True
        elif serial_number_line:
            serial_number_line = False
            output['serial_number'] = stripped.upper().replace(':','')
        elif stripped.startswith('Signature Algorithm: '):
            output['sig_algorithm'] = stripped[21:]
        elif stripped.startswith('Issuer: '):
            issuer = stripped[8:].replace(', ', ',')
            output['enc_issuer'] = re.escape(issuer)
            subfields = split_subfields(issuer)
            for subfield in subfields:
                output['enc_issuer_' + subfield] = re.escape(subfields[subfield])
        elif stripped.startswith('Not Before: '):
            split = stripped[12:].split(',')
            not_before_string = split[0]
            timestamp = convert_time(not_before_string)
            if timestamp != None:
                output['not_valid_before'] = timestamp
            output['not_valid_before_raw'] = '\'' + not_before_string + '\''
            if len(split) > 1 and split[1].startswith('Not After: '):
                not_after_string = split[1][11:]
                timestamp = convert_time(not_after_string)
                if timestamp != None:
                    output['not_valid_after'] = timestamp
                output['not_valid_after_raw'] = '\'' + not_after_string + '\''
        elif stripped.startswith('Not After : '):
            not_after_string = stripped[12:]
            timestamp = convert_time(not_after_string)
            if timestamp != None:
                output['not_valid_after'] = timestamp
            output['not_valid_after_raw'] = '\'' + not_after_string + '\''
        elif stripped.startswith('Subject: '):
            subject = stripped[9:].replace(', ', ',')
            output['enc_subject'] = re.escape(subject)
            subfields = split_subfields(subject)
            for subfield in subfields:
                output['enc_subject_' + subfield] = re.escape(subfields[subfield])
        elif stripped.startswith('Public Key Algorithm: '):
            output['key_algorithm'] = stripped[22:]
        elif stripped.startswith('RSA Public Key: ('):
            output['key_type'] = 'rsa'
            output['key_length'] = int(stripped[17:].replace(' bit)', ''))
        elif stripped.startswith('EC Public Key:'):
            output['key_type'] = 'ecdsa'
        elif stripped.startswith('ASN1 OID: '):
            output['curve'] = stripped[10:]
            output['key_length'] = 256 # This is a guess based on what we've observed
        elif stripped.startswith('Exponent: '):
            exponent_string = stripped[10:]
            fields = exponent_string.split(' ')
            try:
                output['exponent'] = int(fields[0])
            except ValueError:
                pass
    return output
    
def print_header(file_handle):
    first = True
    header = ''
    for field in field_names:
        if first:
            first = False
        else:
            header += '|'
        header += field
    file_handle.write(header + '\n')
    
def print_csv(cert_record, file_handle):
    output = ''
    first = True
    for field_name in field_names:
        if first:
            first = False
        else:
            output += '|'
        if field_name in cert_record:
            output += str(cert_record[field_name])
    file_handle.write(output + '\n')
            
if len(sys.argv) < 2:
    print('ERROR: no file specified\n')
    sys.exit(1)

scan_date = sys.argv[1].replace('./', '').replace('_certs', '')
cert_file = open(sys.argv[1], 'r')
output_file = open('./output/' + sys.argv[1] + '.csv', 'w')
print_header(output_file)
for line in cert_file:
    fields = line.split(',')

    cert_der = base64.b64decode(fields[1].strip())
    try:
        p = subprocess.Popen(['openssl', 'x509', '-inform', 'der', '-text', '-noout'],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
        cert_decode = p.communicate(input=cert_der)[0]
        cert_dict = openssl_output_to_dict(cert_decode)
        cert_dict['sha1'] = fields[0]
        # We initially always indicate the feed match is False, as it's easier to update the 
        #   value via SQL once it's in the database.  See the query in 'update_feed_match.sql'
        cert_dict['feed_match'] = False
        cert_dict['size'] = len(cert_der)
        cert_dict['date'] = scan_date
        if 'enc_issuer' in cert_dict and 'enc_subject' in cert_dict:
            cert_dict['self_signed'] = cert_dict['enc_issuer'] == cert_dict['enc_subject']
        else:
            cert_dict['self_signed'] = ''
        if 'not_valid_before' in cert_dict and 'not_valid_after' in cert_dict:
            cert_dict['duration'] = cert_dict['not_valid_after'] - cert_dict['not_valid_before']
        print_csv(cert_dict, output_file)
    except subprocess.CalledProcessError:
        pass
output_file.close()
cert_file.close()
