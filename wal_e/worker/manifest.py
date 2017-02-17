import hashlib
import json
import os
import stat

from wal_e import log_help

logger = log_help.WalELogger(__name__)


def verify(base, manifest, checksums=False):
    retval = True
    nfiles = 0
    nbytes = 0

    with open(manifest, 'r') as f:
        manifest_list = json.load(f)

    for entry in manifest_list:
        if 'name' in entry:
            filename = os.path.join(base, entry['name'])
        if 'filetype' in entry:
            filetype = entry['filetype']
        if 'size' in entry:
            size = int(entry['size'])
        if 'hexdigest' in entry:
            hexdigest = entry['hexdigest'].strip()

        try:
            statres = os.lstat(filename)
        except OSError, e:
            logger.warning('Could not verify {}: {}'
                           ''.format(entry['name'], e.strerror))
            retval = False
            continue

        if stat.S_ISDIR(statres.st_mode) and filetype == 'DIR':
            nfiles += 1
        elif stat.S_ISLNK(statres.st_mode) and filetype == 'LNK':
            nfiles += 1
        elif not stat.S_ISREG(statres.st_mode) and filetype != 'REG':
            nfiles += 1
            logger.debug('found odd file {filename}'
                         '(filetype={filetype}, mode={mode}'.format(
                             filename=filename,
                             filetype=filetype,
                             mode=statres.st_mode))
        elif not stat.S_ISREG(statres.st_mode):
            retval = False
            logger.warning('expected regular file of length {} '
                           'instead found {} mode {:06o}'
                           ''.format(size,
                                     filename,
                                     statres.st_mode))

        elif statres.st_size != size:
            retval = False
            logger.warning('expected regular file of length {} '
                           'instead found {} size {}'
                           ''.format(size,
                                     filename,
                                     statres.st_size))

        elif (checksums and _checksum_file(filename) != hexdigest):
            retval = False
            logger.warning('file {} checksum mismatch '
                           '(expected sha1 of {})'
                           ''.format(filename, hexdigest))
        else:
            nfiles += 1
            nbytes += size
    return (retval, nfiles, nbytes)


def _checksum_file(filename):
    sha1 = hashlib.sha1()

    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha1.update(chunk)
    return sha1.hexdigest()


def directory(data_directory):
    return os.path.join(data_directory, '.wal-e', 'manifests')
