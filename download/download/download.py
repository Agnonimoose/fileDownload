"""Utilities to download a file"""
import os
import os.path as op
from subprocess import check_output
from six.moves import urllib
from zipfile import ZipFile
import tarfile
from math import log, ceil
import time
import sys
import shutil
import tempfile
import ftplib
from functools import partial

if sys.version_info[0] == 3:
    string_types = str
else:
    string_types = basestring

ALLOWED_KINDS = ["file", "tar", "zip", "tar.gz"]
ZIP_KINDS = ["tar", "zip", "tar.gz"]

remote_file_size_default = 1


def download(
    url, path, kind="file", replace=False, timeout=10.0
, limit=None):
    """Download a URL.

    This will download a file and store it in a '~/data/` folder,
    creating directories if need be. It will also work for zip
    files, in which case it will unzip all of the files to the
    desired location.

    Parameters
    ----------
    url : string
        The url of the file to download. This may be a dropbox
        or google drive "share link", or a regular URL. If it
        is a share link, then it should point to a single file and
        not a folder. To download folders, zip them first.
    path : string
        The path where the downloaded file will be stored. If ``zipfile``
        is True, then this must be a folder into which files will be zipped.
    kind : one of ['file', 'zip', 'tar', 'tar.gz']
        The kind of file to be downloaded. If not 'file', then the file
        contents will be unpackaged according to the kind specified. Package
        contents will be placed in ``root_destination/<name>``.
    replace : bool
        If True and the URL points to a single file, overwrite the
        old file if possible.
    timeout : float
        The URL open timeout.

    Returns
    -------
    out_path : string
        A path to the downloaded file (or folder, in the case of
        a zip file).
    """
    if kind not in ALLOWED_KINDS:
        raise ValueError("`kind` must be one of {}, got {}".format(ALLOWED_KINDS, kind))

    path = op.expanduser(path)

    if len(path) == 0:
        raise ValueError("You must specify a path. For current directory use .")

    download_url = _convert_url_to_downloadable(url)

    if replace is False and op.exists(path):
        msg = (
            "Replace is False and data exists, so doing nothing. "
            "Use replace=True to re-download the data."
        )
    elif kind in ZIP_KINDS:
        if path and not op.isdir(path):
            os.makedirs(path)

        path_temp = _TempDir()
        path_temp_file = op.join(path_temp, "tmp.{}".format(kind))
        fetched = _fetch_file(
            download_url,
            path_temp_file,
            timeout=timeout,
            limit=limit
        )

        if fetched == False:
            return False

        if kind == "zip":
            zipper = ZipFile
        elif kind == "tar":
            zipper = tarfile.open
        elif kind == "tar.gz":
            zipper = partial(tarfile.open, mode="r:gz")
        with zipper(path_temp_file) as myobj:
            myobj.extractall(path)
        msg = "Successfully downloaded / unzipped to {}".format(path)
    else:
        directory = op.dirname(path)
        if directory and not op.isdir(directory):
            os.makedirs(directory)
        fetched = _fetch_file(
            download_url,
            path,
            timeout=timeout,
            limit=limit
        )
        if fetched == False:
            return False
        msg = "Successfully downloaded file to {}".format(path)

    return path


def _convert_url_to_downloadable(url):
    """Convert a url to the proper style depending on its website."""

    if "drive.google.com" in url:
        file_id = url.split("d/")[1].split("/")[0]
        base_url = "https://drive.google.com/uc?export=download&id="
        out = "{}{}".format(base_url, file_id)
    elif "dropbox.com" in url:
        if url.endswith(".png"):
            out = url + "?dl=1"
        else:
            out = url.replace("dl=0", "dl=1")
    else:
        out = url
    return out


def _fetch_file(
    url,
    file_name,
    resume=True,
    hash_=None,
    timeout=10.0,
    limit=None
):
    """Load requested file, downloading it if needed or requested.

    Parameters
    ----------
    url: string
        The url of file to be downloaded.
    file_name: string
        Name, along with the path, of where downloaded file will be saved.
    resume: bool, optional
        If true, try to resume partially downloaded files.
    hash_ : str | None
        The hash of the file to check. If None, no checking is
        performed.
    timeout : float
        The URL open timeout.
    """
    if hash_ is not None and (not isinstance(hash_, string_types) or len(hash_) != 32):
        raise ValueError(
            "Bad hash value given, should be a 32-character " "string:\n%s" % (hash_,)
        )
    temp_file_name = file_name + ".part"

    try:
        remote_file_size = remote_file_size_default
        if "dropbox.com" in url:
            try:
                import requests
            except ModuleNotFoundError:
                raise ValueError(
                    "To download Dropbox links, you need to "
                    "install the `requests` module."
                )
            resp = requests.get(url, stream=True)
            chunk_size = 8192
            with open(temp_file_name, "wb") as ff:
                for chunk in resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        ff.write(chunk)
        else:
            req = request_agent(url)
            u = urllib.request.urlopen(req, timeout=timeout)
            u.close()
            url = u.geturl()
            req = request_agent(url)
            u = urllib.request.urlopen(req, timeout=timeout)
            try:
                remote_file_size = int(
                    u.headers.get(
                        "Content-Length", str(remote_file_size_default)
                    ).strip()
                )
            finally:
                u.close()
                del u

            if not os.path.exists(temp_file_name):
                resume = False
            if resume:
                initial_size = op.getsize(temp_file_name)
            else:
                initial_size = 0

            if initial_size > remote_file_size:
                raise RuntimeError(
                    "Local file (%s) is larger than remote "
                    "file (%s), cannot resume download"
                    % (sizeof_fmt(initial_size), sizeof_fmt(remote_file_size))
                )
            if limit:
                if remote_file_size > limit:
                    return False

            scheme = urllib.parse.urlparse(url).scheme
            fun = _get_http if scheme in ("http", "https") else _get_ftp
            fun(
                url,
                temp_file_name,
                initial_size,
                remote_file_size,
            )

            if hash_ is not None:
                md5 = md5sum(temp_file_name)
                if hash_ != md5:
                    raise RuntimeError(
                        "Hash mismatch for downloaded file %s, "
                        "expected %s but got %s" % (temp_file_name, hash_, md5)
                    )
        local_file_size = op.getsize(temp_file_name)
        if local_file_size != remote_file_size:
            if remote_file_size != remote_file_size_default:
                raise Exception(
                    "Error: File size is %d and should be %d"
                    "* Please wait some time and try re-downloading the file again."
                    % (local_file_size, remote_file_size)
                )
        shutil.move(temp_file_name, file_name)
    except Exception as ee:
        raise RuntimeError(
            "Error while fetching file %s."
            " Dataset fetching aborted.\nError: %s" % (url, ee)
        )


def _get_ftp(
    url, temp_file_name, initial_size, file_size
):
    """Safely (resume a) download to a file from FTP."""

    parsed_url = urllib.parse.urlparse(url)
    file_name = os.path.basename(parsed_url.path)
    server_path = parsed_url.path.replace(file_name, "")
    unquoted_server_path = urllib.parse.unquote(server_path)

    data = ftplib.FTP()
    if parsed_url.port is not None:
        data.connect(parsed_url.hostname, parsed_url.port)
    else:
        data.connect(parsed_url.hostname)
    data.login()
    if len(server_path) > 1:
        data.cwd(unquoted_server_path)
    data.sendcmd("TYPE I")
    data.sendcmd("REST " + str(initial_size))
    down_cmd = "RETR " + file_name
    assert file_size == data.size(file_name)

    mode = "ab" if initial_size > 0 else "wb"
    with open(temp_file_name, mode) as local_file:

        def chunk_write(chunk):
            return _chunk_write(chunk, local_file)

        data.retrbinary(down_cmd, chunk_write)
        data.close()


def _get_http(
    url, temp_file_name, initial_size, file_size
):
    """Safely (resume a) download to a file from http(s)."""
    req = request_agent(url)
    if initial_size > 0:
        req.headers["Range"] = "bytes=%s-" % (initial_size,)
    try:
        response = urllib.request.urlopen(req)
    except Exception:
        del req.headers["Range"]
        response = urllib.request.urlopen(req)
    total_size = int(
        response.headers.get("Content-Length", str(remote_file_size_default)).strip()
    )
    if initial_size > 0 and file_size == total_size:
        initial_size = 0
    total_size += initial_size
    if total_size != file_size:
        raise RuntimeError("URL could not be parsed properly")
    mode = "ab" if initial_size > 0 else "wb"

    chunk_size = 8192  # 2 ** 13
    with open(temp_file_name, mode) as local_file:
        while True:
            t0 = time.time()
            chunk = response.read(chunk_size)
            dt = time.time() - t0
            if dt < 0.005:
                chunk_size *= 2
            elif dt > 0.1 and chunk_size > 8192:
                chunk_size = chunk_size // 2
            if not chunk:
                break
            local_file.write(chunk)


def md5sum(fname, block_size=1048576):  # 2 ** 20
    """Calculate the md5sum for a file.

    Parameters
    ----------
    fname : str
        Filename.
    block_size : int
        Block size to use when reading.

    Returns
    -------
    hash_ : str
        The hexadecimal digest of the hash.
    """
    md5 = hashlib.md5()
    with open(fname, "rb") as fid:
        while True:
            data = fid.read(block_size)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()


def sizeof_fmt(num):
    """Turn number of bytes into human-readable str.

    Parameters
    ----------
    num : int
        The number of bytes.

    Returns
    -------
    size : str
        The size in human-readable format.
    """
    units = ["bytes", "kB", "MB", "GB", "TB", "PB"]
    decimals = [0, 0, 1, 2, 2, 2]
    if num > 1:
        exponent = min(int(log(num, 1024)), len(units) - 1)
        quotient = float(num) / 1024 ** exponent
        unit = units[exponent]
        num_decimals = decimals[exponent]
        format_string = "{0:.%sf} {1}" % (num_decimals)
        return format_string.format(quotient, unit)
    if num == 0:
        return "0 bytes"
    if num == 1:
        return "1 byte"


class _TempDir(str):
    """Create and auto-destroy temp dir. Instances should be
    defined inside test functions. Instances defined at module level can not
    guarantee proper destruction of the temporary directory.

    When used at module level, the current use of the __del__() method for
    cleanup can fail because the rmtree function may be cleaned up before this
    object (an alternative could be using the atexit module instead).
    """

    def __new__(self):
        new = str.__new__(self, tempfile.mkdtemp(prefix="tmp_download_tempdir_"))
        return new

    def __init__(self):
        self._path = self.__str__()

    def __del__(self):
        shutil.rmtree(self._path, ignore_errors=True)


def request_agent(url):
    req = urllib.request.Request(
        url,
        data=None,
        # Simulate a user-agent because some websites require it for this to work
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
        },
    )
    return req

def _chunk_write(chunk, local_file):
    """Write a chunk to file. """
    local_file.write(chunk)

