#include "KittyIOFile.hpp"

bool KittyIOFile::Open()
{
    if (_fd <= 0)
    {
        errno = 0, _error = 0;
        if (_mode)
            _fd = open(_filePath.c_str(), _flags, _mode);
        else
            _fd = open(_filePath.c_str(), _flags);

        _error = _fd > 0 ? 0 : errno;
    }
    return _fd > 0;
}

bool KittyIOFile::Close()
{
    bool rt = true;
    if (_fd > 0)
    {
        errno = 0, _error = 0;
        rt = close(_fd) != -1;
        if (!rt)
            _error = errno;

        _fd = 0;
    }
    return rt;
}

ssize_t KittyIOFile::Read(void *buffer, size_t len)
{
    char *buf = (char *)buffer;
    size_t bytesRead = 0;
    do
    {
        errno = 0, _error = 0;
        ssize_t readSize = KT_EINTR_RETRY(read(_fd, buf + bytesRead, len - bytesRead));
        if (readSize <= 0)
        {
            if (readSize < 0)
                _error = errno;
            break;
        }

        bytesRead += readSize;
    } while (bytesRead < len);
    return bytesRead;
}

ssize_t KittyIOFile::Write(const void *buffer, size_t len)
{
    const char *buf = (const char *)buffer;
    size_t bytesWritten = 0;
    do
    {
        errno = 0, _error = 0;
        ssize_t writeSize = KT_EINTR_RETRY(write(_fd, buf + bytesWritten, len - bytesWritten));
        if (writeSize <= 0)
        {
            if (writeSize < 0)
                _error = errno;
            break;
        }

        bytesWritten += writeSize;
    } while (bytesWritten < len);
    return bytesWritten;
}

ssize_t KittyIOFile::Read(uintptr_t offset, void *buffer, size_t len)
{
    char *buf = (char *)buffer;
    size_t bytesRead = 0;
    do
    {
        errno = 0, _error = 0;
#ifdef __APPLE__
        ssize_t readSize = KT_EINTR_RETRY(pread(_fd, buf + bytesRead, len - bytesRead, offset + bytesRead));
#else
        ssize_t readSize = KT_EINTR_RETRY(pread64(_fd, buf + bytesRead, len - bytesRead, offset + bytesRead));
#endif
        if (readSize <= 0)
        {
            if (readSize < 0)
                _error = errno;
            break;
        }

        bytesRead += readSize;
    } while (bytesRead < len);
    return bytesRead;
}

ssize_t KittyIOFile::Write(uintptr_t offset, const void *buffer, size_t len)
{
    const char *buf = (const char *)buffer;
    size_t bytesWritten = 0;
    do
    {
        errno = 0, _error = 0;
#ifdef __APPLE__
        ssize_t writeSize = KT_EINTR_RETRY(pwrite(_fd, buf + bytesWritten, len - bytesWritten, offset + bytesWritten));
#else
        ssize_t writeSize = KT_EINTR_RETRY(pwrite64(_fd, buf + bytesWritten, len - bytesWritten, offset + bytesWritten));
#endif
        if (writeSize <= 0)
        {
            if (writeSize < 0)
                _error = errno;
            break;
        }

        bytesWritten += writeSize;
    } while (bytesWritten < len);
    return bytesWritten;
}

#ifdef __APPLE__
struct stat KittyIOFile::Stat()
{
    errno = 0, _error = 0;
    struct stat s;
    if (stat(_filePath.c_str(), &s) == -1)
        _error = errno;
    return s;
}
#else
struct stat64 KittyIOFile::Stat()
{
    errno = 0, _error = 0;
    struct stat64 s;
    if (stat64(_filePath.c_str(), &s) == -1)
        _error = errno;
    return s;
}
#endif

bool KittyIOFile::readToString(std::string *str)
{
    if (!str)
        return false;

    str->clear();

    const ssize_t flen = Stat().st_size;
    if (flen > 0)
    {
        str->resize(flen, 0);
        return Read(0, (void*)(str->data()), flen) == flen;
    }

    // incase stat fails to get file size
    std::vector<char> tmp_buf(KT_IO_BUFFER_MAX_SIZE, 0);
    ssize_t n = 0, off = 0;
    while ((n = Read(off, tmp_buf.data(), KT_IO_BUFFER_MAX_SIZE)) > 0)
    {
        off += n;
        str->append(tmp_buf.data(), n);
    }

    return n != -1;
}

bool KittyIOFile::readToBuffer(std::vector<char> *buf)
{
    if (!buf)
        return false;

    buf->clear();

    const ssize_t flen = Stat().st_size;
    if (flen > 0)
    {
        buf->resize(flen, 0);
        return Read(0, buf->data(), flen) == flen;
    }

    // incase stat fails to get file size
    std::vector<char> tmp_buf(KT_IO_BUFFER_MAX_SIZE, 0);
    ssize_t n = 0, off = 0;
    while ((n = Read(off, tmp_buf.data(), KT_IO_BUFFER_MAX_SIZE)) > 0)
    {
        off += n;
        buf->insert(buf->end(), tmp_buf.data(), tmp_buf.data() + n);
    }

    return n != -1;
}

bool KittyIOFile::writeToFile(uintptr_t offset, size_t len, const std::string &filePath)
{
    KittyIOFile of(filePath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    of.Delete();
    if (!of.Open()) return false;

    uintptr_t woff = 0;
    std::vector<char> buf(KT_IO_BUFFER_MAX_SIZE);

    while (len)
    {
        memset(buf.data(), 0, buf.size());

        ssize_t nread = Read(offset, buf.data(), buf.size());
        if (nread <= 0)
            break;

        if (of.Write(woff, buf.data(), nread) != nread)
            break;

        offset += nread;
        len -= nread;
        woff += nread;
    }

    return ssize_t(len) <= 0;
}

bool KittyIOFile::writeToFile(const std::string &filePath)
{
    ssize_t size = Stat().st_size;
    if (size)
    {
        return writeToFile(0, size, filePath);
    }

    KittyIOFile of(filePath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    of.Delete();
    if (!of.Open()) return false;

    uintptr_t offset = 0;
    std::vector<char> buf(KT_IO_BUFFER_MAX_SIZE);

    while (true)
    {
        memset(buf.data(), 0, buf.size());

        ssize_t nread = Read(offset, buf.data(), buf.size());
        if (nread <= 0)
            break;

        if (of.Write(offset, buf.data(), nread) != nread)
            return false;

        offset += nread;
    }
    
    return true;
}

bool KittyIOFile::writeToFd(int fd)
{
    if (fd <= 0)
        return false;

    std::vector<char> buf;
    if (!readToBuffer(&buf) || buf.empty())
        return false;

    char *ptr = buf.data();
    ssize_t len = buf.size();

    do
    {
        ssize_t nwritten = KT_EINTR_RETRY(write(fd, ptr, len));
        if (nwritten <= 0)
        {
            _error = errno;
            return false;
        }

        ptr += nwritten;
        len -= nwritten;
    } while (len > 0);

    return true;
}

bool KittyIOFile::readFileToString(const std::string& filePath, std::string* str)
{
    KittyIOFile of(filePath, O_RDONLY | O_CLOEXEC);
    return of.Open() && of.readToString(str);
}

bool KittyIOFile::readFileToBuffer(const std::string& filePath, std::vector<char>* buf)
{
    KittyIOFile of(filePath, O_RDONLY | O_CLOEXEC);
    return of.Open() && of.readToBuffer(buf);
}

bool KittyIOFile::copy(const std::string &srcFilePath, const std::string &dstFilePath)
{
    KittyIOFile src(srcFilePath, O_RDONLY | O_CLOEXEC);
    return src.Open() && src.writeToFile(dstFilePath);
}

void KittyIOFile::listFilesCallback(const std::string& dirPath, std::function<bool(const std::string&)> cb)
{
    if (auto dir = opendir(dirPath.c_str()))
    {
        while (auto f = readdir(dir))
        {
            if (f->d_name[0] == '.')
                continue;

            if (f->d_type == DT_DIR)
                listFilesCallback(dirPath + f->d_name + "/", cb);

            if (f->d_type == DT_REG)
            {
                if (cb && cb(dirPath + f->d_name)) return;
            }
        }
        closedir(dir);
    }
}