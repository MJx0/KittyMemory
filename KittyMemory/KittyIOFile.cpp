#include "KittyIOFile.hpp"

bool KittyIOFile::open()
{
    _error = 0;
    if (_fd < 0)
    {
        if (_mode)
            _fd = KT_EINTR_RETRY(::open(_filePath.c_str(), _flags, _mode));
        else
            _fd = KT_EINTR_RETRY(::open(_filePath.c_str(), _flags));

        if (_fd < 0)
            _error = errno;
    }
    return _fd >= 0;
}

bool KittyIOFile::close()
{
    _error = 0;
    if (_fd >= 0)
    {
        if (KT_EINTR_RETRY(::close(_fd)) == -1)
        {
            _error = errno;
            return false;
        }
        _fd = -1;
    }
    return true;
}

ssize_t KittyIOFile::read(void *buffer, size_t len)
{
    _error = 0;

    if (_fd < 0)
        return -1;

    char *ptr = static_cast<char *>(buffer);
    size_t total = 0;
    while (total < len)
    {
        size_t toRead = std::min(len - total, _bufferSize);
        ssize_t n = KT_EINTR_RETRY(::read(_fd, ptr + total, toRead));
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : -1;
        }
        total += n;
    }
    return total;
}

ssize_t KittyIOFile::write(const void *buffer, size_t len)
{
    _error = 0;

    if (_fd < 0)
        return -1;

    const char *ptr = static_cast<const char *>(buffer);
    size_t total = 0;
    while (total < len)
    {
        size_t toWrite = std::min(len - total, _bufferSize);
        ssize_t n = KT_EINTR_RETRY(::write(_fd, ptr + total, toWrite));
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : -1;
        }
        total += n;
    }
    return total;
}

ssize_t KittyIOFile::pread(uintptr_t offset, void *buffer, size_t len)
{
    _error = 0;

    if (_fd < 0)
        return -1;

    char *ptr = static_cast<char *>(buffer);
    size_t total = 0;
    while (total < len)
    {
        size_t toRead = std::min(len - total, _bufferSize);
#ifdef __APPLE__
        ssize_t n = KT_EINTR_RETRY(::pread(_fd, ptr + total, toRead, (off_t)(offset + total)));
#else
        ssize_t n = KT_EINTR_RETRY(::pread64(_fd, ptr + total, toRead, (off64_t)(offset + total)));
#endif
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : -1;
        }
        total += n;
    }
    return total;
}

ssize_t KittyIOFile::pwrite(uintptr_t offset, const void *buffer, size_t len)
{
    _error = 0;

    if (_fd < 0)
        return -1;

    const char *ptr = static_cast<const char *>(buffer);
    size_t total = 0;
    while (total < len)
    {
        size_t toWrite = std::min(len - total, _bufferSize);
#ifdef __APPLE__
        ssize_t n = KT_EINTR_RETRY(::pwrite(_fd, ptr + total, toWrite, (off_t)(offset + total)));
#else
        ssize_t n = KT_EINTR_RETRY(::pwrite64(_fd, ptr + total, toWrite, (off64_t)(offset + total)));
#endif
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : -1;
        }
        total += n;
    }
    return total;
}

bool KittyIOFile::readToString(std::string *str)
{
    _error = 0;

    if (!str)
        return false;

    str->clear();

    auto s = info();
    if (_error == 0 && s.st_size > 0)
    {
        str->resize(s.st_size);
        return (size_t)pread(0, str->data(), s.st_size) == (size_t)s.st_size;
    }

    std::vector<char> buffer(_bufferSize);
    uintptr_t offset = 0;
    while (true)
    {
        ssize_t n = pread(offset, buffer.data(), buffer.size());
        if (n <= 0)
            break;

        offset += n;
        str->append(buffer.data(), n);
    }

    return _error == 0;
}

bool KittyIOFile::readToBuffer(std::vector<char> *buf)
{
    _error = 0;

    if (!buf)
        return false;

    buf->clear();

    auto s = info();
    if (_error == 0 && s.st_size > 0)
    {
        buf->resize(s.st_size);
        return (size_t)pread(0, buf->data(), s.st_size) == (size_t)s.st_size;
    }

    std::vector<char> buffer(_bufferSize);
    uintptr_t offset = 0;
    while (true)
    {
        ssize_t n = pread(offset, buffer.data(), buffer.size());
        if (n <= 0)
            break;

        offset += n;
        buf->insert(buf->end(), buffer.data(), buffer.data() + n);
    }

    return _error == 0;
}

bool KittyIOFile::writeOffsetToFile(uintptr_t offset, size_t len, const std::string &filePath)
{
    _error = 0;

    KittyIOFile of(filePath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (!of.open())
        return false;

    std::vector<char> buffer(_bufferSize);
    size_t remaining = len;
    uintptr_t curr_off = offset;

    while (remaining > 0)
    {
        size_t to_read = std::min(remaining, _bufferSize);
        ssize_t nread = pread(curr_off, buffer.data(), to_read);
        if (nread <= 0)
            break;

        if (of.write(buffer.data(), nread) != nread)
            return false;

        curr_off += nread;
        remaining -= nread;
    }

    return remaining == 0;
}

bool KittyIOFile::writeToFd(int fd)
{
    _error = 0;

    if (_fd < 0 || fd < 0)
        return false;

    std::vector<char> buffer(_bufferSize);
    uintptr_t offset = 0;

    while (true)
    {
        ssize_t nr = pread(offset, buffer.data(), buffer.size());
        if (nr < 0)
            return false;

        if (nr == 0)
            break;

        ssize_t total_nw = 0;
        while (total_nw < nr)
        {
            ssize_t nw = KT_EINTR_RETRY(::write(fd, buffer.data() + total_nw, nr - total_nw));
            if (nw <= 0)
            {
                _error = (nw < 0) ? errno : 0;
                return false;
            }
            total_nw += nw;
        }

        offset += nr;
    }

    return true;
}

void KittyIOFile::listFilesCallback(const std::string &dirPath, std::function<bool(const std::string &)> cb)
{
    DIR *dir = opendir(dirPath.c_str());
    if (!dir)
        return;

    std::string base = dirPath;
    if (!base.empty() && base.back() != '/')
        base += '/';

    while (struct dirent *f = readdir(dir))
    {
        if (f->d_name[0] == '.')
            continue;

        std::string path = base + f->d_name;
        if (f->d_type == DT_DIR)
        {
            listFilesCallback(path, cb);
        }
        else if (f->d_type == DT_REG)
        {
            if (cb && cb(path))
                break;
        }
    }

    closedir(dir);
}