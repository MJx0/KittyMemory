#include "KittyIOFile.hpp"

bool KittyIOFile::open()
{
    _error = 0;

    if (_fd >= 0)
        close();

    if (_mode)
        _fd = KT_EINTR_RETRY(::open(_filePath.c_str(), _flags, _mode));
    else
        _fd = KT_EINTR_RETRY(::open(_filePath.c_str(), _flags));

    if (_fd < 0)
        _error = errno;

    return _fd >= 0;
}

bool KittyIOFile::close()
{
    _error = 0;
    if (_fd >= 0)
    {
        if (KT_EINTR_RETRY(::close(_fd)) == -1)
        {
            _fd = -1;
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
        size_t toRead = std::min(len - total, KT_IO_CHUNK_SIZE);
        ssize_t n = KT_EINTR_RETRY(::read(_fd, ptr + total, toRead));
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : (_error == 0 ? 0 : -1);
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
        size_t toWrite = std::min(len - total, KT_IO_CHUNK_SIZE);
        ssize_t n = KT_EINTR_RETRY(::write(_fd, ptr + total, toWrite));
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : (_error == 0 ? 0 : -1);
        }
        total += n;
    }
    return total;
}

ssize_t KittyIOFile::pread(kt_off64_t offset, void *buffer, size_t len)
{
    _error = 0;

    if (_fd < 0)
        return -1;

    char *ptr = static_cast<char *>(buffer);
    size_t total = 0;

    while (total < len)
    {
        size_t toRead = std::min(len - total, KT_IO_CHUNK_SIZE);
        ssize_t n = KT_EINTR_RETRY(kt_pread64(_fd, ptr + total, toRead, (kt_off64_t)(offset + total)));
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : (_error == 0 ? 0 : -1);
        }
        total += n;
    }
    return total;
}

ssize_t KittyIOFile::pwrite(kt_off64_t offset, const void *buffer, size_t len)
{
    _error = 0;

    if (_fd < 0)
        return -1;

    const char *ptr = static_cast<const char *>(buffer);
    size_t total = 0;
    while (total < len)
    {
        size_t toWrite = std::min(len - total, KT_IO_CHUNK_SIZE);
        ssize_t n = KT_EINTR_RETRY(kt_pwrite64(_fd, ptr + total, toWrite, (kt_off64_t)(offset + total)));
        if (n <= 0)
        {
            _error = (n < 0) ? errno : 0;
            return total > 0 ? total : (_error == 0 ? 0 : -1);
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
        str->resize(static_cast<size_t>(s.st_size));
        ssize_t n = pread(0, (void*)str->data(), static_cast<size_t>(s.st_size));
        if (n > 0)
        {
            if (n != static_cast<ssize_t>(s.st_size))
            {
                str->resize(static_cast<size_t>(n));
            }
            return true;
        }

        str->clear();
    }

    std::vector<char> buffer(KT_IO_CHUNK_SIZE, 0);
    kt_off64_t offset = 0;
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
        buf->resize(static_cast<size_t>(s.st_size));
        ssize_t n = pread(0, buf->data(), static_cast<size_t>(s.st_size));
        if (n > 0)
        {
            if (n != static_cast<ssize_t>(s.st_size))
            {
                buf->resize(static_cast<size_t>(n));
            }
            return true;
        }

        buf->clear();
    }

    std::vector<char> buffer(KT_IO_CHUNK_SIZE, 0);
    kt_off64_t offset = 0;
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

bool KittyIOFile::copyToFd(int fd)
{
    _error = 0;

    if (_fd < 0 || fd < 0)
        return false;

    std::vector<char> buffer(KT_IO_CHUNK_SIZE, 0);
    kt_off64_t offset = 0;

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

bool KittyIOFile::listFilesCallback(const std::string &dirPath, std::function<bool(const std::string &)> cb)
{
    DIR *dir = opendir(dirPath.c_str());
    if (!dir)
        return false;

    std::string base = dirPath;
    if (!base.empty() && base.back() != '/')
        base += '/';

    while (struct dirent *f = readdir(dir))
    {
        if (f->d_name[0] == '.')
            continue;

        std::string path = base + f->d_name;

        unsigned char d_type = f->d_type;
        if (d_type == DT_UNKNOWN)
        {
            kt_stat64_t st{};
            if (kt_stat64(path.c_str(), &st) == 0)
            {
                if (S_ISDIR(st.st_mode))
                    d_type = DT_DIR;
                else if (S_ISREG(st.st_mode))
                    d_type = DT_REG;
            }
        }

        if (d_type == DT_DIR)
        {
            if (listFilesCallback(path, cb))
            {
                closedir(dir);
                return true;
            }
        }
        else if (d_type == DT_REG)
        {
            if (cb && cb(path))
            {
                closedir(dir);
                return true;
            }
        }
    }

    closedir(dir);
    return false;
}

bool KittyIOFile::createDirectoryRecursive(const std::string &path, mode_t mode)
{
    if (path.empty())
        return false;

    std::string current;
    size_t pos = 0;

    if (path[0] == '/')
    {
        current = "/";
        pos = 1;
    }

    while (pos <= path.size())
    {
        size_t next = path.find('/', pos);
        std::string part = path.substr(pos, next - pos);

        if (!part.empty())
        {
            if (!current.empty() && current.back() != '/')
                current += "/";

            current += part;

            if (mkdir(current.c_str(), mode) != 0)
            {
                if (errno != EEXIST)
                {
                    return false;
                }
            }
        }

        if (next == std::string::npos)
            break;

        pos = next + 1;
    }

    return true;
}