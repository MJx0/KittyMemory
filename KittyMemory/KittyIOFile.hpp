#pragma once

#include "KittyUtils.hpp"

#define KT_IO_BUFFER_MAX_SIZE (1024*1024)

class KittyIOFile
{
private:
    int _fd;
    std::string _filePath;
    int _flags;
    mode_t _mode;
    int _error;

public:
    KittyIOFile() : _fd(0), _flags(0), _mode(0), _error(0) {}

    KittyIOFile(const std::string &filePath, int flags, mode_t mode)
        : _fd(0), _filePath(filePath), _flags(flags), _mode(mode), _error(0) {}

    KittyIOFile(const std::string &filePath, int flags)
        : _fd(0), _filePath(filePath), _flags(flags), _mode(0), _error(0) {}

    ~KittyIOFile()
    {
        if (_fd > 0)
        {
            close(_fd);
        }
    }

    bool Open();
    bool Close();

    inline int lastError() const { return _error; }
    inline std::string lastStrError() const { return _error ? strerror(_error) : ""; }

    inline int FD() const { return _fd; }
    inline std::string Path() const { return _filePath; }
    inline int Flags() const { return _flags; }
    inline mode_t Mode() const { return _mode; }

    ssize_t Read(void *buffer, size_t len);
    ssize_t Write(const void *buffer, size_t len);

    ssize_t Read(uintptr_t offset, void *buffer, size_t len);
    ssize_t Write(uintptr_t offset, const void *buffer, size_t len);

    inline bool Exists() { return access(_filePath.c_str(), F_OK) != -1; }

    inline bool canRead() { return access(_filePath.c_str(), R_OK) != -1; }
    inline bool canWrite() { return access(_filePath.c_str(), W_OK) != -1; }
    inline bool canExecute() { return access(_filePath.c_str(), X_OK) != -1; }

    inline bool isFile()
    {
        struct stat s;
        return stat(_filePath.c_str(), &s) != -1 && S_ISREG(s.st_mode);
    }

    inline bool Delete() { return unlink(_filePath.c_str()) != -1; }

#ifdef __APPLE__
    struct stat Stat();
#else
    struct stat64 Stat();
#endif

    bool readToString(std::string *str);
    bool readToBuffer(std::vector<char> *buf);

    bool writeToFile(uintptr_t offset, size_t len, const std::string &filePath);
    bool writeToFile(const std::string &filePath);

    bool writeToFd(int fd);

    static bool readFileToString(const std::string &filePath, std::string *str);
    static bool readFileToBuffer(const std::string &filePath, std::vector<char> *buf);

    static bool copy(const std::string &srcFilePath, const std::string &dstFilePath);

    static void listFilesCallback(const std::string& dir, std::function<bool(const std::string&)> cb);
};